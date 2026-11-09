//! The keys that an endpoint protects its stateless packets with, shared by every worker of the
//! process (ruling T10-a), and what they protect: the tokens of stateless resets (RFC 9000
//! section 10.3) and of Retry packets (RFC 9000 section 8.1.2).
//!
//! A stateless reset token is the first 16 bytes of HMAC-SHA-256 of the connection ID under the
//! reset key, so that any worker computes the token of any connection ID without state. A Retry
//! token is the peer address, the time of issue and the original destination connection ID of
//! the client, sealed with AES-256-GCM under the Retry key and a random nonce that the token
//! carries, with the source connection ID of the Retry, which the client sends its next Initial
//! packet to, as associated data.

use crate::{
  crypto::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadKey as _, Aes256GcmKeyGlobal, Hmac as _, HmacSha256Global,
  },
  quic::{Cid, MAX_CID_LEN, wipe},
  rng::CryptoRng,
};
use core::{
  fmt::{Debug, Formatter},
  net::{IpAddr, SocketAddr},
};

/// The bytes of a stateless reset token.
pub(crate) const RESET_TOKEN_LEN: usize = 16;
/// The bytes of a Retry token.
pub(crate) const RETRY_TOKEN_LEN: usize = AEAD_NONCE_LEN + PLAINTEXT_LEN + AEAD_TAG_LEN;
/// How long a Retry token is valid after it was issued.
pub(crate) const RETRY_TOKEN_LIFETIME_US: u64 = 10_000_000;

const KEY_LEN: usize = 32;
// The peer address (an IPv6 address, IPv4 ones mapped, and the port), the time of issue and the
// original destination CID with its length
const PLAINTEXT_LEN: usize = 16 + 2 + 8 + 1 + MAX_CID_LEN;
// The clocks of the workers are read once per turn: a token issued by another worker may come
// from a little later than the time of the turn that checks it
const CLOCK_SLACK_US: u64 = 1_000_000;

/// The keys of the stateless packets of an endpoint: one process, every worker. See the
/// [module documentation](self). Overwritten with zeros when dropped.
pub(crate) struct EndpointKeys {
  reset: [u8; KEY_LEN],
  retry: [u8; KEY_LEN],
}

impl EndpointKeys {
  /// Keys drawn from `rng`.
  #[allow(dead_code, reason = "called by the HTTP/3 server of task 14, once per process")]
  #[inline]
  pub(crate) fn new<RNG>(rng: &mut RNG) -> Self
  where
    RNG: CryptoRng,
  {
    Self { reset: rng.u8_32(), retry: rng.u8_32() }
  }

  /// The stateless reset token of the connection ID `cid`.
  #[inline]
  pub(crate) fn reset_token(&self, cid: &[u8]) -> crate::Result<[u8; RESET_TOKEN_LEN]> {
    let mut hmac = HmacSha256Global::from_key(&self.reset)?;
    hmac.update(cid);
    let mut digest = hmac.finalize();
    let mut token = [0; RESET_TOKEN_LEN];
    if let Some(src) = digest.as_ref().get(..RESET_TOKEN_LEN) {
      token.copy_from_slice(src);
    }
    wipe(digest.as_mut());
    Ok(token)
  }

  /// Writes into `out` the token of a Retry with the source connection ID `retry_scid` that
  /// answers, at `now_us`, the first Initial packet of `peer` sent to `original_dcid`.
  #[inline]
  pub(crate) fn seal_retry_token<RNG>(
    &self,
    rng: &mut RNG,
    peer: SocketAddr,
    now_us: u64,
    original_dcid: &Cid,
    retry_scid: &[u8],
    out: &mut [u8; RETRY_TOKEN_LEN],
  ) -> crate::Result<()>
  where
    RNG: CryptoRng,
  {
    let nonce: [u8; AEAD_NONCE_LEN] = {
      let mut elem = [0; AEAD_NONCE_LEN];
      rng.fill_slice(&mut elem);
      elem
    };
    let (nonce_part, rest) = out.split_at_mut(AEAD_NONCE_LEN);
    nonce_part.copy_from_slice(&nonce);
    let (plaintext, tag_part) = rest.split_at_mut(PLAINTEXT_LEN);
    plaintext.copy_from_slice(&plaintext_of(peer, now_us, original_dcid));
    let key = Aes256GcmKeyGlobal::new(&self.retry)?;
    let tag = key.seal_in_place(nonce, retry_scid, plaintext)?;
    tag_part.copy_from_slice(&tag);
    Ok(())
  }

  /// The original destination connection ID that `token` carries, if it is a Retry token of
  /// this process that was issued to `peer` less than ten seconds before `now_us`, for a Retry
  /// whose source connection ID is `retry_scid`. `None` for any other token.
  #[inline]
  pub(crate) fn open_retry_token(
    &self,
    token: &[u8],
    peer: SocketAddr,
    now_us: u64,
    retry_scid: &[u8],
  ) -> Option<Cid> {
    let mut copy: [u8; RETRY_TOKEN_LEN] = token.try_into().ok()?;
    let (nonce, sealed) = copy.split_at_mut(AEAD_NONCE_LEN);
    let nonce: [u8; AEAD_NONCE_LEN] = (&*nonce).try_into().ok()?;
    let key = Aes256GcmKeyGlobal::new(&self.retry).ok()?;
    let plaintext = key.open_in_place(nonce, retry_scid, sealed).ok()?;
    let (address, rest) = plaintext.split_at_checked(18)?;
    let (issued, rest) = rest.split_at_checked(8)?;
    let (cid_len, cid) = rest.split_first()?;
    let issued = u64::from_be_bytes(issued.try_into().ok()?);
    if address != peer_bytes(peer).as_slice()
      || issued > now_us.saturating_add(CLOCK_SLACK_US)
      || now_us.saturating_sub(issued) >= RETRY_TOKEN_LIFETIME_US
    {
      return None;
    }
    Cid::new(cid.get(..usize::from(*cid_len))?).ok()
  }
}

impl Debug for EndpointKeys {
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("EndpointKeys").finish_non_exhaustive()
  }
}

impl Drop for EndpointKeys {
  #[inline]
  fn drop(&mut self) {
    wipe(&mut self.reset);
    wipe(&mut self.retry);
  }
}

// An address and a port, an IPv4 address as the IPv6 address that maps it: a dual-stack socket
// reports either.
fn peer_bytes(peer: SocketAddr) -> [u8; 18] {
  let ip = match peer.ip() {
    IpAddr::V4(elem) => elem.to_ipv6_mapped(),
    IpAddr::V6(elem) => elem.to_ipv4_mapped().map_or(elem, |el| el.to_ipv6_mapped()),
  };
  let mut rslt = [0; 18];
  let (head, tail) = rslt.split_at_mut(16);
  head.copy_from_slice(&ip.octets());
  tail.copy_from_slice(&peer.port().to_be_bytes());
  rslt
}

fn plaintext_of(peer: SocketAddr, now_us: u64, original_dcid: &Cid) -> [u8; PLAINTEXT_LEN] {
  let mut rslt = [0; PLAINTEXT_LEN];
  let (address, rest) = rslt.split_at_mut(18);
  address.copy_from_slice(&peer_bytes(peer));
  let (issued, rest) = rest.split_at_mut(8);
  issued.copy_from_slice(&now_us.to_be_bytes());
  let (cid_len, cid) = rest.split_at_mut(1);
  cid_len.copy_from_slice(&[u8::try_from(original_dcid.len()).unwrap_or(0)]);
  if let Some(dst) = cid.get_mut(..original_dcid.len()) {
    dst.copy_from_slice(original_dcid.as_slice());
  }
  rslt
}

#[cfg(test)]
mod tests {
  use crate::{
    quic::{
      Cid,
      token::{EndpointKeys, RETRY_TOKEN_LEN, RETRY_TOKEN_LIFETIME_US},
    },
    rng::ChaCha20,
  };
  use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

  const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 4433);

  fn keys(seed: u8) -> EndpointKeys {
    EndpointKeys::new(&mut ChaCha20::from_key([seed; 32]))
  }

  // A reset token depends on the CID and on the key, and on nothing else.
  #[test]
  fn reset_tokens_are_per_key_and_cid() {
    let (one, other) = (keys(1), keys(2));
    let cid = [0, 1, 2, 3, 4, 5, 6, 7];
    assert_eq!(one.reset_token(&cid).unwrap(), one.reset_token(&cid).unwrap());
    assert_ne!(one.reset_token(&cid).unwrap(), other.reset_token(&cid).unwrap());
    assert_ne!(one.reset_token(&cid).unwrap(), one.reset_token(&[0, 1, 2, 3, 4, 5, 6, 8]).unwrap());
  }

  // A Retry token opens for the peer, the Retry and the time that it was made for: not for
  // another peer, another source CID of the Retry, after ten seconds or under another key, and
  // not once a byte changed.
  #[test]
  fn retry_tokens_open_only_where_and_when_they_were_issued() {
    let keys = keys(1);
    let mut rng = ChaCha20::from_key([9; 32]);
    let odcid = Cid::new(&[0xaa; 20]).unwrap();
    let rscid = [3, 1, 4, 1, 5, 9, 2, 6];
    let mut token = [0; RETRY_TOKEN_LEN];
    keys.seal_retry_token(&mut rng, PEER, 1_000, &odcid, &rscid, &mut token).unwrap();
    assert_eq!(keys.open_retry_token(&token, PEER, 1_000, &rscid), Some(odcid));
    assert_eq!(
      keys.open_retry_token(&token, PEER, 1_000 + RETRY_TOKEN_LIFETIME_US - 1, &rscid),
      Some(odcid)
    );
    // The same peer, seen through a dual-stack socket
    let mapped = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped()), 4433);
    assert_eq!(keys.open_retry_token(&token, mapped, 2_000, &rscid), Some(odcid));
    assert_eq!(keys.open_retry_token(&token, PEER, 1_000 + RETRY_TOKEN_LIFETIME_US, &rscid), None);
    let other_port = SocketAddr::new(PEER.ip(), 4434);
    assert_eq!(keys.open_retry_token(&token, other_port, 1_000, &rscid), None);
    let other_ip = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4433);
    assert_eq!(keys.open_retry_token(&token, other_ip, 1_000, &rscid), None);
    assert_eq!(keys.open_retry_token(&token, PEER, 1_000, &[3, 1, 4, 1, 5, 9, 2, 7]), None);
    assert_eq!(self::keys(2).open_retry_token(&token, PEER, 1_000, &rscid), None);
    for idx in [0, RETRY_TOKEN_LEN / 2, RETRY_TOKEN_LEN - 1] {
      let mut tampered = token;
      tampered[idx] ^= 1;
      assert_eq!(keys.open_retry_token(&tampered, PEER, 1_000, &rscid), None, "{idx}");
    }
    assert_eq!(keys.open_retry_token(&token[1..], PEER, 1_000, &rscid), None);
    // Each token has its own nonce
    let mut again = [0; RETRY_TOKEN_LEN];
    keys.seal_retry_token(&mut rng, PEER, 1_000, &odcid, &rscid, &mut again).unwrap();
    assert_ne!(token, again);
    // A token from the future is refused beyond the slack of the clocks of the workers
    assert_eq!(keys.open_retry_token(&token, PEER, 0, &rscid), Some(odcid));
  }
}
