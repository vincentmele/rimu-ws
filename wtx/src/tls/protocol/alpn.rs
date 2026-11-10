// https://datatracker.ietf.org/doc/html/rfc7301

use crate::{
  codec::{Decode, Encode},
  collections::ArrayVectorCopy,
  misc::counter_writer::{CounterWriterBytesTy, CounterWriterIterTy, u8_write, u16_write_iter},
  tls::{
    MAX_ALPN_LEN, TlsError,
    misc::{u8_chunk, u16_chunk},
    tls_cc::TlsCc,
    tls_cc_wrappers::{TlsDecodeWrapper, TlsEncodeWrapper},
  },
};

/// Application-Layer Protocol Negotiation Extension
///
/// <https://datatracker.ietf.org/doc/html/rfc7301>
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Alpn {
  /// List of names
  pub protocol_name_list: ArrayVectorCopy<ArrayVectorCopy<u8, 8>, MAX_ALPN_LEN>,
}

impl Alpn {
  /// The ALPN of a ClientHello, for a server that serves the names in `dw.served_alpn()`
  /// (RFC 7301 section 3.2: it picks one of the protocols it supports, from any position of the
  /// list of the client). The list of the client has no limit and a name of the client can be of
  /// any length, so only what can be picked is kept, in the order of the client: the names that
  /// the server serves and the empty ones, which the server refuses. The other names are skipped
  /// as they are read, which needs no memory and cannot lose a name that matches.
  #[inline]
  pub(crate) fn decode_offer(dw: &mut TlsDecodeWrapper<'_>) -> crate::Result<Self> {
    let err = TlsError::InvalidOfferedPsks;
    let served = dw.served_alpn().clone();
    let mut protocol_name_list = ArrayVectorCopy::new();
    u16_chunk(dw, err, |local_dw| {
      while !local_dw.bytes().is_empty() {
        u8_chunk(local_dw, err, |local_local_dw| {
          let bytes = local_local_dw.bytes();
          if let Ok(name) = ArrayVectorCopy::<u8, 8>::try_from(bytes)
            && (name.is_empty() || served.protocol_name_list.contains(&name))
          {
            let _rslt = protocol_name_list.push(name);
          }
          Ok(())
        })?;
      }
      Ok(())
    })?;
    Ok(Self { protocol_name_list })
  }
}

impl<'de> Decode<'de, TlsCc> for Alpn {
  #[inline]
  fn decode(dw: &mut TlsDecodeWrapper<'de>) -> crate::Result<Self> {
    let err = TlsError::InvalidOfferedPsks;
    let mut protocol_name_list = ArrayVectorCopy::new();
    u16_chunk(dw, err, |local_dw| {
      while !local_dw.bytes().is_empty() {
        u8_chunk(local_dw, err, |local_local_dw| {
          protocol_name_list.push(local_local_dw.bytes().try_into()?)?;
          Ok(())
        })?;
      }
      Ok(())
    })?;
    Ok(Self { protocol_name_list })
  }
}

impl Encode<TlsCc> for Alpn {
  #[inline]
  fn encode(&self, ew: &mut TlsEncodeWrapper<'_>) -> crate::Result<()> {
    u16_write_iter(
      CounterWriterIterTy::Bytes(CounterWriterBytesTy::IgnoresLen),
      self.protocol_name_list.iter(),
      None,
      ew,
      |elem, local_ew| {
        u8_write(CounterWriterBytesTy::IgnoresLen, None, local_ew, |local_local_ew| {
          local_local_ew.buffer().extend_from_copyable_slice(elem)?;
          crate::Result::Ok(())
        })
      },
    )?;
    Ok(())
  }
}
