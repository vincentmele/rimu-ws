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
#[derive(Clone, Debug, Default)]
pub struct Alpn {
  /// List of names
  pub protocol_name_list: ArrayVectorCopy<ArrayVectorCopy<u8, 8>, MAX_ALPN_LEN>,
}

impl<'de> Decode<'de, TlsCc> for Alpn {
  #[inline]
  fn decode(dw: &mut TlsDecodeWrapper<'de>) -> crate::Result<Self> {
    let err = TlsError::InvalidOfferedPsks;
    let mut protocol_name_list = ArrayVectorCopy::new();
    u16_chunk(dw, err, |local_dw| {
      while !local_dw.bytes().is_empty() {
        u8_chunk(local_dw, err, |local_local_dw| {
          // RFC 7301 section 3.1: the server picks among the protocols it supports, so an offered
          // name that does not fit (more than 8 bytes, as "hq-interop", or beyond the fourth)
          // is not an error, it is a protocol that is not served
          if let Ok(name) = local_local_dw.bytes().try_into() {
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
