use crate::http2::{Http2Error, Http2ErrorCode, common_flags::CommonFlags};

pub(crate) const fn protocol_err(error: Http2Error) -> crate::Error {
  crate::Error::Http2ErrorGoAway(Http2ErrorCode::ProtocolError, error)
}

pub(crate) fn trim_frame_pad(cf: CommonFlags, data: &mut &[u8]) -> crate::Result<Option<u8>> {
  let mut pad_len = None;
  if cf.has_pad() {
    let [local_pad_len, rest @ ..] = data else {
      return Err(protocol_err(Http2Error::InvalidFramePad));
    };
    let idx_opt = rest.len().checked_sub(usize::from(*local_pad_len));
    let Some(local_data) = idx_opt.and_then(|idx| rest.get(..idx)) else {
      return Err(protocol_err(Http2Error::InvalidFramePad));
    };
    *data = local_data;
    pad_len = Some(*local_pad_len);
  }
  Ok(pad_len)
}
