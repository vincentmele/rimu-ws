//! Frames (RFC 9000 section 19): a zero-copy, allocation-free reader of the payload of a decrypted
//! packet and a writer that fills a buffer of the caller frame by frame.

use crate::quic::{
  QuicError, TransportErrorCode,
  varint::{VARINT_MAX, decode_varint, varint_len},
  writer::Writer,
};
use core::{hint::cold_path, ops::RangeInclusive};

// Frame types. All of them have the shortest encoding of a variable-length integer, which takes a
// single byte (RFC 9000 section 12.4).
const PADDING: u8 = 0x00;
const PING: u8 = 0x01;
const ACK: u8 = 0x02;
const ACK_ECN: u8 = 0x03;
const RESET_STREAM: u8 = 0x04;
const STOP_SENDING: u8 = 0x05;
const CRYPTO: u8 = 0x06;
const NEW_TOKEN: u8 = 0x07;
// The types from 0x08 to 0x0f are STREAM frames, the three low bits are flags
const STREAM_FIRST: u8 = 0x08;
const STREAM_LAST: u8 = 0x0f;
const STREAM_FIN: u8 = 0x01;
const STREAM_LEN: u8 = 0x02;
const STREAM_OFF: u8 = 0x04;
const MAX_DATA: u8 = 0x10;
const MAX_STREAM_DATA: u8 = 0x11;
const MAX_STREAMS_BIDI: u8 = 0x12;
const MAX_STREAMS_UNI: u8 = 0x13;
const DATA_BLOCKED: u8 = 0x14;
const STREAM_DATA_BLOCKED: u8 = 0x15;
const STREAMS_BLOCKED_BIDI: u8 = 0x16;
const STREAMS_BLOCKED_UNI: u8 = 0x17;
const NEW_CONNECTION_ID: u8 = 0x18;
const RETIRE_CONNECTION_ID: u8 = 0x19;
const PATH_CHALLENGE: u8 = 0x1a;
const PATH_RESPONSE: u8 = 0x1b;
const CONNECTION_CLOSE: u8 = 0x1c;
const CONNECTION_CLOSE_APP: u8 = 0x1d;
const HANDSHAKE_DONE: u8 = 0x1e;

// A limit of streams above this one would allow stream IDs that need more than 62 bits
// (RFC 9000 sections 4.6 and 19.11).
const MAX_STREAMS_LIMIT: u64 = 1 << 60;
const MAX_CID_LEN: usize = crate::quic::MAX_CID_LEN;
const RESET_TOKEN_LEN: usize = 16;

/// The packet number space of the packet that carries frames.
///
/// `Data` stands for 0-RTT and 1-RTT packets, which share a space. The few frames that 0-RTT
/// packets can not carry are not told apart from the rest: this implementation does not accept
/// early data and drops 0-RTT packets, so they never reach the reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Space {
  /// Initial packets.
  Initial,
  /// Handshake packets.
  Handshake,
  /// 1-RTT (and 0-RTT) packets.
  Data,
}

impl Space {
  // RFC 9000 table 3. Only PADDING, PING, ACK, CRYPTO and CONNECTION_CLOSE of type 0x1c can be
  // sent before the handshake completes. The same table also forbids some frames to clients and
  // servers, which the connection checks because it is the one that knows its role.
  const fn allows(self, ty: u8) -> bool {
    match self {
      Self::Initial | Self::Handshake => {
        matches!(ty, PADDING | PING | ACK | ACK_ECN | CRYPTO | CONNECTION_CLOSE)
      }
      Self::Data => true,
    }
  }
}

/// A frame whose variable-sized fields point into the payload that it was read from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Frame<'a> {
  /// A run of PADDING bytes.
  Padding(usize),
  /// PING
  Ping,
  /// ACK (with ECN counts or without them)
  Ack(AckFrame<'a>),
  /// RESET_STREAM
  ResetStream { id: u64, code: u64, final_size: u64 },
  /// STOP_SENDING
  StopSending { id: u64, code: u64 },
  /// CRYPTO
  Crypto { offset: u64, data: &'a [u8] },
  /// NEW_TOKEN
  NewToken(&'a [u8]),
  /// STREAM
  Stream { id: u64, offset: u64, data: &'a [u8], fin: bool },
  /// MAX_DATA
  MaxData(u64),
  /// MAX_STREAM_DATA
  MaxStreamData { id: u64, max: u64 },
  /// MAX_STREAMS, of bidirectional or unidirectional streams
  MaxStreams { bidi: bool, max: u64 },
  /// DATA_BLOCKED
  DataBlocked(u64),
  /// STREAM_DATA_BLOCKED
  StreamDataBlocked { id: u64, max: u64 },
  /// STREAMS_BLOCKED, of bidirectional or unidirectional streams
  StreamsBlocked { bidi: bool, max: u64 },
  /// NEW_CONNECTION_ID
  NewConnectionId { seq: u64, retire_prior_to: u64, cid: &'a [u8], reset_token: &'a [u8; 16] },
  /// RETIRE_CONNECTION_ID
  RetireConnectionId(u64),
  /// PATH_CHALLENGE
  PathChallenge([u8; 8]),
  /// PATH_RESPONSE
  PathResponse([u8; 8]),
  /// CONNECTION_CLOSE of the transport (`app` is false, `frame_ty` is set) or of the application
  ConnectionClose { app: bool, code: u64, frame_ty: Option<u64>, reason: &'a [u8] },
  /// HANDSHAKE_DONE
  HandshakeDone,
}

/// The fields of an ACK frame. `delay` is the encoded value, that is, it is not scaled by the
/// `ack_delay_exponent` of the sender yet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AckFrame<'a> {
  /// The largest packet number that is acknowledged.
  pub(crate) largest: u64,
  /// The time between the receipt of `largest` and the sending of the frame, as encoded.
  pub(crate) delay: u64,
  /// The number of packets before `largest` that are acknowledged along with it.
  pub(crate) first_range: u64,
  /// ECT(0), ECT(1) and ECN-CE counts, if the frame has them.
  pub(crate) ecn: Option<[u64; 3]>,
  // The gap and length pairs after the first range, already checked by the reader
  ranges: &'a [u8],
  range_count: u64,
}

impl<'a> AckFrame<'a> {
  /// The acknowledged packet numbers as ranges, from the one with the largest packet numbers
  /// (the first range) to the one with the smallest.
  ///
  /// An error means that a range would start below zero, after which there are no more items. The
  /// reader already checks every ACK frame that it returns, so this can only fail for a frame that
  /// was built by hand.
  #[inline]
  pub(crate) fn ranges(
    &self,
  ) -> impl Iterator<Item = crate::Result<RangeInclusive<u64>>> + use<'a> {
    AckRanges::new(self.largest, self.first_range, self.ranges, self.range_count)
  }
}

// Decodes the first range, which comes from the fields of the frame, and then the pairs
struct AckRanges<'a> {
  // Until the first range is yielded
  first: Option<(u64, u64)>,
  pending: u64,
  rest: &'a [u8],
  // The smallest packet number of the range that was yielded last
  smallest: u64,
}

impl<'a> AckRanges<'a> {
  #[inline]
  const fn new(largest: u64, first_range: u64, rest: &'a [u8], range_count: u64) -> Self {
    Self { first: Some((largest, first_range)), pending: range_count, rest, smallest: 0 }
  }

  // RFC 9000 section 19.3.1: `smallest = largest - length` and the largest packet number of the
  // next range is `smallest - gap - 2`.
  fn next_pair(&mut self) -> crate::Result<RangeInclusive<u64>> {
    let Some((gap, gap_len)) = decode_varint(self.rest) else {
      return Err(truncated());
    };
    let after_gap = self.rest.get(gap_len..).unwrap_or_default();
    let Some((length, length_len)) = decode_varint(after_gap) else {
      return Err(truncated());
    };
    let Some(largest) = gap.checked_add(2).and_then(|elem| self.smallest.checked_sub(elem)) else {
      return Err(underflow());
    };
    let Some(smallest) = largest.checked_sub(length) else {
      return Err(underflow());
    };
    self.rest = after_gap.get(length_len..).unwrap_or_default();
    self.smallest = smallest;
    Ok(smallest..=largest)
  }
}

impl Iterator for AckRanges<'_> {
  type Item = crate::Result<RangeInclusive<u64>>;

  #[inline]
  fn next(&mut self) -> Option<Self::Item> {
    let result = if let Some((largest, first_range)) = self.first.take() {
      match largest.checked_sub(first_range) {
        Some(smallest) => {
          self.smallest = smallest;
          Ok(smallest..=largest)
        }
        None => Err(underflow()),
      }
    } else if self.pending == 0 {
      return None;
    } else {
      self.pending = self.pending.wrapping_sub(1);
      self.next_pair()
    };
    if result.is_err() {
      // Nothing is yielded after an error
      self.pending = 0;
    }
    Some(result)
  }
}

/// Reads the frames of the payload of a packet, in order.
///
/// Items borrow from the payload and nothing is allocated. After the first error there are no
/// more items: what follows a malformed frame can not be located. Errors are connection errors
/// ([`crate::Error::QuicClose`]): `FRAME_ENCODING_ERROR` for unknown or malformed frames,
/// `PROTOCOL_VIOLATION` for frames that the space does not allow and for frame types that are
/// encoded with more bytes than needed.
#[derive(Debug)]
pub(crate) struct FrameReader<'a> {
  rest: &'a [u8],
  space: Space,
}

impl<'a> FrameReader<'a> {
  /// `payload` is the decrypted payload of a packet of the given space.
  #[inline]
  pub(crate) const fn new(payload: &'a [u8], space: Space) -> Self {
    Self { rest: payload, space }
  }

  fn parse(&mut self) -> crate::Result<Frame<'a>> {
    let Some((raw_ty, ty_len)) = decode_varint(self.rest) else {
      return Err(truncated());
    };
    if ty_len != varint_len(raw_ty) {
      return Err(violation(QuicError::NonMinimalFrameType));
    }
    let Some(ty) = u8::try_from(raw_ty).ok().filter(|elem| *elem <= HANDSHAKE_DONE) else {
      return Err(encoding(QuicError::UnknownFrameType));
    };
    if !self.space.allows(ty) {
      return Err(violation(QuicError::FrameNotAllowed));
    }
    let mut cursor = Cursor { rest: self.rest.get(ty_len..).unwrap_or_default() };
    let frame = match ty {
      PADDING => {
        // The byte of the type is the first of the run
        let len = self.rest.iter().position(|byte| *byte != 0).unwrap_or(self.rest.len());
        cursor.rest = self.rest.get(len..).unwrap_or_default();
        Frame::Padding(len)
      }
      PING => Frame::Ping,
      ACK | ACK_ECN => {
        let largest = cursor.varint()?;
        let delay = cursor.varint()?;
        let range_count = cursor.varint()?;
        let first_range = cursor.varint()?;
        // The pairs are checked once here and, if wanted, once more by `AckFrame::ranges`
        let mut ranges = AckRanges::new(largest, first_range, cursor.rest, range_count);
        for range in &mut ranges {
          range?;
        }
        let len = cursor.rest.len().wrapping_sub(ranges.rest.len());
        let Some((ranges, rest)) = cursor.rest.split_at_checked(len) else {
          return Err(truncated());
        };
        cursor.rest = rest;
        let ecn = if ty == ACK_ECN {
          Some([cursor.varint()?, cursor.varint()?, cursor.varint()?])
        } else {
          None
        };
        Frame::Ack(AckFrame { largest, delay, first_range, ecn, ranges, range_count })
      }
      RESET_STREAM => Frame::ResetStream {
        id: cursor.varint()?,
        code: cursor.varint()?,
        final_size: cursor.varint()?,
      },
      STOP_SENDING => Frame::StopSending { id: cursor.varint()?, code: cursor.varint()? },
      CRYPTO => {
        let offset = cursor.varint()?;
        let len = cursor.varint()?;
        let data = cursor.take(len)?;
        check_end_of_data(offset, data)?;
        Frame::Crypto { offset, data }
      }
      NEW_TOKEN => {
        let len = cursor.varint()?;
        let token = cursor.take(len)?;
        if token.is_empty() {
          return Err(invalid());
        }
        Frame::NewToken(token)
      }
      STREAM_FIRST..=STREAM_LAST => {
        let id = cursor.varint()?;
        let offset = if ty & STREAM_OFF == 0 { 0 } else { cursor.varint()? };
        let data = if ty & STREAM_LEN == 0 {
          // Without a length the data go to the end of the packet
          core::mem::take(&mut cursor.rest)
        } else {
          let len = cursor.varint()?;
          cursor.take(len)?
        };
        check_end_of_data(offset, data)?;
        Frame::Stream { id, offset, data, fin: ty & STREAM_FIN != 0 }
      }
      MAX_DATA => Frame::MaxData(cursor.varint()?),
      MAX_STREAM_DATA => Frame::MaxStreamData { id: cursor.varint()?, max: cursor.varint()? },
      MAX_STREAMS_BIDI | MAX_STREAMS_UNI => {
        Frame::MaxStreams { bidi: ty == MAX_STREAMS_BIDI, max: cursor.stream_limit()? }
      }
      DATA_BLOCKED => Frame::DataBlocked(cursor.varint()?),
      STREAM_DATA_BLOCKED => {
        Frame::StreamDataBlocked { id: cursor.varint()?, max: cursor.varint()? }
      }
      STREAMS_BLOCKED_BIDI | STREAMS_BLOCKED_UNI => {
        Frame::StreamsBlocked { bidi: ty == STREAMS_BLOCKED_BIDI, max: cursor.stream_limit()? }
      }
      NEW_CONNECTION_ID => {
        let seq = cursor.varint()?;
        let retire_prior_to = cursor.varint()?;
        let cid_len = cursor.byte()?;
        if retire_prior_to > seq || cid_len == 0 || usize::from(cid_len) > MAX_CID_LEN {
          return Err(invalid());
        }
        let cid = cursor.take(u64::from(cid_len))?;
        let reset_token = cursor.array::<RESET_TOKEN_LEN>()?;
        Frame::NewConnectionId { seq, retire_prior_to, cid, reset_token }
      }
      RETIRE_CONNECTION_ID => Frame::RetireConnectionId(cursor.varint()?),
      PATH_CHALLENGE => Frame::PathChallenge(*cursor.array::<8>()?),
      PATH_RESPONSE => Frame::PathResponse(*cursor.array::<8>()?),
      CONNECTION_CLOSE | CONNECTION_CLOSE_APP => {
        let app = ty == CONNECTION_CLOSE_APP;
        let code = cursor.varint()?;
        let frame_ty = if app { None } else { Some(cursor.varint()?) };
        let len = cursor.varint()?;
        Frame::ConnectionClose { app, code, frame_ty, reason: cursor.take(len)? }
      }
      HANDSHAKE_DONE => Frame::HandshakeDone,
      // Checked above
      _ => return Err(encoding(QuicError::UnknownFrameType)),
    };
    self.rest = cursor.rest;
    Ok(frame)
  }
}

impl<'a> Iterator for FrameReader<'a> {
  type Item = crate::Result<Frame<'a>>;

  #[inline]
  fn next(&mut self) -> Option<Self::Item> {
    if self.rest.is_empty() {
      return None;
    }
    let result = self.parse();
    if result.is_err() {
      self.rest = &[];
    }
    Some(result)
  }
}

// The offset of the byte after the data of a CRYPTO or STREAM frame has an encoding
// (RFC 9000 sections 19.6 and 19.8).
fn check_end_of_data(offset: u64, data: &[u8]) -> crate::Result<()> {
  let end = u64::try_from(data.len()).ok().and_then(|len| offset.checked_add(len));
  if end.is_some_and(|elem| elem <= VARINT_MAX) { Ok(()) } else { Err(invalid()) }
}

struct Cursor<'a> {
  rest: &'a [u8],
}

impl<'a> Cursor<'a> {
  // A fixed number of bytes
  fn array<const N: usize>(&mut self) -> crate::Result<&'a [u8; N]> {
    let Some((head, tail)) = self.rest.split_first_chunk::<N>() else {
      return Err(truncated());
    };
    self.rest = tail;
    Ok(head)
  }

  fn byte(&mut self) -> crate::Result<u8> {
    let Some((head, tail)) = self.rest.split_first() else {
      return Err(truncated());
    };
    self.rest = tail;
    Ok(*head)
  }

  // A limit of streams
  fn stream_limit(&mut self) -> crate::Result<u64> {
    let limit = self.varint()?;
    if limit > MAX_STREAMS_LIMIT {
      return Err(invalid());
    }
    Ok(limit)
  }

  fn take(&mut self, len: u64) -> crate::Result<&'a [u8]> {
    let split = usize::try_from(len).ok().and_then(|elem| self.rest.split_at_checked(elem));
    let Some((head, tail)) = split else {
      return Err(truncated());
    };
    self.rest = tail;
    Ok(head)
  }

  fn varint(&mut self) -> crate::Result<u64> {
    let Some((value, len)) = decode_varint(self.rest) else {
      return Err(truncated());
    };
    self.rest = self.rest.get(len..).unwrap_or_default();
    Ok(value)
  }
}

/// Writes frames one after the other at the start of a buffer of the caller.
///
/// Every method writes a whole frame or nothing: if the frame does not fit, or has a field that
/// the wire format or the RFC does not allow, the method returns `false` and the writer is as it
/// was before the call. The buffer is not touched either, except by [`Self::write_ack`], which
/// can leave junk after the written bytes. The writer does not know the packet that carries the
/// frames: the caller picks the ones that the packet allows (RFC 9000 table 3).
#[derive(Debug)]
pub(crate) struct FrameWriter<'a> {
  inner: Writer<'a>,
}

impl<'a> FrameWriter<'a> {
  /// Starts at the beginning of `buf`.
  #[inline]
  pub(crate) const fn new(buf: &'a mut [u8]) -> Self {
    Self { inner: Writer::new(buf) }
  }

  /// The number of bytes written so far.
  #[inline]
  pub(crate) const fn len(&self) -> usize {
    self.inner.pos()
  }

  /// The number of bytes that can still be written.
  #[inline]
  pub(crate) const fn remaining(&self) -> usize {
    self.inner.remaining()
  }

  /// The bytes written so far.
  #[inline]
  pub(crate) fn written(&self) -> &[u8] {
    self.inner.written()
  }

  /// Writes an ACK frame without ECN counts. `delay` is the encoded value.
  ///
  /// `ranges` go from the one with the largest packet numbers to the one with the smallest. The
  /// first ends at `largest` and a range is always separated from the next by at least one
  /// packet number that is not acknowledged. Anything else is not written.
  ///
  /// The frame has all the ranges or it is not written, so callers that have more ranges than
  /// room should limit them. If it does not fit, junk can remain after the written bytes.
  pub(crate) fn write_ack(
    &mut self,
    largest: u64,
    delay: u64,
    ranges: impl Iterator<Item = RangeInclusive<u64>>,
  ) -> bool {
    let start = self.inner.pos();
    if put_ack(&mut self.inner, largest, delay, ranges).is_err() {
      cold_path();
      self.inner.rewind(start);
      return false;
    }
    true
  }

  /// Writes bytes that go after the header of a CRYPTO or STREAM frame.
  #[inline]
  pub(crate) fn write_bytes(&mut self, bytes: &[u8]) -> bool {
    self.frame(bytes.len(), &[], |writer| writer.put(bytes))
  }

  /// Writes a CONNECTION_CLOSE frame, of the application if `app` is true. The type of the frame
  /// that caused the error is only part of the transport variant, with 0 if there is none.
  ///
  /// A close of the application must not be sent in Initial and Handshake packets, a transport
  /// close with the error `APPLICATION_ERROR` takes its place there (RFC 9000 section 10.2.3).
  #[inline]
  pub(crate) fn write_connection_close(
    &mut self,
    app: bool,
    code: u64,
    frame_ty: Option<u64>,
    reason: &[u8],
  ) -> bool {
    self.write_frame(&Frame::ConnectionClose { app, code, frame_ty, reason })
  }

  /// Writes the header of a CRYPTO frame that is followed by `data_len` bytes, which must be
  /// written next with [`Self::write_bytes`]. Nothing is written if the data do not fit too.
  #[inline]
  pub(crate) fn write_crypto_header(&mut self, offset: u64, data_len: usize) -> bool {
    let Some(len) = data_len_if_end_is_valid(offset, data_len) else {
      cold_path();
      return false;
    };
    let size = sum([1, varint_len(offset), varint_len(len), data_len]);
    self.frame(size, &[offset], |writer| put_crypto_header(writer, offset, len))
  }

  /// Writes any frame, including its data. Fixed forms of the more common ones follow.
  pub(crate) fn write_frame(&mut self, frame: &Frame<'_>) -> bool {
    match *frame {
      Frame::Padding(len) => self.frame(len, &[], |writer| writer.zeros(len)),
      Frame::Ping => self.frame(1, &[], |writer| writer.put_u8(PING)),
      Frame::Ack(ack) => {
        let [ect0, ect1, ce] = ack.ecn.unwrap_or_default();
        let ecn_len = if ack.ecn.is_some() {
          sum([varint_len(ect0), varint_len(ect1), varint_len(ce)])
        } else {
          0
        };
        let size = sum([
          1,
          varint_len(ack.largest),
          varint_len(ack.delay),
          varint_len(ack.range_count),
          varint_len(ack.first_range),
          ack.ranges.len(),
          ecn_len,
        ]);
        let values = [ack.largest, ack.delay, ack.range_count, ack.first_range, ect0, ect1, ce];
        self.frame(size, &values, |writer| {
          writer.put_u8(if ack.ecn.is_some() { ACK_ECN } else { ACK })?;
          writer.varint(ack.largest)?;
          writer.varint(ack.delay)?;
          writer.varint(ack.range_count)?;
          writer.varint(ack.first_range)?;
          writer.put(ack.ranges)?;
          if ack.ecn.is_some() {
            writer.varint(ect0)?;
            writer.varint(ect1)?;
            writer.varint(ce)?;
          }
          Ok(())
        })
      }
      Frame::ResetStream { id, code, final_size } => {
        let size = sum([1, varint_len(id), varint_len(code), varint_len(final_size)]);
        self.frame(size, &[id, code, final_size], |writer| {
          writer.put_u8(RESET_STREAM)?;
          writer.varint(id)?;
          writer.varint(code)?;
          writer.varint(final_size)
        })
      }
      Frame::StopSending { id, code } => {
        let size = sum([1, varint_len(id), varint_len(code)]);
        self.frame(size, &[id, code], |writer| {
          writer.put_u8(STOP_SENDING)?;
          writer.varint(id)?;
          writer.varint(code)
        })
      }
      Frame::Crypto { offset, data } => {
        let Some(len) = data_len_if_end_is_valid(offset, data.len()) else {
          cold_path();
          return false;
        };
        let size = sum([1, varint_len(offset), varint_len(len), data.len()]);
        self.frame(size, &[offset], |writer| {
          put_crypto_header(writer, offset, len)?;
          writer.put(data)
        })
      }
      Frame::NewToken(token) => {
        let len = u64::try_from(token.len()).unwrap_or(u64::MAX);
        if token.is_empty() {
          cold_path();
          return false;
        }
        self.frame(sum([1, varint_len(len), token.len()]), &[len], |writer| {
          writer.put_u8(NEW_TOKEN)?;
          writer.varint(len)?;
          writer.put(token)
        })
      }
      Frame::Stream { id, offset, data, fin } => {
        let Some(len) = data_len_if_end_is_valid(offset, data.len()) else {
          cold_path();
          return false;
        };
        let size = sum([1, varint_len(id), stream_offset_len(offset), varint_len(len), data.len()]);
        self.frame(size, &[id], |writer| {
          put_stream_header(writer, id, offset, len, fin)?;
          writer.put(data)
        })
      }
      Frame::MaxData(max) => self.single_varint(MAX_DATA, max),
      Frame::MaxStreamData { id, max } => {
        let size = sum([1, varint_len(id), varint_len(max)]);
        self.frame(size, &[id, max], |writer| {
          writer.put_u8(MAX_STREAM_DATA)?;
          writer.varint(id)?;
          writer.varint(max)
        })
      }
      Frame::MaxStreams { bidi, max } => {
        let ty = if bidi { MAX_STREAMS_BIDI } else { MAX_STREAMS_UNI };
        self.stream_limit(ty, max)
      }
      Frame::DataBlocked(max) => self.single_varint(DATA_BLOCKED, max),
      Frame::StreamDataBlocked { id, max } => {
        let size = sum([1, varint_len(id), varint_len(max)]);
        self.frame(size, &[id, max], |writer| {
          writer.put_u8(STREAM_DATA_BLOCKED)?;
          writer.varint(id)?;
          writer.varint(max)
        })
      }
      Frame::StreamsBlocked { bidi, max } => {
        let ty = if bidi { STREAMS_BLOCKED_BIDI } else { STREAMS_BLOCKED_UNI };
        self.stream_limit(ty, max)
      }
      Frame::NewConnectionId { seq, retire_prior_to, cid, reset_token } => {
        let cid_len = u8::try_from(cid.len()).unwrap_or(u8::MAX);
        if retire_prior_to > seq || cid.is_empty() || cid.len() > MAX_CID_LEN {
          cold_path();
          return false;
        }
        let size =
          sum([1, varint_len(seq), varint_len(retire_prior_to), 1, cid.len(), RESET_TOKEN_LEN]);
        self.frame(size, &[seq, retire_prior_to], |writer| {
          writer.put_u8(NEW_CONNECTION_ID)?;
          writer.varint(seq)?;
          writer.varint(retire_prior_to)?;
          writer.put_u8(cid_len)?;
          writer.put(cid)?;
          writer.put(reset_token)
        })
      }
      Frame::RetireConnectionId(seq) => self.single_varint(RETIRE_CONNECTION_ID, seq),
      Frame::PathChallenge(data) => self.frame(9, &[], |writer| {
        writer.put_u8(PATH_CHALLENGE)?;
        writer.put(&data)
      }),
      Frame::PathResponse(data) => self.frame(9, &[], |writer| {
        writer.put_u8(PATH_RESPONSE)?;
        writer.put(&data)
      }),
      Frame::ConnectionClose { app, code, frame_ty, reason } => {
        let len = u64::try_from(reason.len()).unwrap_or(u64::MAX);
        let frame_ty = if app { None } else { Some(frame_ty.unwrap_or(0)) };
        let size =
          sum([1, varint_len(code), frame_ty.map_or(0, varint_len), varint_len(len), reason.len()]);
        self.frame(size, &[code, frame_ty.unwrap_or(0)], |writer| {
          writer.put_u8(if app { CONNECTION_CLOSE_APP } else { CONNECTION_CLOSE })?;
          writer.varint(code)?;
          if let Some(elem) = frame_ty {
            writer.varint(elem)?;
          }
          writer.varint(len)?;
          writer.put(reason)
        })
      }
      Frame::HandshakeDone => self.frame(1, &[], |writer| writer.put_u8(HANDSHAKE_DONE)),
    }
  }

  /// Writes a HANDSHAKE_DONE frame.
  #[inline]
  pub(crate) fn write_handshake_done(&mut self) -> bool {
    self.write_frame(&Frame::HandshakeDone)
  }

  /// Writes a MAX_DATA frame.
  #[inline]
  pub(crate) fn write_max_data(&mut self, max: u64) -> bool {
    self.write_frame(&Frame::MaxData(max))
  }

  /// Writes a MAX_STREAM_DATA frame.
  #[inline]
  pub(crate) fn write_max_stream_data(&mut self, id: u64, max: u64) -> bool {
    self.write_frame(&Frame::MaxStreamData { id, max })
  }

  /// Writes a MAX_STREAMS frame for bidirectional or unidirectional streams. `max` can not be
  /// above 2^60.
  #[inline]
  pub(crate) fn write_max_streams(&mut self, bidi: bool, max: u64) -> bool {
    self.write_frame(&Frame::MaxStreams { bidi, max })
  }

  /// Writes a NEW_CONNECTION_ID frame. `cid` has between 1 and 20 bytes and `retire_prior_to`
  /// can not be above `seq`.
  #[inline]
  pub(crate) fn write_new_connection_id(
    &mut self,
    seq: u64,
    retire_prior_to: u64,
    cid: &[u8],
    reset_token: &[u8; 16],
  ) -> bool {
    self.write_frame(&Frame::NewConnectionId { seq, retire_prior_to, cid, reset_token })
  }

  /// Writes `len` PADDING bytes.
  #[inline]
  pub(crate) fn write_padding(&mut self, len: usize) -> bool {
    self.write_frame(&Frame::Padding(len))
  }

  /// Writes a PATH_RESPONSE frame that echoes the data of a PATH_CHALLENGE.
  #[inline]
  pub(crate) fn write_path_response(&mut self, data: [u8; 8]) -> bool {
    self.write_frame(&Frame::PathResponse(data))
  }

  /// Writes the header of a STREAM frame that is followed by `data_len` bytes, which must be
  /// written next with [`Self::write_bytes`]. Nothing is written if the data do not fit too.
  ///
  /// The offset is only written if it is not zero and the length always is, so the frame can be
  /// followed by others.
  #[inline]
  pub(crate) fn write_stream_header(
    &mut self,
    id: u64,
    offset: u64,
    data_len: usize,
    fin: bool,
  ) -> bool {
    let Some(len) = data_len_if_end_is_valid(offset, data_len) else {
      cold_path();
      return false;
    };
    let size = sum([1, varint_len(id), stream_offset_len(offset), varint_len(len), data_len]);
    self.frame(size, &[id], |writer| put_stream_header(writer, id, offset, len, fin))
  }

  // Runs `write` if `size` bytes are available and every value is a valid variable-length
  // integer, so a frame that fits and is valid is never partially written. `size` is what `write`
  // writes plus the bytes of the data that the caller writes next, if any.
  #[inline]
  fn frame(
    &mut self,
    size: usize,
    values: &[u64],
    write: impl FnOnce(&mut Writer<'a>) -> crate::Result<()>,
  ) -> bool {
    if self.inner.remaining() < size || values.iter().any(|elem| *elem > VARINT_MAX) {
      cold_path();
      return false;
    }
    let start = self.inner.pos();
    if write(&mut self.inner).is_err() {
      cold_path();
      self.inner.rewind(start);
      return false;
    }
    true
  }

  // A frame that is its type and a variable-length integer
  #[inline]
  fn single_varint(&mut self, ty: u8, value: u64) -> bool {
    self.frame(sum([1, varint_len(value)]), &[value], |writer| {
      writer.put_u8(ty)?;
      writer.varint(value)
    })
  }

  // MAX_STREAMS and STREAMS_BLOCKED
  #[inline]
  fn stream_limit(&mut self, ty: u8, limit: u64) -> bool {
    if limit > MAX_STREAMS_LIMIT {
      cold_path();
      return false;
    }
    self.single_varint(ty, limit)
  }
}

fn put_ack(
  writer: &mut Writer<'_>,
  largest: u64,
  delay: u64,
  mut ranges: impl Iterator<Item = RangeInclusive<u64>>,
) -> crate::Result<()> {
  let Some(first) = ranges.next() else {
    return Err(invalid());
  };
  let (first_start, first_end) = (*first.start(), *first.end());
  if first_end != largest || first_start > first_end {
    return Err(invalid());
  }
  writer.put_u8(ACK)?;
  writer.varint(largest)?;
  writer.varint(delay)?;
  // The count is only known after the ranges and most of the time it takes a single byte
  let count_at = writer.pos();
  writer.put_u8(0)?;
  writer.varint(first_end.wrapping_sub(first_start))?;
  let mut smallest = first_start;
  let mut count: u64 = 0;
  for range in ranges {
    let (start, end) = (*range.start(), *range.end());
    // Packets from `end + 1` to `smallest - 1` are not acknowledged, there must be at least one
    let Some(gap) = end.checked_add(2).and_then(|elem| smallest.checked_sub(elem)) else {
      return Err(invalid());
    };
    if start > end {
      return Err(invalid());
    }
    writer.varint(gap)?;
    writer.varint(end.wrapping_sub(start))?;
    smallest = start;
    count = count.wrapping_add(1);
  }
  writer.expand_byte_into_varint(count_at, count)
}

fn put_crypto_header(writer: &mut Writer<'_>, offset: u64, data_len: u64) -> crate::Result<()> {
  writer.put_u8(CRYPTO)?;
  writer.varint(offset)?;
  writer.varint(data_len)
}

fn put_stream_header(
  writer: &mut Writer<'_>,
  id: u64,
  offset: u64,
  data_len: u64,
  fin: bool,
) -> crate::Result<()> {
  let mut ty = STREAM_FIRST | STREAM_LEN;
  if offset != 0 {
    ty |= STREAM_OFF;
  }
  if fin {
    ty |= STREAM_FIN;
  }
  writer.put_u8(ty)?;
  writer.varint(id)?;
  if offset != 0 {
    writer.varint(offset)?;
  }
  writer.varint(data_len)
}

// The length as a `u64` if the end of the data has an encoding
#[inline]
fn data_len_if_end_is_valid(offset: u64, data_len: usize) -> Option<u64> {
  let len = u64::try_from(data_len).ok()?;
  offset.checked_add(len).filter(|end| *end <= VARINT_MAX).map(|_| len)
}

#[inline]
const fn stream_offset_len(offset: u64) -> usize {
  if offset == 0 { 0 } else { varint_len(offset) }
}

#[inline]
fn sum<const N: usize>(parts: [usize; N]) -> usize {
  parts.iter().fold(0usize, |acc, elem| acc.wrapping_add(*elem))
}

// Errors of frames are errors of the connection

#[inline(always)]
fn encoding(kind: QuicError) -> crate::Error {
  cold_path();
  crate::Error::QuicClose(TransportErrorCode::FrameEncodingError, kind)
}

#[inline(always)]
fn invalid() -> crate::Error {
  encoding(QuicError::InvalidFrame)
}

#[inline(always)]
fn truncated() -> crate::Error {
  encoding(QuicError::Truncated)
}

#[inline(always)]
fn underflow() -> crate::Error {
  encoding(QuicError::AckRangeUnderflow)
}

#[inline(always)]
fn violation(kind: QuicError) -> crate::Error {
  cold_path();
  crate::Error::QuicClose(TransportErrorCode::ProtocolViolation, kind)
}

#[cfg(test)]
#[allow(clippy::single_range_in_vec_init, reason = "a single ACK range is a valid case")]
mod tests {
  use crate::{
    Error,
    quic::{
      QuicError, TransportErrorCode, VARINT_MAX,
      frame::{AckFrame, Frame, FrameReader, FrameWriter, Space},
    },
  };
  use alloc::{vec, vec::Vec};
  use core::ops::RangeInclusive;

  const CID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
  const TOKEN: [u8; 16] = hexd!(b"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");

  fn hex(input: &str) -> Vec<u8> {
    let digits: Vec<u8> = input
      .bytes()
      .filter(|byte| !byte.is_ascii_whitespace())
      .map(|byte| u8::try_from(char::from(byte).to_digit(16).unwrap()).unwrap())
      .collect();
    digits.chunks(2).map(|pair| (pair[0] << 4) | pair[1]).collect()
  }

  // Every frame type with its encoding, written by hand from RFC 9000 section 19
  fn cases() -> Vec<(Frame<'static>, Vec<u8>)> {
    vec![
      (Frame::Padding(3), hex("00 00 00")),
      (Frame::Ping, hex("01")),
      (Frame::ResetStream { id: 4, code: 0x1234, final_size: 100 }, hex("04 04 5234 4064")),
      (Frame::StopSending { id: 8, code: 7 }, hex("05 08 07")),
      (Frame::Crypto { offset: 16, data: &[1, 2, 3] }, hex("06 10 03 010203")),
      (Frame::NewToken(&[9, 9]), hex("07 02 0909")),
      (Frame::Stream { id: 4, offset: 0, data: &[0xaa, 0xbb], fin: false }, hex("0a 04 02 aabb")),
      (Frame::Stream { id: 4, offset: 0, data: &[0xaa, 0xbb], fin: true }, hex("0b 04 02 aabb")),
      (
        Frame::Stream { id: 4, offset: 300, data: &[0xaa, 0xbb], fin: false },
        hex("0e 04 412c 02 aabb"),
      ),
      (Frame::Stream { id: 4, offset: 300, data: &[], fin: true }, hex("0f 04 412c 00")),
      (Frame::MaxData(1_000_000), hex("10 800f4240")),
      (Frame::MaxStreamData { id: 4, max: 15_293 }, hex("11 04 7bbd")),
      (Frame::MaxStreams { bidi: true, max: 100 }, hex("12 4064")),
      (Frame::MaxStreams { bidi: false, max: 100 }, hex("13 4064")),
      (Frame::DataBlocked(63), hex("14 3f")),
      (Frame::StreamDataBlocked { id: 4, max: 64 }, hex("15 04 4040")),
      (Frame::StreamsBlocked { bidi: true, max: 3 }, hex("16 03")),
      (Frame::StreamsBlocked { bidi: false, max: 3 }, hex("17 03")),
      (
        Frame::NewConnectionId { seq: 1, retire_prior_to: 0, cid: &CID, reset_token: &TOKEN },
        hex("18 01 00 08 0102030405060708 a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
      ),
      (Frame::RetireConnectionId(2), hex("19 02")),
      (Frame::PathChallenge([1, 2, 3, 4, 5, 6, 7, 8]), hex("1a 0102030405060708")),
      (
        Frame::PathResponse([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]),
        hex("1b 1112131415161718"),
      ),
      (
        Frame::ConnectionClose { app: false, code: 0x0a, frame_ty: Some(6), reason: b"bad" },
        hex("1c 0a 06 03 626164"),
      ),
      (
        Frame::ConnectionClose { app: true, code: 0x101, frame_ty: None, reason: b"" },
        hex("1d 4101 00"),
      ),
      (Frame::HandshakeDone, hex("1e")),
    ]
  }

  fn read_ok(bytes: &[u8]) -> Vec<Frame<'_>> {
    FrameReader::new(bytes, Space::Data).map(|frame| frame.unwrap()).collect()
  }

  fn first_error(bytes: &[u8], space: Space) -> Error {
    FrameReader::new(bytes, space).find_map(Result::err).expect("an error")
  }

  #[track_caller]
  fn assert_close(error: Error, code: TransportErrorCode, kind: QuicError) {
    assert!(
      matches!(error, Error::QuicClose(elem_code, elem_kind) if elem_code == code && elem_kind == kind),
      "{error:?} is not {code:?} {kind:?}"
    );
  }

  fn ack_ranges(ack: &AckFrame<'_>) -> Vec<RangeInclusive<u64>> {
    ack.ranges().map(|range| range.unwrap()).collect()
  }

  // The frame written with the specific method of the writer, if it has one
  fn write_with_named_method(writer: &mut FrameWriter<'_>, frame: &Frame<'_>) -> bool {
    match *frame {
      Frame::Padding(len) => writer.write_padding(len),
      Frame::Crypto { offset, data } => {
        writer.write_crypto_header(offset, data.len()) && writer.write_bytes(data)
      }
      Frame::Stream { id, offset, data, fin } => {
        writer.write_stream_header(id, offset, data.len(), fin) && writer.write_bytes(data)
      }
      Frame::MaxData(max) => writer.write_max_data(max),
      Frame::MaxStreamData { id, max } => writer.write_max_stream_data(id, max),
      Frame::MaxStreams { bidi, max } => writer.write_max_streams(bidi, max),
      Frame::NewConnectionId { seq, retire_prior_to, cid, reset_token } => {
        writer.write_new_connection_id(seq, retire_prior_to, cid, reset_token)
      }
      Frame::PathResponse(data) => writer.write_path_response(data),
      Frame::ConnectionClose { app, code, frame_ty, reason } => {
        writer.write_connection_close(app, code, frame_ty, reason)
      }
      Frame::HandshakeDone => writer.write_handshake_done(),
      _ => writer.write_frame(frame),
    }
  }

  #[test]
  fn every_frame_round_trips() {
    for (frame, bytes) in cases() {
      let mut buffer = [0xaa; 128];
      let mut writer = FrameWriter::new(&mut buffer);
      assert!(writer.write_frame(&frame), "{frame:?}");
      assert_eq!(writer.written(), &bytes[..], "{frame:?}");
      assert_eq!(read_ok(&bytes), [frame], "{frame:?}");

      let mut buffer = [0xaa; 128];
      let mut writer = FrameWriter::new(&mut buffer);
      assert!(write_with_named_method(&mut writer, &frame), "{frame:?}");
      assert_eq!(writer.written(), &bytes[..], "{frame:?}");
    }
  }

  #[test]
  fn frames_in_sequence_and_padding_runs() {
    let mut payload = Vec::new();
    for (_, bytes) in cases() {
      payload.extend_from_slice(&bytes);
    }
    let expected: Vec<_> = cases().into_iter().map(|(frame, _)| frame).collect();
    assert_eq!(read_ok(&payload), expected);
    // Consecutive PADDING bytes are a single frame
    assert_eq!(
      read_ok(&hex("00 00 00 01 00 00")),
      [Frame::Padding(3), Frame::Ping, Frame::Padding(2)]
    );
    assert!(read_ok(&[]).is_empty());
  }

  #[test]
  fn ack_round_trips_and_pins_the_wire_format() {
    let mut buffer = [0xaa; 64];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(writer.write_ack(10, 5, [8..=10, 3..=5].into_iter()));
    assert_eq!(writer.written(), &hex("02 0a 05 01 02 01 02")[..]);
    let written = writer.written().to_vec();
    let frames = read_ok(&written);
    let [Frame::Ack(ack)] = frames[..] else {
      panic!("{frames:?}");
    };
    assert_eq!((ack.largest, ack.delay, ack.first_range, ack.ecn), (10, 5, 2, None));
    assert_eq!(ack_ranges(&ack), [8..=10, 3..=5]);
    // Writing what was read gives the same bytes
    let mut buffer = [0xaa; 64];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(writer.write_frame(&frames[0]));
    assert_eq!(writer.written(), &written[..]);

    // A single range, as in the server Initial of RFC 9001 appendix A.3
    let mut buffer = [0xaa; 64];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(writer.write_ack(0, 0, [0..=0].into_iter()));
    assert_eq!(writer.written(), &hex("02 00 00 00 00")[..]);

    // ECN counts follow the ranges and change the type
    let bytes = hex("03 0a 05 00 02 01 02 03");
    let frames = read_ok(&bytes);
    let [Frame::Ack(ack)] = frames[..] else {
      panic!("{frames:?}");
    };
    assert_eq!((ack.largest, ack.delay, ack.first_range), (10, 5, 2));
    assert_eq!(ack.ecn, Some([1, 2, 3]));
    assert_eq!(ack_ranges(&ack), [8..=10]);
    let mut buffer = [0xaa; 64];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(writer.write_frame(&frames[0]));
    assert_eq!(writer.written(), &bytes[..]);

    // Encodings that are longer than needed are valid
    let bytes = hex("02 4001 4000 4000 4000");
    let frames = read_ok(&bytes);
    let [Frame::Ack(ack)] = frames[..] else {
      panic!("{frames:?}");
    };
    assert_eq!((ack.largest, ack.delay, ack.first_range), (1, 0, 0));
    assert_eq!(ack_ranges(&ack), [1..=1]);
  }

  #[test]
  fn ack_count_takes_the_bytes_that_it_needs() {
    // 70 ranges of two packets: the count of 69 needs two bytes
    let ranges: Vec<_> = (0..70u64).map(|idx| (999 - 4 * idx)..=(1000 - 4 * idx)).collect();
    let mut buffer = vec![0xaa; 1024];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(writer.write_ack(1000, 1, ranges.iter().cloned()));
    let written = writer.written().to_vec();
    assert_eq!(written.get(..7), Some(&hex("02 43e8 01 4045 01")[..]));
    let frames = read_ok(&written);
    let [Frame::Ack(ack)] = frames[..] else {
      panic!("{frames:?}");
    };
    assert_eq!(ack_ranges(&ack), ranges);

    // Single packets separated by one hole: a count of 16 399 takes four bytes
    let ranges: Vec<_> =
      (0..16_400u64).map(|idx| (50_000 - 2 * idx)..=(50_000 - 2 * idx)).collect();
    let mut buffer = vec![0xaa; 40_000];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(writer.write_ack(50_000, 0, ranges.iter().cloned()));
    let written = writer.written().to_vec();
    assert_eq!(written.get(..11), Some(&hex("02 8000c350 00 8000400f 00")[..]));
    assert_eq!(written.len(), 11 + 16_399 * 2);
    let frames = read_ok(&written);
    let [Frame::Ack(ack)] = frames[..] else {
      panic!("{frames:?}");
    };
    assert_eq!(ack_ranges(&ack), ranges);

    // A count that does not fit after the ranges changes nothing
    let ranges: Vec<_> = (0..70u64).map(|idx| (999 - 4 * idx)..=(1000 - 4 * idx)).collect();
    let mut buffer = vec![0xaa; 1 + 2 + 1 + 1 + 1 + 69 * 2];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(!writer.write_ack(1000, 1, ranges.iter().cloned()));
    assert_eq!((writer.len(), writer.remaining()), (0, 144));
  }

  #[test]
  fn ack_ranges_descending_and_underflow_rejected() {
    // Gap 6 leads to packet 0
    let bytes = hex("02 0a 00 01 02 06 00");
    let frames = read_ok(&bytes);
    let [Frame::Ack(ack)] = frames[..] else {
      panic!("{frames:?}");
    };
    assert_eq!(ack_ranges(&ack), [8..=10, 0..=0]);
    let ranges = ack_ranges(&ack);
    assert!(ranges.windows(2).all(|pair| pair[1].end() < pair[0].start()));

    // One more would be packet -1
    assert_close(
      first_error(&hex("02 0a 00 01 02 07 00"), Space::Data),
      TransportErrorCode::FrameEncodingError,
      QuicError::AckRangeUnderflow,
    );
    // A range that is longer than the packet numbers below the gap
    assert_close(
      first_error(&hex("02 0a 00 01 02 01 06"), Space::Data),
      TransportErrorCode::FrameEncodingError,
      QuicError::AckRangeUnderflow,
    );
    // The first range is longer than the largest packet number
    assert_close(
      first_error(&hex("02 05 00 00 06"), Space::Data),
      TransportErrorCode::FrameEncodingError,
      QuicError::AckRangeUnderflow,
    );
    // The same checks hold for a frame that was not validated by the reader
    let mut ack =
      AckFrame { largest: 5, delay: 0, first_range: 6, ecn: None, ranges: &[], range_count: 0 };
    let mut iter = ack.ranges();
    assert!(matches!(
      iter.next(),
      Some(Err(Error::QuicClose(
        TransportErrorCode::FrameEncodingError,
        QuicError::AckRangeUnderflow
      )))
    ));
    assert!(iter.next().is_none());
    ack = AckFrame {
      largest: 10,
      delay: 0,
      first_range: 2,
      ecn: None,
      ranges: &[7, 0],
      range_count: 1,
    };
    let mut iter = ack.ranges();
    assert_eq!(iter.next().unwrap().unwrap(), 8..=10);
    assert!(iter.next().unwrap().is_err());
    assert!(iter.next().is_none());

    // More ranges than bytes, also when the count is the largest possible
    assert_close(
      first_error(&hex("02 0a 00 05 02 01 00"), Space::Data),
      TransportErrorCode::FrameEncodingError,
      QuicError::Truncated,
    );
    assert_close(
      first_error(&hex("02 0a 00 ffffffffffffffff 02 01 00"), Space::Data),
      TransportErrorCode::FrameEncodingError,
      QuicError::Truncated,
    );
    // A pair cut in half
    assert_close(
      first_error(&hex("02 0a 00 01 02 01"), Space::Data),
      TransportErrorCode::FrameEncodingError,
      QuicError::Truncated,
    );
  }

  #[test]
  fn ack_writer_rejects_ranges_that_are_not_descending() {
    let mut buffer = [0xaa; 64];
    let mut writer = FrameWriter::new(&mut buffer);
    // No ranges
    assert!(!writer.write_ack(10, 0, core::iter::empty()));
    // The first one does not end at the largest packet
    assert!(!writer.write_ack(10, 0, [5..=9].into_iter()));
    // Empty range
    assert!(!writer.write_ack(10, 0, [RangeInclusive::new(11, 10)].into_iter()));
    // Ascending
    assert!(!writer.write_ack(10, 0, [3..=5, 8..=10].into_iter()));
    // Touching or overlapping ranges would have to be a single one
    assert!(!writer.write_ack(10, 0, [8..=10, 5..=7].into_iter()));
    assert!(!writer.write_ack(10, 0, [8..=10, 5..=8].into_iter()));
    // A value that has no encoding
    assert!(!writer.write_ack(VARINT_MAX + 1, 0, [VARINT_MAX + 1..=VARINT_MAX + 1].into_iter()));
    assert!(!writer.write_ack(10, VARINT_MAX + 1, [10..=10].into_iter()));
    assert_eq!(writer.len(), 0);
    // Packets 8 to 10, a hole of 6 and 7 (a gap of 1), then 4 and 5
    assert!(writer.write_ack(10, 0, [8..=10, 4..=5].into_iter()));
    assert_eq!(writer.written(), &hex("02 0a 00 01 02 01 01")[..]);
  }

  #[test]
  fn stream_frame_offset_zero_omitted_len_always_set() {
    let mut buffer = [0xaa; 32];
    for (fin, ty) in [(false, 0x0a), (true, 0x0b)] {
      let mut writer = FrameWriter::new(&mut buffer);
      assert!(writer.write_stream_header(4, 0, 3, fin));
      assert!(writer.write_bytes(&[1, 2, 3]));
      assert_eq!(writer.written(), [ty, 4, 3, 1, 2, 3]);
    }
    for (fin, ty) in [(false, 0x0e), (true, 0x0f)] {
      let mut writer = FrameWriter::new(&mut buffer);
      assert!(writer.write_stream_header(4, 7, 3, fin));
      assert!(writer.write_bytes(&[1, 2, 3]));
      assert_eq!(writer.written(), [ty, 4, 7, 3, 1, 2, 3]);
    }
    // Without data
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(writer.write_stream_header(1 << 20, 0, 0, true));
    assert_eq!(writer.written(), [0x0b, 0x80, 0x10, 0x00, 0x00, 0x00]);
    // The header only fits together with the data that follows it
    for (cap, fits) in [(5, false), (6, true)] {
      let mut small = vec![0xaa; cap];
      let mut writer = FrameWriter::new(&mut small);
      assert_eq!(writer.write_stream_header(4, 0, 3, false), fits);
      assert_eq!(writer.len(), if fits { 3 } else { 0 });
      if fits {
        assert!(writer.write_bytes(&[1, 2, 3]));
        assert!(!writer.write_bytes(&[0]));
      }
    }
    // The end of the stream must have an encoding
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(!writer.write_stream_header(4, VARINT_MAX, 1, false));
    assert!(writer.write_stream_header(4, VARINT_MAX - 1, 1, false));
    assert!(!writer.write_stream_header(VARINT_MAX + 1, 0, 1, false));
  }

  #[test]
  fn stream_frames_without_length_take_the_rest_of_the_packet() {
    let bytes = hex("08 04 aabbcc");
    assert_eq!(
      read_ok(&bytes),
      [Frame::Stream { id: 4, offset: 0, data: &[0xaa, 0xbb, 0xcc], fin: false }]
    );
    let bytes = hex("0d 04 05 aa");
    assert_eq!(read_ok(&bytes), [Frame::Stream { id: 4, offset: 5, data: &[0xaa], fin: true }]);
    // A frame with a length is followed by more frames
    let bytes = hex("0a 04 01 aa 01");
    assert_eq!(
      read_ok(&bytes),
      [Frame::Stream { id: 4, offset: 0, data: &[0xaa], fin: false }, Frame::Ping]
    );
  }

  #[test]
  fn crypto_header_checks_the_data_too() {
    let mut buffer = [0xaa; 16];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(writer.write_crypto_header(300, 4));
    assert!(writer.write_bytes(&[1, 2, 3, 4]));
    assert_eq!(writer.written(), &hex("06 412c 04 01020304")[..]);
    let mut small = [0xaa; 7];
    let mut writer = FrameWriter::new(&mut small);
    assert!(!writer.write_crypto_header(300, 4));
    assert_eq!(writer.len(), 0);
    // The end of the data must have an encoding
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(!writer.write_crypto_header(VARINT_MAX, 1));
    assert!(writer.write_crypto_header(VARINT_MAX - 1, 1));
  }

  #[test]
  fn frame_not_allowed_in_initial_is_protocol_violation() {
    let stream = hex("0a 04 02 aabb");
    for space in [Space::Initial, Space::Handshake] {
      assert_close(
        first_error(&stream, space),
        TransportErrorCode::ProtocolViolation,
        QuicError::FrameNotAllowed,
      );
      // The type decides, before the rest of the frame is looked at
      assert_close(
        first_error(&[0x0a], space),
        TransportErrorCode::ProtocolViolation,
        QuicError::FrameNotAllowed,
      );
    }
    assert_eq!(read_ok(&stream).len(), 1);

    // RFC 9000 table 3: PADDING, PING, ACK, CRYPTO and CONNECTION_CLOSE of type 0x1c
    let early = [0x00, 0x01, 0x02, 0x03, 0x06, 0x1c];
    for ty in 0x00..=0x1e_u8 {
      for space in [Space::Initial, Space::Handshake] {
        let error = FrameReader::new(&[ty], space).next().unwrap().err();
        if early.contains(&ty) {
          assert!(
            !matches!(error, Some(Error::QuicClose(TransportErrorCode::ProtocolViolation, _))),
            "{ty:#x} in {space:?}"
          );
        } else {
          assert!(
            matches!(
              error,
              Some(Error::QuicClose(
                TransportErrorCode::ProtocolViolation,
                QuicError::FrameNotAllowed
              ))
            ),
            "{ty:#x} in {space:?}"
          );
        }
      }
    }
    // The ones that are allowed are read as usual
    for space in [Space::Initial, Space::Handshake] {
      let payload = hex("00 00 01 02 00 00 00 00 06 00 02 aabb 1c 0a 00 00");
      let frames: Vec<_> = FrameReader::new(&payload, space).map(|frame| frame.unwrap()).collect();
      assert_eq!(frames.len(), 5);
      assert_eq!(frames.get(2).map(|frame| matches!(frame, Frame::Ack(_))), Some(true));
      assert_eq!(frames.get(3), Some(&Frame::Crypto { offset: 0, data: &[0xaa, 0xbb] }));
      assert_eq!(
        frames.get(4),
        Some(&Frame::ConnectionClose { app: false, code: 0x0a, frame_ty: Some(0), reason: &[] })
      );
    }
    // Only the transport variant of CONNECTION_CLOSE is allowed
    assert_close(
      first_error(&hex("1d 0c 00"), Space::Initial),
      TransportErrorCode::ProtocolViolation,
      QuicError::FrameNotAllowed,
    );
    assert_eq!(read_ok(&hex("1d 0c 00")).len(), 1);
  }

  #[test]
  fn unknown_and_misencoded_frame_types() {
    for space in [Space::Initial, Space::Handshake, Space::Data] {
      // The first type after HANDSHAKE_DONE, and extension frames that were not negotiated
      for bytes in [&hex("1f")[..], &hex("30 00")[..], &hex("4040")[..], &hex("40af 00")[..]] {
        assert_close(
          first_error(bytes, space),
          TransportErrorCode::FrameEncodingError,
          QuicError::UnknownFrameType,
        );
      }
    }
    // A type must have the shortest encoding (RFC 9000 section 12.4)
    for bytes in
      [&hex("4001")[..], &hex("80000001")[..], &hex("c000000000000000")[..], &hex("4000")[..]]
    {
      assert_close(
        first_error(bytes, Space::Data),
        TransportErrorCode::ProtocolViolation,
        QuicError::NonMinimalFrameType,
      );
    }
    // Type cut in half
    assert_close(
      first_error(&hex("40"), Space::Data),
      TransportErrorCode::FrameEncodingError,
      QuicError::Truncated,
    );
  }

  #[test]
  fn truncated_frame_is_frame_encoding_error() {
    for (frame, bytes) in cases() {
      if matches!(frame, Frame::Padding(_)) {
        continue;
      }
      for cut in 1..bytes.len() {
        let error = first_error(&bytes[..cut], Space::Data);
        assert!(
          matches!(error, Error::QuicClose(TransportErrorCode::FrameEncodingError, _)),
          "{frame:?} cut at {cut}: {error:?}"
        );
      }
    }
    for bytes in
      [hex("03 0a 05 00 02 01 02"), hex("07 03 aabb"), hex("1a 01020304"), hex("18 01 00 08 0102")]
    {
      assert_close(
        first_error(&bytes, Space::Data),
        TransportErrorCode::FrameEncodingError,
        QuicError::Truncated,
      );
    }
    // The reader stops at the first error
    let bytes = hex("01 01 10");
    let mut reader = FrameReader::new(&bytes, Space::Data);
    assert!(matches!(reader.next(), Some(Ok(Frame::Ping))));
    assert!(matches!(reader.next(), Some(Ok(Frame::Ping))));
    assert!(matches!(reader.next(), Some(Err(_))));
    assert!(reader.next().is_none());
    assert!(reader.next().is_none());
  }

  #[test]
  fn invalid_field_values_are_frame_encoding_errors() {
    let invalid = |bytes: &str| {
      assert_close(
        first_error(&hex(bytes), Space::Data),
        TransportErrorCode::FrameEncodingError,
        QuicError::InvalidFrame,
      );
    };
    // NEW_TOKEN without a token
    invalid("07 00");
    // NEW_CONNECTION_ID with CIDs of 0 and 21 bytes, and with Retire Prior To after the sequence
    invalid("18 01 00 00 a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    invalid(
      "18 01 00 15 0102030405060708090a0b0c0d0e0f1011121314 15 a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    );
    invalid("18 01 02 01 aa a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    // Limits of streams above 2^60 cannot be stream IDs
    invalid("12 d000000000000001");
    invalid("13 d000000000000001");
    invalid("16 d000000000000001");
    invalid("17 d000000000000001");
    assert_eq!(
      read_ok(&hex("12 d000000000000000")),
      [Frame::MaxStreams { bidi: true, max: 1 << 60 }]
    );
    // The end of the data of STREAM and CRYPTO frames must be below 2^62
    invalid("0e 04 ffffffffffffffff 01 aa");
    invalid("0e 04 fffffffffffffffe 02 aabb");
    invalid("06 ffffffffffffffff 01 aa");
    invalid("06 fffffffffffffffe 02 aabb");
    assert_eq!(
      read_ok(&hex("06 fffffffffffffffe 01 aa")),
      [Frame::Crypto { offset: VARINT_MAX - 1, data: &[0xaa] }]
    );
    assert_eq!(
      read_ok(&hex("0f 04 ffffffffffffffff 00")),
      [Frame::Stream { id: 4, offset: VARINT_MAX, data: &[], fin: true }]
    );
  }

  #[test]
  fn rfc9001_initial_payloads() {
    // Appendix A.2: a CRYPTO frame with a ClientHello of 241 bytes and PADDING up to 1162 bytes
    let mut payload = hex("06 00 40f1");
    payload.extend_from_slice(&[0x01; 241]);
    payload.extend_from_slice(&[0; 917]);
    let frames: Vec<_> =
      FrameReader::new(&payload, Space::Initial).map(|frame| frame.unwrap()).collect();
    assert_eq!(frames, [Frame::Crypto { offset: 0, data: &[0x01; 241] }, Frame::Padding(917)]);
    // Appendix A.3: an ACK of packet 0 and a CRYPTO frame with a ServerHello of 90 bytes
    let mut payload = hex("02 00 00 00 00 06 00 40 5a");
    payload.extend_from_slice(&[0x02; 90]);
    let frames: Vec<_> =
      FrameReader::new(&payload, Space::Initial).map(|frame| frame.unwrap()).collect();
    let [Frame::Ack(ack), crypto] = frames[..] else {
      panic!("{frames:?}");
    };
    assert_eq!((ack.largest, ack.delay, ack.first_range, ack.ecn), (0, 0, 0, None));
    assert_eq!(ack_ranges(&ack), [0..=0]);
    assert_eq!(crypto, Frame::Crypto { offset: 0, data: &[0x02; 90] });
  }

  #[test]
  fn writer_never_writes_partial_frames() {
    for (frame, bytes) in cases() {
      // Whatever the capacity, a frame is all there or not there at all and the buffer is intact
      for cap in 0..bytes.len() {
        let mut buffer = vec![0xaa; cap];
        let mut writer = FrameWriter::new(&mut buffer);
        assert!(!writer.write_frame(&frame), "{frame:?} in {cap}");
        assert!(!write_with_named_method(&mut writer, &frame), "{frame:?} in {cap}");
        assert_eq!((writer.len(), writer.remaining()), (0, cap), "{frame:?} in {cap}");
        assert!(buffer.iter().all(|byte| *byte == 0xaa), "{frame:?} in {cap}");
      }
      // After another frame, which stays as it is
      for cap in 1..=bytes.len() + 1 {
        let mut buffer = vec![0xaa; cap];
        let mut writer = FrameWriter::new(&mut buffer);
        assert!(writer.write_frame(&Frame::Ping));
        assert_eq!(writer.write_frame(&frame), cap > bytes.len(), "{frame:?} in {cap}");
        assert_eq!(writer.len(), if cap > bytes.len() { 1 + bytes.len() } else { 1 });
        assert_eq!(writer.written().first(), Some(&1));
      }
    }
    // An ACK is not written with fewer ranges than it has
    let ranges: Vec<_> = (0..20u64).map(|idx| (100 - 4 * idx)..=(100 - 4 * idx)).collect();
    let mut buffer = vec![0xaa; 128];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(writer.write_ack(100, 0, ranges.iter().cloned()));
    let needed = writer.len();
    for cap in 0..needed {
      let mut buffer = vec![0xaa; cap];
      let mut writer = FrameWriter::new(&mut buffer);
      assert!(!writer.write_ack(100, 0, ranges.iter().cloned()), "ACK in {cap}");
      assert_eq!((writer.len(), writer.remaining()), (0, cap), "ACK in {cap}");
    }
    // The same holds for what follows a frame
    let mut buffer = vec![0xaa; needed];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(writer.write_handshake_done());
    assert!(!writer.write_ack(100, 0, ranges.iter().cloned()));
    assert_eq!(writer.written(), [0x1e]);
    // Raw bytes
    let mut buffer = [0xaa; 3];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(!writer.write_bytes(&[1, 2, 3, 4]));
    assert!(writer.write_bytes(&[1, 2]));
    assert!(!writer.write_bytes(&[3, 4]));
    assert!(writer.write_bytes(&[]));
    assert!(writer.write_bytes(&[3]));
    assert_eq!(writer.written(), [1, 2, 3]);
  }

  #[test]
  fn writer_rejects_values_that_a_frame_cannot_have() {
    let mut buffer = [0xaa; 128];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(!writer.write_max_data(VARINT_MAX + 1));
    assert!(!writer.write_max_stream_data(VARINT_MAX + 1, 0));
    assert!(!writer.write_max_streams(true, (1 << 60) + 1));
    assert!(!writer.write_max_streams(false, u64::MAX));
    assert!(!writer.write_frame(&Frame::StreamsBlocked { bidi: true, max: (1 << 60) + 1 }));
    assert!(!writer.write_frame(&Frame::NewToken(&[])));
    assert!(!writer.write_new_connection_id(1, 0, &[], &TOKEN));
    assert!(!writer.write_new_connection_id(1, 0, &[0; 21], &TOKEN));
    assert!(!writer.write_new_connection_id(1, 2, &CID, &TOKEN));
    assert!(!writer.write_connection_close(false, VARINT_MAX + 1, None, b""));
    assert!(!writer.write_frame(&Frame::ResetStream {
      id: 0,
      code: 0,
      final_size: VARINT_MAX + 1
    }));
    assert_eq!(writer.len(), 0);
    assert!(buffer.iter().all(|byte| *byte == 0xaa));
    assert!(FrameWriter::new(&mut buffer).write_max_streams(true, 1 << 60));
    assert!(FrameWriter::new(&mut buffer).write_new_connection_id(1, 1, &CID, &TOKEN));
    assert!(FrameWriter::new(&mut buffer).write_new_connection_id(1, 0, &[0; 20], &TOKEN));
  }

  #[test]
  fn padding_overwrites_old_content_and_connection_close_forms() {
    let mut buffer = [0xaa; 8];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(writer.write_padding(0));
    assert_eq!(writer.len(), 0);
    assert!(writer.write_padding(5));
    assert!(!writer.write_padding(4));
    assert_eq!(writer.written(), [0; 5]);
    assert_eq!(buffer, [0, 0, 0, 0, 0, 0xaa, 0xaa, 0xaa]);
    // A transport close without the type of the frame that caused it says 0, an application close
    // has no type
    let mut buffer = [0xaa; 16];
    let mut writer = FrameWriter::new(&mut buffer);
    assert!(writer.write_connection_close(false, 0x0a, None, b"x"));
    assert!(writer.write_connection_close(true, 0x0c, Some(9), b""));
    assert_eq!(writer.written(), &hex("1c 0a 00 01 78 1d 0c 00")[..]);
  }
}
