//! The frame codec over arbitrary bytes, for tests and the fuzzer: whatever the input is, the
//! reader returns frames or an error, never panics, its frames are consistent with the input and
//! the writer can reproduce them.

use crate::{
  Error,
  quic::{Frame, FrameReader, FrameWriter, Space, TransportErrorCode, VARINT_MAX},
};
use alloc::{vec, vec::Vec};
use core::ops::RangeInclusive;

/// Feeds `data` to the frame reader of every space and uses it to drive the writer.
#[inline]
pub fn check_bytes(data: &[u8]) {
  let initial = check_reader(data, Space::Initial);
  let handshake = check_reader(data, Space::Handshake);
  let data_space = check_reader(data, Space::Data);
  // The spaces differ in what they allow and in nothing else
  assert!(data_space.starts_with(&initial));
  assert!(data_space.starts_with(&handshake));
  check_ack_writer(data);
}

// Returns the frames before the end of the input or the first error
fn check_reader(payload: &[u8], space: Space) -> Vec<Frame<'_>> {
  let mut frames = Vec::new();
  let mut reader = FrameReader::new(payload, space);
  for result in &mut reader {
    match result {
      Ok(frame) => {
        check_frame(payload, space, &frame);
        frames.push(frame);
      }
      Err(error) => {
        assert!(matches!(
          error,
          Error::QuicClose(
            TransportErrorCode::FrameEncodingError | TransportErrorCode::ProtocolViolation,
            _
          )
        ));
        break;
      }
    }
  }
  // Nothing is read after the end or after an error
  assert!(reader.next().is_none());

  // What was read can be written and read again
  let mut buffer = vec![0xaa; payload.len().wrapping_add(16)];
  let mut writer = FrameWriter::new(&mut buffer);
  for frame in &frames {
    assert!(writer.write_frame(frame), "{frame:?}");
  }
  let written = writer.written();
  assert!(written.len() <= payload.len().wrapping_add(16));
  let again: Vec<_> = FrameReader::new(written, space).collect::<Result<_, _>>().unwrap();
  assert_eq!(again, frames);
  frames
}

fn check_frame(payload: &[u8], space: Space, frame: &Frame<'_>) {
  let within_payload = |bytes: &[u8]| {
    let (outer, inner) = (payload.as_ptr_range(), bytes.as_ptr_range());
    assert!(outer.start <= inner.start && inner.end <= outer.end);
  };
  if space != Space::Data {
    assert!(matches!(
      frame,
      Frame::Padding(_)
        | Frame::Ping
        | Frame::Ack(_)
        | Frame::Crypto { .. }
        | Frame::ConnectionClose { app: false, .. }
    ));
  }
  match *frame {
    Frame::Padding(len) => assert!(len > 0 && len <= payload.len()),
    Frame::Ack(ack) => {
      let mut previous_start = None;
      let mut count: u64 = 0;
      for range in ack.ranges() {
        let range = range.unwrap();
        assert!(range.start() <= range.end());
        match previous_start {
          // Starts with the largest packet number, which `first_range` packets follow
          None => {
            assert_eq!(*range.end(), ack.largest);
            assert_eq!(range.end() - range.start(), ack.first_range);
          }
          // At least one packet is not acknowledged between ranges
          Some(previous) => assert!(range.end() + 1 < previous),
        }
        previous_start = Some(*range.start());
        count += 1;
      }
      assert!(count >= 1);
    }
    Frame::Crypto { offset, data } | Frame::Stream { offset, data, .. } => {
      within_payload(data);
      assert!(offset + u64::try_from(data.len()).unwrap() <= VARINT_MAX);
    }
    Frame::NewToken(token) => {
      within_payload(token);
      assert!(!token.is_empty());
    }
    Frame::MaxStreams { max, .. } | Frame::StreamsBlocked { max, .. } => {
      assert!(max <= 1 << 60);
    }
    Frame::NewConnectionId { seq, retire_prior_to, cid, reset_token } => {
      within_payload(cid);
      within_payload(reset_token);
      assert!((1..=20).contains(&cid.len()));
      assert!(retire_prior_to <= seq);
    }
    Frame::ConnectionClose { app, frame_ty, reason, .. } => {
      within_payload(reason);
      assert_eq!(app, frame_ty.is_none());
    }
    _ => {}
  }
  // The writer takes as many bytes as the frame needs, no more and no less
  let mut buffer = vec![0xaa; payload.len().wrapping_add(16)];
  let mut writer = FrameWriter::new(&mut buffer);
  assert!(writer.write_frame(frame));
  let needed = writer.len();
  for capacity in [needed.wrapping_sub(1), needed / 2, 0] {
    if capacity >= needed {
      continue;
    }
    let mut small = vec![0xaa; capacity];
    let mut writer = FrameWriter::new(&mut small);
    assert!(!writer.write_frame(frame));
    assert_eq!((writer.len(), writer.remaining()), (0, capacity));
    assert!(small.iter().all(|byte| *byte == 0xaa));
  }
  let mut exact = vec![0xaa; needed];
  assert!(FrameWriter::new(&mut exact).write_frame(frame));
}

// Builds ranges out of `data` and checks that an ACK frame with them is read back unchanged
fn check_ack_writer(data: &[u8]) {
  let Some((&[a, b, c, d, delay], pairs)) = data.split_first_chunk::<5>() else {
    return;
  };
  let largest = u64::from(u32::from_be_bytes([a, b, c, d]));
  let delay = u64::from(delay) * 997;
  let mut ranges: Vec<RangeInclusive<u64>> = Vec::new();
  let mut end = largest;
  for &[length, gap] in pairs.as_chunks::<2>().0 {
    let start = end.saturating_sub(u64::from(length));
    ranges.push(start..=end);
    // At least one packet number between ranges
    let Some(next_end) = start.checked_sub(u64::from(gap) + 2) else {
      break;
    };
    end = next_end;
  }
  if ranges.is_empty() {
    ranges.push(largest..=largest);
  }
  let mut buffer = vec![0xaa; data.len().wrapping_mul(2).wrapping_add(64)];
  let mut writer = FrameWriter::new(&mut buffer);
  assert!(writer.write_ack(largest, delay, ranges.iter().cloned()));
  let written = writer.written();
  let needed = written.len();
  let frames: Vec<_> =
    FrameReader::new(written, Space::Handshake).collect::<Result<_, _>>().unwrap();
  let [Frame::Ack(ack)] = frames[..] else {
    panic!("{frames:?}");
  };
  assert_eq!((ack.largest, ack.delay, ack.ecn), (largest, delay, None));
  let read: Vec<_> = ack.ranges().collect::<Result<_, _>>().unwrap();
  assert_eq!(read, ranges);
  // Writing what was read, instead of the ranges, gives the same bytes
  let mut again = vec![0xaa; needed];
  let mut writer = FrameWriter::new(&mut again);
  assert!(writer.write_frame(&frames[0]));
  assert_eq!(writer.written(), written);
  // One byte less does not fit and leaves the writer as it was
  let mut small = vec![0xaa; needed.wrapping_sub(1)];
  let mut writer = FrameWriter::new(&mut small);
  assert!(!writer.write_ack(largest, delay, ranges.iter().cloned()));
  assert_eq!(writer.len(), 0);
}

#[cfg(test)]
mod tests {
  use crate::quic::frame_check::check_bytes;
  use alloc::vec::Vec;

  // Frames that are valid, to be put together and damaged
  const SEEDS: [&[u8]; 9] = [
    &hexd!(b"0a0402aabb"),
    &hexd!(b"0e04412c02aabb"),
    &hexd!(b"0602aabb"),
    &hexd!(b"020a05010201"),
    &hexd!(b"030a050102010102030405"),
    &hexd!(b"1801000801020304050607080a0b0c0d0e0f101112131415161718"),
    &hexd!(b"1c0a06036261641d0c00"),
    &hexd!(b"0000000100010707020909"),
    &hexd!(b"1011223344556677121f1c1e"),
  ];

  #[test]
  fn arbitrary_bytes_do_not_break_the_frame_codec() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      state
    };
    let mut data = Vec::new();
    for round in 0..4_000 {
      data.clear();
      match round % 3 {
        // Noise
        0 => {
          for _ in 0..next() % 64 {
            data.push(u8::try_from(next() & 0xff).unwrap());
          }
        }
        // Noise that starts with a type that exists
        1 => {
          data.push(u8::try_from(next() % 0x20).unwrap());
          for _ in 0..next() % 32 {
            data.push(u8::try_from(next() & 0xff).unwrap());
          }
        }
        // Valid frames with a few changed bytes and a cut
        _ => {
          for _ in 0..1 + next() % 4 {
            data.extend_from_slice(SEEDS[usize::try_from(next() % 9).unwrap()]);
          }
          for _ in 0..next() % 3 {
            let idx = usize::try_from(next()).unwrap() % data.len();
            data[idx] = u8::try_from(next() & 0xff).unwrap();
          }
          if next() % 4 == 0 {
            data.truncate(usize::try_from(next()).unwrap() % data.len());
          }
        }
      }
      check_bytes(&data);
    }
    for seed in SEEDS {
      check_bytes(seed);
    }
  }
}
