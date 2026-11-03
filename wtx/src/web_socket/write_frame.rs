// Common functions that used be used by pure WebSocket structures or tunneling protocols.

use crate::{
  codec::CompressionFlush,
  collections::{MaybeUninitSlice, VectorUsize},
  misc::{Lease, LeaseMut},
  net::{StreamCommon, StreamReader, StreamWriter},
  rng::Rng,
  web_socket::{
    Frame, FrameMut, mask_op::mask_op, misc::has_masked_frame,
    web_socket_compression::WebSocketCompression,
  },
};
use core::{hint::cold_path, num::NonZeroUsize};

/// Queued frames are sent once the queue reaches this many bytes, even if nothing would block.
/// Payloads of at least this size bypass the queue (no copy) and are sent with whatever is
/// queued in front of them.
pub(crate) const WRITE_QUEUE_FLUSH_LEN: usize = 16 * 1024;

/// A stream whose reads and writes first send the frames queued by `write_frame_buffered`.
///
/// Reading flushes before the socket is touched, so queued replies always go out before the
/// connection can block waiting for its peer. Writing puts the queue and the new bytes in one
/// syscall, which keeps frames in the order they were written.
pub(crate) struct QueuedStream<'any, S> {
  pub(crate) stream: &'any mut S,
  pub(crate) write_queue: &'any mut VectorUsize<u8>,
}

impl<S> StreamCommon for QueuedStream<'_, S> {}

impl<S> StreamReader for QueuedStream<'_, S>
where
  S: StreamReader + StreamWriter,
{
  #[inline]
  async fn read(&mut self, bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<Option<NonZeroUsize>> {
    flush_write_queue(self.stream, self.write_queue).await?;
    self.stream.read(bytes).await
  }
}

impl<S> StreamWriter for QueuedStream<'_, S>
where
  S: StreamWriter,
{
  #[inline]
  async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
    if self.write_queue.is_empty() {
      return self.stream.write_all(bytes).await;
    }
    self.stream.write_all_vectored(&[self.write_queue.as_slice(), bytes]).await?;
    self.write_queue.clear();
    Ok(())
  }

  #[inline]
  async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
    if self.write_queue.is_empty() {
      return self.stream.write_all_vectored(bytes).await;
    }
    let mut slices: [&[u8]; 8] = [&[]; 8];
    if let (Some(first), Some(rest)) = (self.write_queue.get(..), slices.get_mut(1..=bytes.len())) {
      rest.copy_from_slice(bytes);
      slices[0] = first;
      self.stream.write_all_vectored(slices.get(..=bytes.len()).unwrap_or_default()).await?;
      self.write_queue.clear();
      return Ok(());
    }
    cold_path();
    flush_write_queue(self.stream, self.write_queue).await?;
    self.stream.write_all_vectored(bytes).await
  }
}

pub(crate) async fn flush_write_queue<SW>(
  stream_writer: &mut SW,
  write_queue: &mut VectorUsize<u8>,
) -> crate::Result<()>
where
  SW: StreamWriter,
{
  if !write_queue.is_empty() {
    stream_writer.write_all(write_queue).await?;
    write_queue.clear();
  }
  Ok(())
}

/// Appends `frame` to `write_queue` instead of writing it. See [`QueuedStream`].
pub(crate) async fn write_frame_buffered<C, P, R, SW, const IS_CLIENT: bool>(
  frame: &mut Frame<P>,
  no_masking: bool,
  nc: &mut C,
  nc_rsv1: u8,
  rng: &mut R,
  stream_writer: &mut SW,
  writer_buffer: &mut VectorUsize<u8>,
  write_queue: &mut VectorUsize<u8>,
  closed_conn_cb: impl FnOnce(&mut SW),
) -> crate::Result<()>
where
  C: WebSocketCompression,
  P: LeaseMut<[u8]>,
  R: Rng,
  SW: StreamWriter,
{
  if manage_compression::<C, _>(frame, nc_rsv1) {
    let fr = manage_frame_compression::<_, _, _, IS_CLIENT>(
      nc,
      nc_rsv1,
      frame,
      no_masking,
      rng,
      writer_buffer,
    )?;
    enqueue(fr.header(), fr.payload(), stream_writer, write_queue).await?;
  } else {
    mask_frame::<_, _, IS_CLIENT>(frame, no_masking, rng);
    let (header, payload) = frame.header_and_payload_mut();
    enqueue(header, payload.lease(), stream_writer, write_queue).await?;
  }
  if frame.op_code().is_close() {
    cold_path();
    flush_write_queue(stream_writer, write_queue).await?;
    closed_conn_cb(stream_writer);
  }
  Ok(())
}

/// Queues `frame` without awaiting anything if it can be: a small, uncompressed frame that is not
/// a close frame and leaves the queue under [`WRITE_QUEUE_FLUSH_LEN`]. Returns `false`, with the
/// frame untouched, for everything else, which is left to [`write_frame_buffered`].
#[inline(always)]
pub(crate) fn try_queue_frame<C, P, R, const IS_CLIENT: bool>(
  frame: &mut Frame<P>,
  no_masking: bool,
  nc_rsv1: u8,
  rng: &mut R,
  write_queue: &mut VectorUsize<u8>,
) -> crate::Result<bool>
where
  C: WebSocketCompression,
  P: LeaseMut<[u8]>,
  R: Rng,
{
  let op_code = frame.op_code();
  let is_uncompressed = C::IS_NOOP || nc_rsv1 == 0 || op_code.is_control();
  let len = write_queue
    .len()
    .wrapping_add(frame.header().len())
    .wrapping_add(frame.payload().lease().len());
  if !is_uncompressed || op_code.is_close() || len >= WRITE_QUEUE_FLUSH_LEN {
    return Ok(false);
  }
  mask_frame::<_, _, IS_CLIENT>(frame, no_masking, rng);
  let (header, payload) = frame.header_and_payload_mut();
  let payload = payload.lease();
  let header_len = header.len();
  let added = header_len.wrapping_add(payload.len());
  if write_queue.capacity().wrapping_sub(write_queue.len()) < added {
    write_queue.reserve(added)?;
  }
  let (_, spare) = write_queue.split_at_spare_mut();
  if spare.len() < added {
    cold_path();
    let _ = write_queue.extend_from_copyable_slices([&*header, payload])?;
    return Ok(true);
  }
  let dst = spare.as_mut_ptr().cast::<u8>();
  // SAFETY: `spare` has room for `added` bytes, which the two copies fill
  unsafe {
    copy_small(dst, header);
    copy_small(dst.add(header_len), payload);
    write_queue.set_len(write_queue.len().wrapping_add(added));
  }
  Ok(true)
}

/// Copies `src` to `dst` without calling `memcpy` for the short lengths that frame headers and
/// small payloads have, where the call costs more than the copy: up to 32 bytes become at most
/// two fixed-size, possibly overlapping, moves.
///
/// # Safety
///
/// `dst` must be valid for `src.len()` bytes and not overlap `src`.
#[inline(always)]
unsafe fn copy_small(dst: *mut u8, src: &[u8]) {
  let len = src.len();
  let from = src.as_ptr();
  // SAFETY: every read is within `src` and every write within the `len` bytes of `dst`
  unsafe {
    match len {
      0 => {}
      1..=3 => {
        *dst = *from;
        *dst.add(len / 2) = *from.add(len / 2);
        *dst.add(len - 1) = *from.add(len - 1);
      }
      4..=7 => {
        dst.cast::<[u8; 4]>().write_unaligned(from.cast::<[u8; 4]>().read_unaligned());
        dst
          .add(len - 4)
          .cast::<[u8; 4]>()
          .write_unaligned(from.add(len - 4).cast::<[u8; 4]>().read_unaligned());
      }
      8..=15 => {
        dst.cast::<[u8; 8]>().write_unaligned(from.cast::<[u8; 8]>().read_unaligned());
        dst
          .add(len - 8)
          .cast::<[u8; 8]>()
          .write_unaligned(from.add(len - 8).cast::<[u8; 8]>().read_unaligned());
      }
      16..=32 => {
        dst.cast::<[u8; 16]>().write_unaligned(from.cast::<[u8; 16]>().read_unaligned());
        dst
          .add(len - 16)
          .cast::<[u8; 16]>()
          .write_unaligned(from.add(len - 16).cast::<[u8; 16]>().read_unaligned());
      }
      _ => core::ptr::copy_nonoverlapping(from, dst, len),
    }
  }
}

async fn enqueue<SW>(
  header: &[u8],
  payload: &[u8],
  stream_writer: &mut SW,
  write_queue: &mut VectorUsize<u8>,
) -> crate::Result<()>
where
  SW: StreamWriter,
{
  if payload.len() >= WRITE_QUEUE_FLUSH_LEN {
    stream_writer.write_all_vectored(&[write_queue.as_slice(), header, payload]).await?;
    write_queue.clear();
    return Ok(());
  }
  let _ = write_queue.extend_from_copyable_slices([header, payload])?;
  if write_queue.len() >= WRITE_QUEUE_FLUSH_LEN {
    flush_write_queue(stream_writer, write_queue).await?;
  }
  Ok(())
}

pub(crate) fn mask_frame<P, R, const IS_CLIENT: bool>(
  frame: &mut Frame<P>,
  no_masking: bool,
  rng: &mut R,
) where
  P: LeaseMut<[u8]>,
  R: Rng,
{
  if IS_CLIENT && !no_masking && !has_masked_frame(*frame.header_first_two_mut()[1]) {
    let mask: [u8; 4] = rng.u8_4();
    frame.set_mask(mask);
    mask_op(frame.payload_mut().lease_mut(), mask);
  }
}

pub(crate) async fn write_frame<C, P, R, SW, const IS_CLIENT: bool>(
  frame: &mut Frame<P>,
  no_masking: bool,
  nc: &mut C,
  nc_rsv1: u8,
  rng: &mut R,
  stream_writer: &mut SW,
  writer_buffer: &mut VectorUsize<u8>,
  closed_conn_cb: impl FnOnce(&mut SW),
) -> crate::Result<()>
where
  C: WebSocketCompression,
  P: LeaseMut<[u8]>,
  R: Rng,
  SW: StreamWriter,
{
  if manage_compression::<C, _>(frame, nc_rsv1) {
    let fr = manage_frame_compression::<_, _, _, IS_CLIENT>(
      nc,
      nc_rsv1,
      frame,
      no_masking,
      rng,
      writer_buffer,
    )?;
    stream_writer.write_all_vectored(&[fr.header(), fr.payload()]).await?;
  } else {
    mask_frame::<_, _, IS_CLIENT>(frame, no_masking, rng);
    let (header, payload) = frame.header_and_payload_mut();
    stream_writer.write_all_vectored(&[header, payload.lease()]).await?;
  }
  if frame.op_code().is_close() {
    cold_path();
    closed_conn_cb(stream_writer);
  }
  Ok(())
}

fn compress_frame<'cb, C, P>(
  frame: &mut Frame<P>,
  nc: &mut C,
  nc_rsv1: u8,
  writer_buffer: &'cb mut VectorUsize<u8>,
) -> crate::Result<FrameMut<'cb>>
where
  C: WebSocketCompression,
  P: LeaseMut<[u8]>,
{
  writer_buffer.clear();
  let bytes = frame.payload().lease();
  let mut payload_len = nc.compress(CompressionFlush::SyncFlush, bytes, writer_buffer)?;
  if frame.fin() {
    if !C::IS_NOOP && nc.no_context_takeover() {
      nc.reset();
    }
    payload_len = payload_len.saturating_sub(4);
  }
  Ok(FrameMut::new(
    frame.fin(),
    frame.op_code(),
    writer_buffer.get_mut(..payload_len).unwrap_or_default(),
    nc_rsv1,
  ))
}

fn manage_compression<C, P>(frame: &mut Frame<P>, nc_rsv1: u8) -> bool
where
  C: WebSocketCompression,
  P: Lease<[u8]>,
{
  if C::IS_NOOP {
    return false;
  }
  let mut should_compress = false;
  if !frame.op_code().is_control() {
    let [first, _] = frame.header_first_two_mut();
    should_compress = nc_rsv1 != 0;
    *first |= nc_rsv1;
  }
  should_compress
}

fn manage_frame_compression<'cb, C, P, R, const IS_CLIENT: bool>(
  nc: &mut C,
  nc_rsv1: u8,
  frame: &mut Frame<P>,
  no_masking: bool,
  rng: &mut R,
  writer_buffer: &'cb mut VectorUsize<u8>,
) -> crate::Result<FrameMut<'cb>>
where
  C: WebSocketCompression,
  P: LeaseMut<[u8]>,
  R: Rng,
{
  let mut compressed_frame = compress_frame(frame, nc, nc_rsv1, writer_buffer)?;
  mask_frame::<_, _, IS_CLIENT>(&mut compressed_frame, no_masking, rng);
  Ok(compressed_frame)
}

#[cfg(test)]
mod tests {
  use crate::web_socket::write_frame::copy_small;

  #[test]
  fn copy_small_copies_every_length() {
    let src: alloc::vec::Vec<u8> = (0..80u8).collect();
    for len in 0..80 {
      let mut dst = [0xAAu8; 81];
      // SAFETY: `dst` has room for `len` bytes
      unsafe { copy_small(dst.as_mut_ptr(), &src[..len]) };
      assert_eq!(&dst[..len], &src[..len]);
      assert!(dst[len..].iter().all(|el| *el == 0xAA), "wrote past {len}");
    }
  }
}
