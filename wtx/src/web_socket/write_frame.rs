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
