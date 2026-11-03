use crate::{collections::VectorUsize, net::BufStreamReader};

#[derive(Debug)]
#[doc = _internal_buffer_doc!()]
pub struct WebSocketBuffer {
  pub(crate) network_buffer: BufStreamReader,
  // Used for decompression
  pub(crate) reader_buffer: VectorUsize<u8>,
  pub(crate) writer_buffer: VectorUsize<u8>,
  // Frames written with `write_frame_buffered` that haven't been sent yet
  pub(crate) write_queue: VectorUsize<u8>,
}

impl WebSocketBuffer {
  /// New empty instance
  #[inline]
  pub const fn new() -> Self {
    Self {
      network_buffer: BufStreamReader::new(),
      reader_buffer: VectorUsize::new(),
      writer_buffer: VectorUsize::new(),
      write_queue: VectorUsize::new(),
    }
  }

  pub(crate) fn clear(&mut self) {
    let Self { network_buffer, reader_buffer, writer_buffer, write_queue } = self;
    network_buffer.clear();
    reader_buffer.clear();
    writer_buffer.clear();
    write_queue.clear();
  }
}

impl Default for WebSocketBuffer {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}
