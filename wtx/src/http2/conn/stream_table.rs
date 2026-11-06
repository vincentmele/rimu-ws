//! The connection's open streams, in reusable slots.

use crate::{
  collections::{DequeUsize, VectorUsize},
  http::{Headers, Method, MsgBufferString, MsgDataMut as _, Protocol, StatusCode},
  http2::conn::body::SharedBytes,
};

/// Body bytes queued on a stream until the windows let them go.
#[derive(Debug)]
pub(crate) enum SendItem {
  /// The next `len` bytes of `Stream::owned`.
  Owned(usize),
  /// Shared bytes, sent by reference.
  Shared(SharedBytes),
}

impl SendItem {
  pub(crate) fn len(&self) -> usize {
    match self {
      Self::Owned(len) => *len,
      Self::Shared(elem) => elem.len(),
    }
  }
}
use hashbrown::HashMap;

/// One open stream.
#[derive(Debug)]
pub(crate) struct Stream {
  /// The declared `content-length` of the body being received, if any.
  pub(crate) content_length: Option<usize>,
  pub(crate) id: u32,
  pub(crate) method: Option<Method>,
  /// The request (server) or response (client) being received. Its buffers are kept when the
  /// slot is freed, so the next stream reuses them.
  pub(crate) msg: MsgBufferString,
  pub(crate) protocol: Option<Protocol>,
  /// Body bytes received so far.
  pub(crate) recv_body_len: usize,
  /// The peer sent END_STREAM.
  pub(crate) recv_closed: bool,
  /// Flow-control window for what the peer sends us.
  pub(crate) recv_window: i32,
  /// The initial HEADERS have arrived (later HEADERS are trailers).
  pub(crate) recv_headers: bool,
  /// We sent END_STREAM.
  pub(crate) send_closed: bool,
  /// We sent the initial HEADERS.
  pub(crate) send_headers: bool,
  /// Flow-control window for what we send. May go negative after a SETTINGS change.
  pub(crate) send_window: i32,
  /// The stream is in the connection's list of streams waiting for window.
  pub(crate) blocked: bool,
  /// Send END_STREAM once the queue drains.
  pub(crate) end_after_queue: bool,
  /// Bytes of the front queue item already sent.
  pub(crate) front_sent: usize,
  /// Copies of borrowed bodies that could not be sent at once.
  pub(crate) owned: VectorUsize<u8>,
  /// Bytes of `owned` already sent.
  pub(crate) owned_read: usize,
  /// Capacity released by the application and not yet announced in a WINDOW_UPDATE.
  pub(crate) recv_unacked: u32,
  pub(crate) send_queue: DequeUsize<SendItem>,
  /// The response status (client).
  pub(crate) status: Option<StatusCode>,
  /// Trailers to send once the queue drains, encoded only then so header blocks reach the peer in
  /// the order they were encoded.
  pub(crate) trailers: Option<Headers>,
}

impl Stream {
  fn new() -> Self {
    Self {
      content_length: None,
      id: 0,
      method: None,
      msg: MsgBufferString::default(),
      protocol: None,
      recv_body_len: 0,
      recv_closed: false,
      recv_window: 0,
      recv_headers: false,
      send_closed: false,
      send_headers: false,
      send_window: 0,
      blocked: false,
      end_after_queue: false,
      front_sent: 0,
      owned: VectorUsize::new(),
      owned_read: 0,
      recv_unacked: 0,
      send_queue: DequeUsize::new(),
      status: None,
      trailers: None,
    }
  }

  /// Body bytes queued and not yet sent.
  pub(crate) fn send_pending(&self) -> usize {
    self.send_queue.iter().map(SendItem::len).sum::<usize>().saturating_sub(self.front_sent)
  }

  fn reset(&mut self, id: u32, recv_window: i32, send_window: i32) {
    self.content_length = None;
    self.id = id;
    self.method = None;
    self.msg.clear();
    self.protocol = None;
    self.recv_body_len = 0;
    self.recv_closed = false;
    self.recv_window = recv_window;
    self.recv_headers = false;
    self.send_closed = false;
    self.send_headers = false;
    self.send_window = send_window;
    self.blocked = false;
    self.end_after_queue = false;
    self.front_sent = 0;
    self.owned.clear();
    self.owned_read = 0;
    self.recv_unacked = 0;
    self.send_queue.clear();
    self.status = None;
    self.trailers = None;
  }
}

/// Open streams by id. Freed slots keep their buffers for reuse.
#[derive(Debug)]
pub(crate) struct StreamTable {
  free: VectorUsize<usize>,
  ids: HashMap<u32, usize>,
  slots: VectorUsize<Stream>,
}

impl StreamTable {
  pub(crate) fn new() -> Self {
    Self { free: VectorUsize::new(), ids: HashMap::new(), slots: VectorUsize::new() }
  }

  /// Number of open streams.
  pub(crate) fn len(&self) -> usize {
    self.ids.len()
  }

  pub(crate) fn contains(&self, id: u32) -> bool {
    self.ids.contains_key(&id)
  }

  pub(crate) fn get(&self, id: u32) -> Option<&Stream> {
    let idx = *self.ids.get(&id)?;
    self.slots.get(idx)
  }

  pub(crate) fn get_mut(&mut self, id: u32) -> Option<&mut Stream> {
    let idx = *self.ids.get(&id)?;
    self.slots.get_mut(idx)
  }

  /// Opens stream `id` in a free slot, or a new one.
  pub(crate) fn open(
    &mut self,
    id: u32,
    recv_window: i32,
    send_window: i32,
  ) -> crate::Result<&mut Stream> {
    let idx = if let Some(idx) = self.free.pop() {
      idx
    } else {
      self.slots.push(Stream::new())?;
      self.slots.len().wrapping_sub(1)
    };
    let _ = self.ids.insert(id, idx);
    let stream = self.slots.get_mut(idx).ok_or(crate::Error::ProgrammingError)?;
    stream.reset(id, recv_window, send_window);
    Ok(stream)
  }

  /// Closes stream `id`, keeping its slot's buffers for the next stream.
  pub(crate) fn close(&mut self, id: u32) -> bool {
    let Some(idx) = self.ids.remove(&id) else {
      return false;
    };
    if let Some(stream) = self.slots.get_mut(idx) {
      stream.msg.clear();
      stream.owned.clear();
      stream.send_queue.clear();
      stream.trailers = None;
    }
    let _rslt = self.free.push(idx);
    true
  }

  /// Every open stream.
  pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Stream> {
    let ids = &self.ids;
    self.slots.iter_mut().filter(move |el| ids.get(&el.id).is_some())
  }
}
