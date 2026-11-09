//! What the HTTP/3 layer keeps for a connection (ruling T13-a).
//!
//! Inline, in the connection, only [`H3ConnState`]: a box taken from the pool of the worker's
//! [`H3App`](crate::http3::H3App) once the connection is established and given back once it is
//! closed. The box, [`H3Conn`], holds the stream identifiers of both sides, the settings of the
//! peer, the QPACK decoder and its memo, the state of the requests being read (indexed by stream
//! index modulo the window of client streams, which two open streams never share) and the GOAWAY
//! that was sent.
//!
//! A box is cleared when it goes back to the pool, so that a pooled box holds no state of a
//! request (ruling T13-a, review V5): a new epoch for the decoder table, so that the memo of the
//! previous connection replays nothing, the memo cleared, so that its decoded bytes do not stay,
//! and the requests forgotten.
//!
//! # Memory
//!
//! The buffers of the requests (heads, bodies, bytes that wait) take at most
//! [`H3Params::max_buffered_body_per_conn`] bytes of capacity per connection ([`Budget`], ruling
//! T13-g): a request that would take more is answered as one whose body is too large. An entry
//! keeps small buffers only once its request is done, and so does a pooled box (review V4).

use crate::{
  collections::VectorUsize,
  http3::{
    DecodeMemo, H3Params, H3Settings, QpackDecoder,
    request::{Fields, H3Request, RequestHead},
  },
  quic::{ConnHandle, QuicConn, StreamId},
};
use alloc::boxed::Box;

/// The capacity of a head buffer, or of the bytes that wait for a request, that an entry keeps once
/// its request is done; larger ones are freed (review V4).
pub(crate) const KEEP_HEAD: usize = 4 * 1024;
/// The capacity of a body buffer that an entry keeps once its request is done.
pub(crate) const KEEP_BODY: usize = 16 * 1024;
/// The capacity of the other buffers of a connection (the decoder scratch, the part of an
/// encoder-stream instruction that waits) that a pooled box keeps.
const KEEP_OTHER: usize = 4 * 1024;
/// The capacity that a response buffer of the worker keeps after a write (review V4).
pub(crate) const KEEP_SCRATCH: usize = 16 * 1024;
/// The smallest capacity, in bytes, that a request buffer grows to.
const MIN_GROWTH: usize = 256;
/// Requests read at once at most: the window of client-initiated bidirectional streams.
const REQ_WINDOW: usize = 256;

// Ruling T13-a: what the connection keeps inline for HTTP/3 is at most 160 bytes, and so a
// connection of the production build with its HTTP/3 state is at most 4 KiB (spec section 5.4).
const _: () = {
  assert!(size_of::<H3ConnState>() <= 160);
  assert!(
    size_of::<
      QuicConn<crate::http3::H3App<SizeProbeHandler>, crate::rng::ChaCha20, crate::tls::SkCtx>,
    >()
      <= 4096
  );
};

/// The state of a connection, inline: see the [module documentation](self).
#[derive(Debug, Default)]
pub(crate) struct H3ConnState {
  /// From the pool of the worker while the connection is established.
  pub(crate) conn: Option<Box<H3Conn>>,
}

#[cfg(test)]
impl H3ConnState {
  /// The capacity that the request buffers hold, in bytes.
  pub(crate) fn buffered(&self) -> usize {
    self.conn.as_ref().map_or(0, |el| el.budget.held)
  }

  /// Requests read, answered later or not answered yet.
  pub(crate) fn live_requests(&self) -> u32 {
    self.conn.as_ref().map_or(0, |el| el.live)
  }

  /// The field sections that the memo replayed.
  pub(crate) fn memo_hits(&self) -> u64 {
    self.conn.as_ref().map_or(0, |el| el.memo.hits)
  }

  /// The settings of the peer, once its SETTINGS frame arrived.
  pub(crate) fn peer_settings(&self) -> Option<H3Settings> {
    self.conn.as_ref().and_then(|el| el.settings)
  }
}

/// The capacity that the request buffers of a connection hold, in bytes, and the most that they
/// may hold (ruling T13-g). It is counted where the buffers grow and where they are freed.
#[derive(Debug)]
pub(crate) struct Budget {
  held: usize,
  max: usize,
}

impl Budget {
  /// Nothing held, at most `max` bytes.
  pub(crate) const fn new(max: usize) -> Self {
    Self { held: 0, max }
  }

  /// If `buf` can take `add` more elements without the budget being passed.
  pub(crate) fn fits<T>(&self, buf: &VectorUsize<T>, add: usize) -> bool {
    let need = buf.len().saturating_add(add);
    need <= buf.capacity() || need.saturating_mul(size_of::<T>()) <= self.room_for(buf)
  }

  /// Makes room in `buf` for `add` more elements: by doubling while the budget allows, and never
  /// past `hint` (the length that it will have, if known), else as much as is needed. Returns
  /// `false`, and grows nothing, if that is more than the budget allows.
  pub(crate) fn grow<T>(
    &mut self,
    buf: &mut VectorUsize<T>,
    add: usize,
    hint: Option<usize>,
  ) -> crate::Result<bool> {
    let need = buf.len().saturating_add(add);
    let capacity = buf.capacity();
    if need <= capacity {
      return Ok(true);
    }
    let size = size_of::<T>().max(1);
    let room = self.room_for(buf) / size;
    if need > room {
      return Ok(false);
    }
    let min = MIN_GROWTH / size;
    let target =
      capacity.saturating_mul(2).max(min).min(room).min(hint.unwrap_or(usize::MAX)).max(need);
    let others = self.held.saturating_sub(bytes(buf));
    buf.reserve_exact(target.wrapping_sub(buf.len()))?;
    self.held = others.saturating_add(bytes(buf));
    Ok(true)
  }

  /// Frees `buf` if its capacity is more than `keep` bytes.
  pub(crate) fn trim<T>(&mut self, buf: &mut VectorUsize<T>, keep: usize) {
    let held = bytes(buf);
    if held > keep {
      self.held = self.held.saturating_sub(held);
      *buf = VectorUsize::new();
    }
  }

  /// If more than half of the budget is held: what entries without a request keep is freed
  /// before a new head is decoded.
  pub(crate) const fn is_tight(&self) -> bool {
    self.held > self.max / 2
  }

  // The bytes that `buf` may hold at most: what the others leave
  fn room_for<T>(&self, buf: &VectorUsize<T>) -> usize {
    self.max.saturating_sub(self.held.saturating_sub(bytes(buf)))
  }
}

/// Where a request is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
  /// The entry holds no request.
  Free,
  /// Before the HEADERS frame of the head.
  Head,
  /// After the head: DATA frames, or the HEADERS frame of the trailers.
  Body,
  /// After the trailers: nothing but unknown frames.
  Trailers,
  /// Given to the handler, which answers it later.
  Parked,
}

/// The payload of a frame that the stream is in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameLeft {
  /// Between frames.
  None,
  /// The bytes of a DATA frame that did not arrive yet.
  Data(u64),
  /// The bytes of an unknown frame that are still to skip.
  Skip(u64),
}

/// A request that is being read, or that the handler answers later.
#[derive(Debug)]
pub(crate) struct Req {
  /// The payloads of the DATA frames.
  pub(crate) body: VectorUsize<u8>,
  /// Its field section waits for QPACK inserts that did not arrive yet.
  pub(crate) blocked: bool,
  /// The FIN arrived, while what came before it waits in `stash`.
  pub(crate) fin: bool,
  /// The frame that the stream is in.
  pub(crate) frame: FrameLeft,
  /// The decoded head.
  pub(crate) head: RequestHead,
  /// Its stream.
  pub(crate) id: StreamId,
  /// Where it is.
  pub(crate) phase: Phase,
  /// What arrived and could not be read yet: a HEADERS frame larger than what the connection
  /// retains (4 KiB), or what follows a field section that waits for QPACK inserts (ruling T13-b).
  pub(crate) stash: VectorUsize<u8>,
}

impl Req {
  const fn new() -> Self {
    Self {
      body: VectorUsize::new(),
      blocked: false,
      fin: false,
      frame: FrameLeft::None,
      head: RequestHead::new(),
      id: StreamId(0),
      phase: Phase::Free,
      stash: VectorUsize::new(),
    }
  }

  /// The request for the handler, whose fields are `fields`.
  pub(crate) fn request(&self) -> H3Request<'_> {
    H3Request {
      method: self.head.method(),
      scheme: self.head.scheme(),
      authority: self.head.authority(),
      path: self.head.path(),
      fields: Fields::new(&self.head),
      host: self.head.host(),
      body: self.body.as_slice(),
      stream: self.id,
    }
  }

  // Forgets the request; the buffers stay if they are small, up to `head`, `body` and `stash`
  // bytes.
  fn clear(&mut self, budget: &mut Budget, head: usize, body: usize, stash: usize) {
    self.body.clear();
    self.blocked = false;
    self.fin = false;
    self.frame = FrameLeft::None;
    self.head.clear();
    self.phase = Phase::Free;
    self.stash.clear();
    self.head.trim(budget, head);
    budget.trim(&mut self.body, body);
    budget.trim(&mut self.stash, stash);
  }
}

/// The state of an established connection, in a box of the pool: see the
/// [module documentation](self).
#[derive(Debug)]
pub(crate) struct H3Conn {
  /// Field sections that wait for QPACK inserts: their stream and Required Insert Count.
  pub(crate) blocked: VectorUsize<(StreamId, u64)>,
  /// The capacity that the request buffers hold, and the most that they may hold.
  pub(crate) budget: Budget,
  /// Our control stream.
  pub(crate) control: StreamId,
  /// The handle of the connection on the endpoint of its worker.
  pub(crate) handle: ConnHandle,
  /// Bytes of an unknown frame of the control stream of the peer that are still to skip.
  pub(crate) control_skip: u64,
  /// The decoder of the field sections of the peer.
  pub(crate) decoder: QpackDecoder,
  /// Our QPACK decoder stream, which carries what `decoder` writes.
  pub(crate) decoder_stream: StreamId,
  /// The part of an encoder-stream instruction that waits for the rest of it, when it is longer
  /// than what the connection retains.
  pub(crate) encoder_rx: VectorUsize<u8>,
  /// Our QPACK encoder stream, on which nothing follows its type.
  pub(crate) encoder_stream: StreamId,
  /// The stream identifier of the GOAWAY that was sent, once the endpoint shuts down: requests
  /// from it on are refused.
  pub(crate) goaway: Option<u64>,
  /// Requests read, answered later or not answered yet.
  pub(crate) live: u32,
  /// The largest push identifier that the client allows (MAX_PUSH_ID), if it allows any.
  pub(crate) max_push_id: Option<u64>,
  /// Field sections decoded lately.
  pub(crate) memo: DecodeMemo<8>,
  /// The lowest stream identifier of a request that did not arrive.
  pub(crate) next_request: u64,
  /// The control stream of the peer.
  pub(crate) peer_control: Option<StreamId>,
  /// The QPACK decoder stream of the peer.
  pub(crate) peer_decoder: Option<StreamId>,
  /// The QPACK encoder stream of the peer.
  pub(crate) peer_encoder: Option<StreamId>,
  /// The identifier of the last GOAWAY of the peer.
  pub(crate) peer_goaway: Option<u64>,
  /// For each entry of the window of client streams, one plus the index of the entry of `reqs`
  /// of its request, or zero.
  pub(crate) req_of: [u16; REQ_WINDOW],
  /// Requests, and entries that held one and wait for the next.
  pub(crate) reqs: VectorUsize<Req>,
  /// The entries of `reqs` that hold no request.
  pub(crate) reqs_free: VectorUsize<u16>,
  /// What the decoder writes Huffman strings and wrapped entries into.
  pub(crate) scratch: VectorUsize<u8>,
  /// The settings of the peer, once its SETTINGS frame arrived.
  pub(crate) settings: Option<H3Settings>,
}

impl H3Conn {
  /// A box for a connection with `params`.
  pub(crate) fn new(params: &H3Params) -> crate::Result<Box<Self>> {
    let max = usize::try_from(params.max_buffered_body_per_conn).unwrap_or(usize::MAX);
    Ok(Box::new(Self {
      blocked: VectorUsize::new(),
      budget: Budget::new(max),
      control: StreamId(0),
      control_skip: 0,
      handle: ConnHandle { generation: 0, slot: 0 },
      decoder: QpackDecoder::new(params.qpack_max_table_capacity, params.qpack_blocked_streams)?,
      decoder_stream: StreamId(0),
      encoder_rx: VectorUsize::new(),
      encoder_stream: StreamId(0),
      goaway: None,
      live: 0,
      max_push_id: None,
      memo: DecodeMemo::new(),
      next_request: 0,
      peer_control: None,
      peer_decoder: None,
      peer_encoder: None,
      peer_goaway: None,
      req_of: [0; REQ_WINDOW],
      reqs: VectorUsize::new(),
      reqs_free: VectorUsize::new(),
      scratch: VectorUsize::new(),
      settings: None,
    }))
  }

  /// Frees the buffers that entries without a request keep, for a request that needs the room.
  pub(crate) fn reclaim(&mut self) {
    let Self { budget, reqs, .. } = self;
    for req in reqs.iter_mut().filter(|el| el.phase == Phase::Free) {
      req.clear(budget, 0, 0, 0);
    }
  }

  /// The bytes that the box takes, on the heap included.
  pub(crate) fn heap_bytes(&self) -> usize {
    let reqs = self.reqs.capacity().saturating_mul(size_of::<Req>());
    let free = self.reqs_free.capacity().saturating_mul(size_of::<u16>());
    let blocked = self.blocked.capacity().saturating_mul(size_of::<(StreamId, u64)>());
    size_of::<Self>()
      .saturating_add(self.decoder.heap_bytes())
      .saturating_add(self.memo.heap_bytes())
      .saturating_add(reqs)
      .saturating_add(free)
      .saturating_add(blocked)
      .saturating_add(self.budget.held)
      .saturating_add(self.encoder_rx.capacity())
      .saturating_add(self.scratch.capacity())
  }

  /// Makes the box the one of no connection, for the pool: every request forgotten, small buffers
  /// kept, a new decoder table and an empty memo (ruling T13-a, review V5). A box whose release
  /// fails must not be used again.
  pub(crate) fn release(&mut self, params: &H3Params) -> crate::Result<()> {
    self.memo.clear();
    self.decoder.reset(params.qpack_max_table_capacity, params.qpack_blocked_streams)?;
    self.blocked.clear();
    self.control = StreamId(0);
    self.control_skip = 0;
    self.handle = ConnHandle { generation: 0, slot: 0 };
    self.decoder_stream = StreamId(0);
    self.encoder_rx.clear();
    self.encoder_stream = StreamId(0);
    self.goaway = None;
    self.live = 0;
    self.max_push_id = None;
    self.next_request = 0;
    self.peer_control = None;
    self.peer_decoder = None;
    self.peer_encoder = None;
    self.peer_goaway = None;
    self.req_of = [0; REQ_WINDOW];
    self.reqs_free.clear();
    self.scratch.clear();
    self.settings = None;
    let Self { budget, encoder_rx, reqs, reqs_free, scratch, .. } = self;
    for (idx, req) in reqs.iter_mut().enumerate().rev() {
      req.clear(budget, KEEP_HEAD, KEEP_BODY, KEEP_HEAD);
      // Room for every entry is reserved when the entry is made
      let _rslt = reqs_free.push(u16::try_from(idx).unwrap_or(u16::MAX));
    }
    if encoder_rx.capacity() > KEEP_OTHER {
      *encoder_rx = VectorUsize::new();
    }
    if scratch.capacity() > KEEP_OTHER {
      *scratch = VectorUsize::new();
    }
    Ok(())
  }

  /// The entry of the request of stream `id`, if it has one.
  pub(crate) fn req_idx(&self, id: StreamId) -> Option<usize> {
    let pos = window_pos(id);
    let idx = usize::from(self.req_of.get(pos).copied()?.checked_sub(1)?);
    let req = self.reqs.get(idx)?;
    (req.id == id && req.phase != Phase::Free).then_some(idx)
  }

  /// A new entry for the request of stream `id`.
  pub(crate) fn take_req(&mut self, id: StreamId) -> crate::Result<usize> {
    let idx = match self.reqs_free.pop() {
      Some(elem) => usize::from(elem),
      None => {
        let idx = self.reqs.len();
        if idx >= REQ_WINDOW {
          return Err(crate::Error::ProgrammingError);
        }
        // So that giving the entry back never allocates
        self.reqs_free.reserve(idx.wrapping_add(1))?;
        self.reqs.push(Req::new())?;
        idx
      }
    };
    let Some(req) = self.reqs.get_mut(idx) else {
      return Err(crate::Error::ProgrammingError);
    };
    req.id = id;
    req.phase = Phase::Head;
    if let Some(elem) = self.req_of.get_mut(window_pos(id)) {
      *elem = u16::try_from(idx.wrapping_add(1)).unwrap_or(0);
    }
    self.live = self.live.wrapping_add(1);
    Ok(idx)
  }

  /// Gives back the entry `idx`: its request is answered, refused or abandoned. It keeps small
  /// buffers only (review V4).
  pub(crate) fn free_req(&mut self, idx: usize) {
    let Self { blocked, budget, live, req_of, reqs, reqs_free, .. } = self;
    let Some(req) = reqs.get_mut(idx).filter(|el| el.phase != Phase::Free) else {
      return;
    };
    let id = req.id;
    req.clear(budget, KEEP_HEAD, KEEP_BODY, KEEP_HEAD);
    if let Some(elem) = req_of.get_mut(window_pos(id))
      && usize::from(*elem) == idx.wrapping_add(1)
    {
      *elem = 0;
    }
    if let Some(pos) = blocked.iter().position(|el| el.0 == id) {
      let _ = blocked.swap_remove(pos);
    }
    let _rslt = reqs_free.push(u16::try_from(idx).unwrap_or(u16::MAX));
    *live = live.saturating_sub(1);
  }

  /// If the request of stream `id` is parked.
  pub(crate) fn is_parked(&self, id: StreamId) -> bool {
    self.req_idx(id).and_then(|idx| self.reqs.get(idx)).is_some_and(|el| el.phase == Phase::Parked)
  }

  /// Parks the request of entry `idx`: its head and body are forgotten, and their buffers kept only
  /// if small, out of the budget of the connection.
  pub(crate) fn park(&mut self, idx: usize) {
    let Self { budget, reqs, .. } = self;
    if let Some(req) = reqs.get_mut(idx) {
      req.body.clear();
      req.head.clear();
      req.head.trim(budget, KEEP_HEAD);
      budget.trim(&mut req.body, KEEP_BODY);
      budget.trim(&mut req.stash, KEEP_HEAD);
      req.phase = Phase::Parked;
    }
  }

  /// Frees the stash of entry `idx` if it holds no request and the stash is large: for a stash that
  /// was out while its request was given back.
  pub(crate) fn trim_free_stash(&mut self, idx: usize) {
    let Self { budget, reqs, .. } = self;
    if let Some(req) = reqs.get_mut(idx).filter(|el| el.phase == Phase::Free) {
      budget.trim(&mut req.stash, KEEP_HEAD);
    }
  }
}

// The capacity of `buf` in bytes.
fn bytes<T>(buf: &VectorUsize<T>) -> usize {
  buf.capacity().saturating_mul(size_of::<T>())
}

// The entry of stream `id` in the window of client streams.
fn window_pos(id: StreamId) -> usize {
  usize::try_from(id.index() % REQ_WINDOW as u64).unwrap_or(0)
}

// A handler, for the size of a connection of the production build.
struct SizeProbeHandler;

impl crate::http3::H3Handler for SizeProbeHandler {
  fn on_request(
    &mut self,
    _: &mut crate::http3::H3ReqCtx<'_, '_>,
    _: &H3Request<'_>,
  ) -> crate::Result<crate::http3::ReqOutcome> {
    Ok(crate::http3::ReqOutcome::Responded)
  }

  fn resume(
    &mut self,
    _: &mut crate::http3::H3ReqCtx<'_, '_>,
    _: StreamId,
  ) -> crate::Result<crate::http3::ReqOutcome> {
    Ok(crate::http3::ReqOutcome::Responded)
  }
}

#[cfg(test)]
impl H3Conn {
  /// If the box holds no state of a connection: no dynamic table entry, no kept section and no
  /// request (review V5).
  pub(crate) fn is_clear(&self) -> bool {
    self.decoder.insert_count() == 0
      && self.memo.kept() == 0
      && self.live == 0
      && self.blocked.is_empty()
      && self.encoder_rx.is_empty()
      && self.settings.is_none()
      && self.reqs.iter().all(|el| {
        el.phase == Phase::Free
          && el.body.is_empty()
          && el.stash.is_empty()
          && el.head.fields().next().is_none()
          && el.head.method().is_empty()
      })
  }
}
