//! What the HTTP/3 layer keeps for a connection (ruling T13-a).
//!
//! Inline, in the connection, only [`H3ConnState`]: a box taken from the pool of the worker's
//! [`H3App`](crate::http3::H3App) once the connection is established and given back once it is
//! closed. The box, [`H3Conn`], holds the stream identifiers of both sides, the settings of the
//! peer, the QPACK decoder and its memo, the state of the requests being read (indexed by stream
//! index modulo the window of client streams, which two open streams never share) and the GOAWAY
//! that was sent. A box that comes back is reset before it is used again: a new epoch for the
//! decoder table, so that the memo of the previous connection replays nothing, and the memo
//! cleared, so that its decoded bytes do not stay.

use crate::{
  collections::VectorUsize,
  http3::{
    DecodeMemo, H3Params, H3Settings, QpackDecoder,
    request::{H3Request, RequestHead},
  },
  quic::{QuicConn, StreamId},
};
use alloc::boxed::Box;

/// Requests read at once at most: the window of client-initiated bidirectional streams.
const REQ_WINDOW: usize = 256;
/// Buffers of a request or of the encoder stream that grew past this are freed when their
/// connection is pooled.
const KEEP_CAPACITY: usize = 64 * 1024;

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
  pub(crate) fn request<'any>(
    &'any self,
    fields: &'any [(&'any [u8], &'any [u8])],
  ) -> H3Request<'any> {
    H3Request {
      method: self.head.method(),
      scheme: self.head.scheme(),
      authority: self.head.authority(),
      path: self.head.path(),
      fields,
      body: self.body.as_slice(),
      stream: self.id,
    }
  }

  // Forgets the request; the storage stays, unless it grew large.
  fn clear(&mut self, forget_large: bool) {
    self.body.clear();
    self.blocked = false;
    self.fin = false;
    self.frame = FrameLeft::None;
    self.head.clear();
    self.phase = Phase::Free;
    self.stash.clear();
    if forget_large {
      self.head.forget_large();
      if self.body.capacity() > KEEP_CAPACITY {
        self.body = VectorUsize::new();
      }
      if self.stash.capacity() > KEEP_CAPACITY {
        self.stash = VectorUsize::new();
      }
    }
  }
}

/// The state of an established connection, in a box of the pool: see the
/// [module documentation](self).
#[derive(Debug)]
pub(crate) struct H3Conn {
  /// Field sections that wait for QPACK inserts: their stream and Required Insert Count.
  pub(crate) blocked: VectorUsize<(StreamId, u64)>,
  /// Our control stream.
  pub(crate) control: StreamId,
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
  /// The lowest stream identifier of a request that did not arrive: what a GOAWAY carries.
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
    Ok(Box::new(Self {
      blocked: VectorUsize::new(),
      control: StreamId(0),
      control_skip: 0,
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

  /// Makes a pooled box the one of a new connection with `params`. A box whose reset fails must
  /// not be used again.
  pub(crate) fn reset(&mut self, params: &H3Params) -> crate::Result<()> {
    self.decoder.reset(params.qpack_max_table_capacity, params.qpack_blocked_streams)?;
    self.memo.clear();
    self.release();
    self.control = StreamId(0);
    self.decoder_stream = StreamId(0);
    self.encoder_stream = StreamId(0);
    self.goaway = None;
    self.max_push_id = None;
    self.next_request = 0;
    self.peer_control = None;
    self.peer_decoder = None;
    self.peer_encoder = None;
    self.peer_goaway = None;
    self.settings = None;
    Ok(())
  }

  /// Forgets every request, for a box that goes back to the pool; storage that grew large is
  /// freed.
  pub(crate) fn release(&mut self) {
    self.blocked.clear();
    self.control_skip = 0;
    self.encoder_rx.clear();
    if self.encoder_rx.capacity() > KEEP_CAPACITY {
      self.encoder_rx = VectorUsize::new();
    }
    self.reqs_free.clear();
    for (idx, req) in self.reqs.iter_mut().enumerate().rev() {
      req.clear(true);
      // Room for every entry is reserved when the entry is made
      let _rslt = self.reqs_free.push(u16::try_from(idx).unwrap_or(u16::MAX));
    }
    self.req_of = [0; REQ_WINDOW];
    self.live = 0;
    self.scratch.clear();
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

  /// Gives back the entry `idx`: its request is answered, refused or abandoned.
  pub(crate) fn free_req(&mut self, idx: usize) {
    let Some(req) = self.reqs.get_mut(idx).filter(|el| el.phase != Phase::Free) else {
      return;
    };
    let id = req.id;
    req.clear(false);
    if let Some(elem) = self.req_of.get_mut(window_pos(id))
      && usize::from(*elem) == idx.wrapping_add(1)
    {
      *elem = 0;
    }
    if let Some(pos) = self.blocked.iter().position(|el| el.0 == id) {
      let _ = self.blocked.swap_remove(pos);
    }
    let _rslt = self.reqs_free.push(u16::try_from(idx).unwrap_or(u16::MAX));
    self.live = self.live.saturating_sub(1);
  }
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
