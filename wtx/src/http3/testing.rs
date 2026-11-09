//! An HTTP/3 client for tests, on the clients of [`crate::quic::testing::Net`]: their
//! [`TestApp`](crate::quic::testing::TestApp) collects what arrives on every stream, and the
//! helpers here write requests and the client's own streams, and read responses and the streams of
//! the server. The server is a [`Net`] whose workers run an [`H3App`] of a [`TestHandler`].

use crate::{
  collections::VectorUsize,
  http3::{
    DecodeOutcome, H3App, H3ConnState, H3FrameTy, H3Handler, H3Params, H3ReqCtx, H3Request,
    H3Settings, QpackDecoder, ReqOutcome, decode_frame_header, encode_frame_header, encode_static,
  },
  quic::{
    ConnState, QuicParams, StreamId, encode_varint,
    testing::{Net, TestApp},
  },
};
use alloc::{vec, vec::Vec};

/// The server of tests: its workers run an [`H3App`] of a [`TestHandler`].
pub(crate) type H3Net = Net<H3App<TestHandler>>;
/// Fields, owned.
pub(crate) type Fields = Vec<(Vec<u8>, Vec<u8>)>;

/// The fields of `GET https://localhost/`.
pub(crate) const GET: [(&[u8], &[u8]); 4] =
  [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"localhost"), (b":path", b"/")];
/// A PRIORITY_UPDATE frame type of RFC 9218, which this implementation does not know.
pub(crate) const PRIORITY_UPDATE: u64 = 0xf0700;

/// A request that reached a [`TestHandler`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct SeenRequest {
  /// `:authority`.
  pub(crate) authority: Vec<u8>,
  /// The body.
  pub(crate) body: Vec<u8>,
  /// The fields that are not pseudo-header fields.
  pub(crate) fields: Fields,
  /// `:method`.
  pub(crate) method: Vec<u8>,
  /// `:path`.
  pub(crate) path: Vec<u8>,
  /// `:scheme`.
  pub(crate) scheme: Vec<u8>,
  /// The stream.
  pub(crate) stream: u64,
}

/// Answers every request with `200`, `content-type: text/plain` and [`Self::body`], except those
/// whose path starts with `/park`, which it parks; a parked request is answered with `resumed`.
#[derive(Clone, Debug, Default)]
pub(crate) struct TestHandler {
  /// The response body.
  pub(crate) body: &'static [u8],
  /// Requests answered or parked.
  pub(crate) count: u64,
  /// Requests parked, by stream.
  pub(crate) parked: Vec<StreamId>,
  /// If requests are kept in [`Self::seen`], which allocates.
  pub(crate) record: bool,
  /// Requests resumed.
  pub(crate) resumed: u64,
  /// The requests, if [`Self::record`].
  pub(crate) seen: Vec<SeenRequest>,
}

impl TestHandler {
  /// Answers with `body` and records the requests.
  pub(crate) fn new(body: &'static [u8]) -> Self {
    Self { body, record: true, ..Self::default() }
  }
}

impl H3Handler for TestHandler {
  fn on_request(
    &mut self,
    cx: &mut H3ReqCtx<'_, '_>,
    req: &H3Request<'_>,
  ) -> crate::Result<ReqOutcome> {
    self.count = self.count.wrapping_add(1);
    if self.record {
      self.seen.push(SeenRequest {
        authority: req.authority.to_vec(),
        body: req.body.to_vec(),
        fields: req.fields.iter().map(|(name, value)| (name.to_vec(), value.to_vec())).collect(),
        method: req.method.to_vec(),
        path: req.path.to_vec(),
        scheme: req.scheme.to_vec(),
        stream: req.stream.0,
      });
    }
    if req.path.starts_with(b"/park") {
      self.parked.push(req.stream);
      return Ok(ReqOutcome::Parked);
    }
    cx.respond_fields(&[(b":status", b"200"), (b"content-type", b"text/plain")], self.body)?;
    Ok(ReqOutcome::Responded)
  }

  fn resume(&mut self, cx: &mut H3ReqCtx<'_, '_>, _stream: StreamId) -> crate::Result<ReqOutcome> {
    self.resumed = self.resumed.wrapping_add(1);
    cx.respond_fields(&[(b":status", b"200")], b"resumed")?;
    Ok(ReqOutcome::Responded)
  }
}

/// A response as the client got it.
#[derive(Clone, Debug, Default)]
pub(crate) struct Response {
  /// The payloads of the DATA frames.
  pub(crate) body: Vec<u8>,
  /// The length and the FIN of every delivery of the stream to the client: one per STREAM frame.
  pub(crate) calls: Vec<(usize, bool)>,
  /// The fields of the HEADERS frame, `:status` included.
  pub(crate) fields: Fields,
  /// If the FIN arrived.
  pub(crate) fin: bool,
  /// The types of the frames, in order.
  pub(crate) frames: Vec<u64>,
}

impl Response {
  /// The value of field `name`.
  pub(crate) fn field(&self, name: &[u8]) -> Option<&[u8]> {
    self.fields.iter().find(|el| el.0 == name).map(|el| el.1.as_slice())
  }
}

/// A server of one worker whose connections have `params` and whose requests `handler` answers.
pub(crate) fn h3_net(quic: QuicParams, params: H3Params, handler: &TestHandler) -> H3Net {
  Net::with_apps(1, quic, |_| H3App::new(handler.clone(), params))
}

/// [`h3_net`] with a client whose handshake is done. Returns the net and the client.
pub(crate) fn connected(params: H3Params, handler: &TestHandler) -> (H3Net, usize) {
  let mut net = h3_net(QuicParams::default(), params, handler);
  let client = net.add_client();
  net.run();
  assert_eq!(net.clients[client].conn.state(), ConnState::Confirmed);
  (net, client)
}

/// A frame of type `ty`.
pub(crate) fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
  let mut header = [0u8; 16];
  let len = encode_frame_header(H3FrameTy::Unknown(ty), payload.len() as u64, &mut header).unwrap();
  let mut rslt = header[..len].to_vec();
  rslt.extend_from_slice(payload);
  rslt
}

/// A HEADERS frame of `fields`, encoded with the static table.
pub(crate) fn headers_frame(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
  let mut section = VectorUsize::new();
  encode_static(fields, &mut section).unwrap();
  frame(0x01, &section)
}

/// A DATA frame of `body`.
pub(crate) fn data_frame(body: &[u8]) -> Vec<u8> {
  frame(0x00, body)
}

/// A variable-length integer.
pub(crate) fn varint(value: u64) -> Vec<u8> {
  let mut buffer = [0u8; 8];
  let len = encode_varint(value, &mut buffer).unwrap();
  buffer[..len].to_vec()
}

/// The control stream of a client: its type and a SETTINGS frame of `settings`.
pub(crate) fn control_stream(settings: H3Settings) -> Vec<u8> {
  let mut out = vec![0u8; 64];
  let len = settings.encode(&mut out[1..]).unwrap();
  out.truncate(len + 1);
  out
}

/// The settings of a client that uses no dynamic table.
pub(crate) const fn client_settings() -> H3Settings {
  H3Settings { qpack_max_table_capacity: 0, qpack_blocked_streams: 0, max_field_section_size: None }
}

/// Opens a request stream of client `client` and writes `bytes` on it, with `fin`.
pub(crate) fn send(net: &mut H3Net, client: usize, bytes: &[u8], fin: bool) -> StreamId {
  let now_us = net.now_us;
  net_ctx(net, client, now_us, |cx| {
    let id = cx.open_bidi()?;
    cx.write(id, bytes, fin)?;
    Ok(id)
  })
  .unwrap()
}

/// Opens a unidirectional stream of client `client` and writes `bytes` on it, without the FIN.
pub(crate) fn open_uni(net: &mut H3Net, client: usize, bytes: &[u8]) -> StreamId {
  let now_us = net.now_us;
  net_ctx(net, client, now_us, |cx| {
    let id = cx.open_uni()?;
    cx.write(id, bytes, false)?;
    Ok(id)
  })
  .unwrap()
}

/// Writes `bytes` on stream `id` of client `client`, with `fin`.
pub(crate) fn write(net: &mut H3Net, client: usize, id: StreamId, bytes: &[u8], fin: bool) {
  let now_us = net.now_us;
  net_ctx(net, client, now_us, |cx| cx.write(id, bytes, fin)).unwrap();
}

/// Resets stream `id` of client `client` with `code`.
pub(crate) fn reset(net: &mut H3Net, client: usize, id: StreamId, code: u64) {
  let now_us = net.now_us;
  net_ctx(net, client, now_us, |cx| {
    cx.reset(id, code);
    Ok(())
  })
  .unwrap();
}

/// Asks the server to stop sending on stream `id` of client `client`, with `code`.
pub(crate) fn stop_sending(net: &mut H3Net, client: usize, id: StreamId, code: u64) {
  let now_us = net.now_us;
  net_ctx(net, client, now_us, |cx| {
    cx.stop_sending(id, code);
    Ok(())
  })
  .unwrap();
}

/// The response of stream `id` as client `client` got it, if anything arrived.
pub(crate) fn response(net: &H3Net, client: usize, id: StreamId) -> Option<Response> {
  response_of(&net.clients[client].app, id)
}

/// The response of stream `id` as the application `app` of a client got it, if anything arrived.
pub(crate) fn response_of(app: &TestApp, id: StreamId) -> Option<Response> {
  let log = app.streams.get(&id.0)?;
  let mut rslt = Response { calls: log.calls.clone(), fin: log.fin, ..Response::default() };
  let mut decoder = QpackDecoder::new(0, 0).unwrap();
  let mut scratch = VectorUsize::new();
  let mut rest = log.data.as_slice();
  while let Some((ty, len, header_len)) = decode_frame_header(rest).unwrap() {
    let len = usize::try_from(len).unwrap();
    let payload = &rest[header_len..header_len + len];
    rslt.frames.push(ty.code());
    match ty {
      H3FrameTy::Headers => {
        let mut fields = Vec::new();
        let outcome = decoder
          .decode(id.0, payload, &mut scratch, &mut |name, value| {
            fields.push((name.to_vec(), value.to_vec()));
            Ok(())
          })
          .unwrap();
        assert_eq!(outcome, DecodeOutcome::Done { referenced_dynamic: false });
        rslt.fields = fields;
      }
      H3FrameTy::Data => rslt.body.extend_from_slice(payload),
      _ => {}
    }
    rest = &rest[header_len + len..];
  }
  assert!(rest.is_empty(), "a frame of the response is cut");
  Some(rslt)
}

/// The unidirectional streams of the server as client `client` got them, by stream: their type
/// and the bytes that follow it.
pub(crate) fn server_streams(net: &H3Net, client: usize) -> Vec<(u64, Vec<u8>)> {
  net.clients[client]
    .app
    .streams
    .iter()
    .filter(|(id, _)| *id & 0b11 == 0b11)
    .map(|(_, log)| {
      let (ty, len) = crate::quic::decode_varint(&log.data).unwrap();
      (ty, log.data[len..].to_vec())
    })
    .collect()
}

/// The frames of the control stream of the server, as client `client` got them: type and payload.
pub(crate) fn server_control_frames(net: &H3Net, client: usize) -> Vec<(u64, Vec<u8>)> {
  let streams = server_streams(net, client);
  let control = &streams.iter().find(|el| el.0 == 0).unwrap().1;
  let mut rslt = Vec::new();
  let mut rest = control.as_slice();
  while let Some((ty, len, header_len)) = decode_frame_header(rest).unwrap() {
    let len = usize::try_from(len).unwrap();
    rslt.push((ty.code(), rest[header_len..header_len + len].to_vec()));
    rest = &rest[header_len + len..];
  }
  rslt
}

/// The CONNECTION_CLOSE that the server owes client `client`, while it is closing: (application,
/// code).
pub(crate) fn server_close(net: &H3Net, client: usize) -> Option<(bool, u64)> {
  let cid = net.clients[client].conn.peer_cid().as_slice().to_vec();
  net.servers[0].endpoint.conn(&cid)?.close_code()
}

/// Runs `f` with the HTTP/3 state of the connection of the server with client `client`.
pub(crate) fn server_state<R>(net: &H3Net, client: usize, f: impl FnOnce(&H3ConnState) -> R) -> R {
  let cid = net.clients[client].conn.peer_cid().as_slice().to_vec();
  f(net.servers[0].endpoint.conn(&cid).unwrap().app_state())
}

/// Resumes the parked request of stream `id` of client `client` on the server.
pub(crate) fn resume(net: &mut H3Net, client: usize, id: StreamId) {
  let cid = net.clients[client].conn.peer_cid().as_slice().to_vec();
  let now_us = net.now_us;
  let server = &mut net.servers[0];
  server
    .endpoint
    .with_cid(now_us, &cid, &mut server.app, |app, cx| app.resume(cx, id))
    .unwrap()
    .unwrap();
}

/// The RESET_STREAM frames that client `client` got: stream and code.
pub(crate) fn resets(net: &H3Net, client: usize) -> Vec<(u64, u64)> {
  net.clients[client].app.resets.iter().map(|(id, code)| (id.0, *code)).collect()
}

/// The STOP_SENDING frames that client `client` got: stream and code.
pub(crate) fn stops(net: &H3Net, client: usize) -> Vec<(u64, u64)> {
  net.clients[client].app.stops.iter().map(|(id, code)| (id.0, *code)).collect()
}

// Runs `f` with the context of the connection of client `client`.
fn net_ctx<R>(
  net: &mut H3Net,
  client: usize,
  now_us: u64,
  f: impl FnOnce(&mut crate::quic::ConnCtx<'_, ()>) -> crate::Result<R>,
) -> crate::Result<R> {
  net.client_ctx(client, now_us, f)
}
