# HTTP/2 breaking changes (feat/http2-driver)

The HTTP/2 module was rewritten around a connection core with no I/O (`http2::conn`), driven by an
io_uring connection task on the server and by a generic async connection task on the client. These
public items changed.

## Server

- **`Http2ServerFramework` runs only on `UringExecutor`.**
  - `run_in_threads` and `run_local` exist only for `UringExecutor`. `run_local` takes the
    thread's `Arc<UringRuntime>`.
  - **Why:** the driver reads with `try_read` and polls parked handlers between reads, which
    needs a runtime that reports readiness without blocking a read. On tokio, a handler that
    waits would stall until the peer's next bytes.
- **`Http2ServerFramework::tokio()`: removed.** Same reason.
- **`Http2ServerFramework::run` (the multi-task, `Send` version): removed.** Use `run_in_threads`
  (one runtime per thread, `SO_REUSEPORT`) or `run_local`.
- **`ServerStream` is now `ServerStream` (no `<SW, TCX>` parameters).**
  - **Why:** it is a same-thread handle into the connection core, not to the socket.
  - Its methods are on the type itself: `recv_data(&mut buffer)`, `send_headers`, `send_data`,
    `send_trailers`, `send_reset`, `send_go_away`, `method`, `protocol` and `stream_id`. The
    `common()` indirection and `CommonStream` on the server side are gone.
  - Dropping an unfinished stream answers `500` if no response was started (a manual handler that
    returned an error, as auto mode does), and otherwise resets it with `CANCEL`.
  - Body bytes that arrived with the request headers are read with `recv_data`, not found in
    `ManualStream::req`.
- **`Http2::<_, _, false>::accept` and its `stream` (the raw server API): removed.** The server
  is the framework; `wtx-examples/examples/http2-server.rs` now shows a manual-mode endpoint.
- **Examples that ran the server on tokio now run on io_uring:** `http2-server-framework` and
  `http2-server-framework-session` open their Postgres pool with `UringExecutor` and serve with
  `run_local` on one thread, since a pooled connection belongs to the runtime that opened it.
- **A client's GOAWAY no longer closes the server's side.** The server keeps answering (PING
  acknowledgements) until the client closes. Closing first, with the client's frames unread,
  made the close a TCP reset that could lose them.
- **`WebSocketOverStream<S>` now needs `S: LeaseMut<ServerStream>`.** It parses WebSocket frames
  from a byte stream rather than one frame per DATA frame.
- **Router behaviour:** an unknown path is answered with 404. The old server closed the
  connection with GOAWAY.
- **Responses always carry `date` and `content-length`.**
- **`FnFutWrapper`'s marker is `PhantomData<fn() -> A>`.**
  - **Why:** a router with manual endpoints (`ManualStream<_, ServerStream>`) stays `Send + Sync`.

## Client

- **`Http2::connect` keeps its signature; the future it returns is now the connection task:** it
  writes the preface and SETTINGS, reads, and wakes the streams. Spawn it, as before. Writes are
  made by whoever queued them (a stream handle, or the task after a read), through an async lock
  on the writing half.
- **`Http2::stream` waits** for the server's first SETTINGS, and while the server's limit on
  concurrent streams is reached. Before, it failed with `ExceedAmountOfActiveConcurrentStreams`.
  A stream counts against the limit until both sides ended, as on the server.
- **`ClientStream` frees its stream on drop**, resetting it with `CANCEL` if it has not ended.
  `recv_res` frees it once the response is complete. `CommonStream::clear` does the same, with no
  50 ms linger.
- **`ClientStream::recv_res` returns `ClosedStream(status)` with the status received before the
  reset, or `500` when none was.** Before, it was `200`.
- **`CommonStream` (client side) lost `send_headers`, `reserve_capacity` and `windows`.**
  - **Why:** a client's HEADERS is the request, sent by `send_req`; flow control is the
    connection's (`send_data` waits for window, `release_capacity` is no longer needed).
  - `release_capacity` is kept and does nothing: the window is handed back as body bytes are
    buffered, up to `HttpRecvParams::max_body_len`.
  - `recv_data` hands `cb` the bytes buffered so far each time more arrive.
- **`enc_buffer` parameters (`send_req`, `send_trailers`) are unused:** the connection encodes
  into its own buffer.
- **`Http2Buffer` holds only a seed and a read buffer.**
- **`Http2Data`, `Window` and `Windows`: removed** with the old driver.
- **`HttpRecvParams::{linger, set_linger}`: removed.** There is no linger after a stream ends.

## Protocol behaviour

- **`Protocol::from_canonical_bytes` accepts `websocket` in any case.** RFC 8441 registers the
  lowercase form, and the old code refused it.
- **Header lists above `max_headers_len`:** answered with 431. Before, it was GOAWAY
  `FRAME_SIZE_ERROR`.

## Parameters

- **New `HttpRecvParams` limits:**
  - `max_conn_buffered_len`
  - `max_continuations`
  - `max_control_frames_per_window`
  - `max_resets_per_window`
  - `max_send_queue_len`
- **New `Http2Error` variants:**
  - `TooManyContinuations`
  - `TooManyControlFrames`
  - `TooManyResets`
  - `SendQueueFull`
