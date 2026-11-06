# HTTP/2 breaking changes (feat/http2-driver)

The HTTP/2 module was rewritten around a connection core with no I/O (`http2::conn`), driven by an
io_uring connection task on the server. These public items changed.

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
  - Dropping an unfinished stream resets it with `CANCEL`.
  - Body bytes that arrived with the request headers are read with `recv_data`, not found in
    `ManualStream::req`.
- **`Http2::<_, _, false>::accept` and `Http2::stream` (the raw server API): removed.** The
  server is the framework. A raw server example (`wtx-examples/examples/http2-server.rs`) is out
  of date until Task 10.
- **`WebSocketOverStream<S>` now needs `S: LeaseMut<ServerStream>`.** It parses WebSocket frames
  from a byte stream rather than one frame per DATA frame.
- **Router behaviour:** an unknown path is answered with 404. The old server closed the
  connection with GOAWAY.
- **Responses always carry `date` and `content-length`.**
- **`FnFutWrapper`'s marker is `PhantomData<fn() -> A>`.**
  - **Why:** a router with manual endpoints (`ManualStream<_, ServerStream>`) stays `Send + Sync`.

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
