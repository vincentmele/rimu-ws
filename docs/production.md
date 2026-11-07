# Running the HTTP/2 server in production

This guide covers the HTTP/2 server framework (`Http2ServerFramework`) on the io_uring runtime
(`UringRuntime`, Linux). For every setting a deployment may change it gives the default, when to
change it, and what the change costs. The defaults are meant to be fast and safe on a shared host;
change one only when your deployment matches the situation described.

## Deployment shapes

| Shape | Change from the defaults |
|---|---|
| A server sharing its host with other work (the default case) | none |
| Dedicated cores: the server's threads have CPUs no other work uses | `UringParams::set_spin` 20 µs for WebSocket servers whose clients reconnect often; HTTP/2 measured level with it |
| Many mostly idle connections (tens of thousands) | lower `set_initial_window_len`, `set_max_conn_buffered_len` and `set_max_send_queue_len` to bound memory per connection; consider `set_direct_files` |
| Clients that speak first behind no proxy (HTTP, WebSocket) | `TcpParams::set_tcp_defer_accept` |

## Memory per connection

What one connection can hold at worst, with the framework's defaults:

- received request bodies not yet taken by handlers: `max_conn_buffered_len` (64 MiB);
- responses queued in the HTTP/2 core: `max_send_queue_len` (64 MiB); bodies sent by reference
  (`StaticFiles`) don't count, their memory is the cache's;
- bytes the runtime holds for sending: about twice `tx_high_water` (32 KiB) plus the largest single
  write;
- received bytes nobody read yet: `rx_high_water` (64 KiB).

Between turns a connection holds neither its output buffer nor, when its stream reads without
waiting (plaintext), its read buffer: both go back to pools of the runtime's thread, so many idle
connections cost little beyond their stream slots and HPACK tables (at 4096 connections under
baseline-h2c load, about 30 KiB each in all).

A peer has to work to reach these: flow control stops it from sending more than the windows allow,
and a peer that stops reading is closed by the idle timeout. Multiply by `set_max_connections` for
the server's bound.

## `Http2ServerFramework`

- `set_max_connections` (default: no limit beyond the process's descriptors): connections past the
  cap are closed at once and reported as `TooManyConnections`. Set it when memory per connection
  times the expected peak would exceed what the host can give.
- `set_handshake_timeout` (10 s): the TLS handshake plus the client's preface and first SETTINGS.
  Lower it behind a load balancer that connects only when it has a request.
- `set_idle_timeout` (300 s): no open stream and nothing received for that long sends GOAWAY
  (`NO_ERROR`) and closes. Lower it to free memory faster with many idle clients.
- `set_shutdown(signal, drain)`: stop accepting, GOAWAY every connection, let open streams finish
  within `drain`. Use it for rolling restarts.
- `set_local_runtimes` (default: one per available thread): one io_uring runtime per thread, each
  with its own listener (`SO_REUSEPORT`).
- `set_error_cb`: receives accept errors, handshake failures and protocol errors that end a
  connection.

## `HttpRecvParams` (`set_http_recv_params`)

The framework starts from `HttpRecvParams::with_optioned_params()`.

- `set_initial_window_len` (4 MiB): the flow-control window each stream starts with, and the
  connection's. Larger windows let a client upload faster on long round trips; each connection may
  then buffer up to `max_conn_buffered_len` of bodies its handlers haven't read.
- `set_max_concurrent_streams_num` (256): streams a client may have open at once. Higher favours
  clients that pipeline many requests; each open stream costs its request buffers.
- `set_max_recv_streams_num` (256): no effect on the HTTP/2 server, which bounds a client's open
  streams with `set_max_concurrent_streams_num` alone; kept so existing configurations build.
- `set_max_frame_len` (16 MiB − 1): the largest frame the server accepts.
- `set_max_headers_len` (64 KiB) and `set_max_hpack_len` (128 KiB each way): the decoded header
  list (larger is answered 431) and the HPACK dynamic tables. A header block split over frames is
  buffered only up to `max_headers_len`; a larger one ends the connection (`ENHANCE_YOUR_CALM`).
  Lower them to bound per-stream and per-connection memory.
- `set_max_continuations` (8): CONTINUATION frames per header block, against continuation floods.
- `set_max_body_len` (64 MiB): the most body bytes a stream may hold for its handler: the whole
  body in auto mode; in manual mode (and WebSocket over HTTP/2) only what `recv_data` has not
  taken yet, so a stream consumed as it arrives may carry more. A declared `content-length` above
  it is answered 413 at once.
- `set_max_conn_buffered_len` (64 MiB): request body bytes a connection's streams may hold, not
  yet taken by their handlers.
- `set_max_send_queue_len` (64 MiB): response bytes the core may hold for a connection before it
  ends it (`ENHANCE_YOUR_CALM`); shared bodies don't count. Manual-mode `send_data` waits once
  256 KiB of a stream wait for window or 256 KiB of the connection's output wait to be written,
  so a streaming handler stays under it.
- `set_max_control_frames_per_window` (1000 per 10 s) and `set_max_resets_per_window` (200 per
  10 s): PING/SETTINGS/empty-frame and RST_STREAM floods end the connection past these. The reset
  budget also counts the resets the peer provokes (a zero WINDOW_UPDATE, an over-window DATA, a bad
  header block).
- `set_enable_connect_protocol` (off): turn it on to serve WebSocket over HTTP/2 (RFC 8441).

## `UringParams` (`set_local_runtime_cb`)

- `set_spin` (0): busy-polls for up to this long before sleeping (HTTP/2 profiles: level in
  throughput, 4% to 7% more user cycles per request). With dedicated cores, 20 µs saves
  the sleep and wake-up between bursts: on the WebSocket echo profile that reconnects constantly it
  measured +4% to +10%, for about 1,000 more user cycles per frame spent spinning; echo and
  pipelined echo were level. On a shared host that spinning is CPU other work needs, and when
  reactors share cores with SMT siblings a long spin (100 µs) measured 3% slower.
- `set_send_submit_bytes` (16 KiB): sends queued in a turn are submitted once they add up to this,
  so the kernel copies them while they are still in the CPU's caches. `0` submits each send, `usize::MAX` only at the end of the turn.
- `set_tx_high_water` (16 KiB): bytes waiting to be sent before a write waits. Raising it lets more
  output wait in the runtime's buffers, which measured slower (the waiting bytes are copied out of
  the cache); lowering it below a TLS record costs more sends.
- `set_rx_high_water` (64 KiB): unread received bytes before the runtime stops receiving.
- `set_recv_buffers` (512 × 4 KiB): the ring receives land in, shared by a runtime's connections.
  Raise it with thousands of busy connections per thread.
- `set_ring_entries` (1024 submission, 4096 completion): the rings' sizes. 4096/16384 measured level
  with the defaults on the WebSocket echo, pipelined echo and reconnecting profiles (512
  connections), and locks more memory per runtime; raise them only if completions overflow.
- `set_direct_files` (0): accept into the ring's descriptor table, which saves the file lookup per
  send and makes closing a queued operation (measured +1% to +2% on WebSocket echo in earlier rounds,
  level in the latest). Accepted connections then can't be passed to other syscalls, and kernel TLS
  can't take them.
- `set_peer_addrs` (on): look up each peer's address at accept (one `getpeername`). Turn it off when
  no handler uses the peer's address: clients that reconnect often then save a syscall each.
- `set_handshake_timeout` (10 s), `set_idle_timeout` (300 s), `set_close_timeout` (10 s): the
  runtime's own bounds on a connection: before anything is sent, with nothing moving either way, and
  after the last handle was dropped with bytes still to send. They also bound a peer that stops
  reading.

## `TcpParams` (`set_tcp_params`)

- `set_tcp_nodelay` (on): no Nagle delay; leave it on for request/response traffic. Turning it off
  measured up to 4% faster on the reconnecting WebSocket profile, where nothing is in flight when an
  echo is written, but Nagle holds a write back while earlier bytes are unacknowledged, which delays
  responses on a connection with several streams at once.
- `set_tcp_defer_accept` (off): hand a connection to `accept` only once its first bytes arrived.
  Saves a wakeup per connection when clients speak first (about +2% on the reconnecting WebSocket
  profile); don't use it for protocols where the server speaks first.
- `set_listen` (4096): the accept backlog.
- `set_reuse_port` (on) and `set_reuse_address` (on): one listener per runtime thread on one port.
- `set_recv_buffer_size` and `set_send_buffer_size` (kernel defaults): fixed socket buffers turn off
  the kernel's autotuning; leave them unset unless measurements say otherwise.

## TLS

- Kernel TLS: `Http2ServerFramework::new` turns it off, and HTTP/2 connections seal their records
  in user space. Measured on both small and 16 KiB records, the kernel cost more: it sends one TCP
  segment per record and copies each record twice.

## Static files

- `StaticFiles::set_cache_bytes` (32 MiB per thread): file contents kept in memory per runtime
  thread. Size it to the files served often. A file larger than this is read whole from disk on
  every request, and each request in flight holds its own copy: keep the files you serve under it.
