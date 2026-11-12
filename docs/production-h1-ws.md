# Running the HTTP/1.1 and WebSocket servers in production

This guide covers the HTTP/1.1 server framework (`Http1ServerFramework`) and the WebSocket server
framework (`WebSocketServerFramework`) on the io_uring runtime (`UringRuntime`, Linux). Like
[the HTTP/2 guide](production.md), it gives each setting's default, when to change it and what the
change costs. The runtime (`UringParams`) and socket (`TcpParams`) settings are shared with HTTP/2
and are described there once: [`UringParams`](production.md#uringparams-set_local_runtime_cb),
[`TcpParams`](production.md#tcpparams-set_tcp_params). The trade-offs given there (spin,
`defer_accept`, `nodelay`, `direct_files`) were measured on the WebSocket profiles and apply to the
WebSocket server as written; for HTTP/1.1 they have not been measured separately.

## Deployment shapes

| Shape | Change from the defaults |
|---|---|
| A server sharing its host with other work (the default case) | none |
| Dedicated cores | `UringParams::set_spin` 20 µs for WebSocket clients that reconnect often (+4 % to +10 % measured; level on the other WebSocket profiles, not measured on HTTP/1.1) |
| Clients that speak first behind no proxy (HTTP, WebSocket) | `TcpParams::set_tcp_defer_accept` (about +2 % on the reconnecting WebSocket profile) |
| Exposed to untrusted clients | `set_max_connections`; lower the runtime's idle timeout (see [Timeouts](#timeouts)); lower WebSocket `max_payload_len` to the largest message the application needs |
| Uploads larger than 1 MiB | raise `HttpRecvParams::set_max_body_len` |

## HTTP/1.1

### `Http1ServerFramework`

- `set_max_connections` (default: no limit beyond the process's descriptors): connections past the
  cap are closed at once and reported as `TooManyConnections`.
- `set_handshake_timeout` (10 s), TLS servers only: from accept, the TLS handshake and then the head
  of the first request. Past it the connection is closed without an answer, which is not reported
  as an error. A plaintext server is bounded by the runtime's handshake timeout instead (below).
- `set_max_delay` (5 s): the longest delay a response may ask for (`Http1Res::set_delay`), so that
  a handler fed a client's number can't hold a connection. Keep it below the runtime's handshake
  timeout less the time a client takes to send its first request: on a plaintext connection that
  timeout runs until the first response leaves.
- `set_shutdown(signal, drain)`: stop accepting, close connections waiting for a request, let those
  in the middle of one answer within `drain`.
- `set_local_runtimes` (one per available thread), `set_local_runtime_cb`, `set_tcp_params`,
  `set_error_cb`: as for HTTP/2. A peer that goes away is not reported as an error.
- `set_http_recv_params`: only `max_body_len` applies to HTTP/1.1 (below).

### Limits and the answers they give

| Limit | Value | Answer |
|---|---|---|
| Request head (request line and headers) | 16 KiB | 431; 414 when the request line alone is over it |
| Header fields | 64 | 431 |
| Request body (`HttpRecvParams::set_max_body_len`) | 1 MiB (`with_default_params`) | 413; a declared `Content-Length` over it is refused before the body is read |
| Chunked framing (sizes, extensions, trailers) | 16 KiB plus a quarter of the body | 413 |
| Trailer fields | 64, each a valid field | 431 / 400 |
| `Transfer-Encoding` other than `chunked` | | 501 |
| Unknown method (uppercase token) | | 501; any other method token is a 400 |
| HTTP major version other than 1 | | 505; HTTP/1.2 and up are served as 1.1 |
| Malformed request line or headers, `Host` with userinfo, a path or a port over 65535, raw non-ASCII or a `#` in the target, bare-LF line endings | | 400 |
| Body cut short by the client's half-close | | 400 |

Every error answer carries `Connection: close`, and the connection closes once it is sent. The
parser follows RFC 9112 strictly; where the RFC leaves a choice, the tests in
`wtx/src/http1/parser.rs` name the server whose behaviour was followed (nginx, httpd, h2o, Envoy,
llhttp).

### Memory per connection

At worst, with the defaults:

- unparsed input: 256 KiB in the protocol core, and up to 256 KiB more received and not yet fed
  (reading stops there, so TCP slows the peer instead of memory growing);
- the decoded body of the request being read: `max_body_len` (1 MiB), plus its framing budget;
- queued responses: flushed once 256 KiB are queued, so a long pipeline of large responses can't
  pile up; a single response is held whole while it is written;
- bytes the runtime holds for sending, and received bytes nobody read: as for HTTP/2
  (`tx_high_water`, `rx_high_water`).

Between requests a connection holds no buffer of its own: the read buffer, the core's buffers and
the response buffers go back to pools of the runtime's thread (at most 64 entries and 16 MiB per
pool; buffers over 1 MiB are freed rather than kept; once a thread has no connection, 4 entries of
at most 2 MiB in all are kept). After warm-up a request allocates nothing (a test counts it).
Multiply by `set_max_connections` for the server's bound.

### Timeouts

The runtime bounds every connection with three timeouts, `UringParams::set_handshake_timeout`
(10 s), `set_idle_timeout` (300 s) and `set_close_timeout` (10 s):

- **Plaintext, before the first response:** the handshake timeout runs from accept until the server
  sends anything. A client that never completes its first request is closed after 10 s.
- **TLS:** the framework's own handshake timeout (10 s) covers the TLS handshake and the head of the
  first request; the runtime's ends at the ServerHello.
- **Afterwards:** the idle timeout counts from the last bytes received or sent, so a client that
  pauses in the middle of a request is not cut off, and one that stops altogether is closed after
  300 s.

**No 408.** A connection closed by a timeout is closed without an answer; nginx answers 408
(`client_header_timeout`). Both are allowed: RFC 9110 §15.5.9 defines the 408 without requiring
it, and RFC 9112 §9.5 lets a server close an idle connection at any time. A test pins the choice
(`a_stalled_request_head_is_closed_without_a_408`).

**Known limit:** after the first request, a head is bounded by the idle timeout between its bytes,
not by a deadline for the whole head. A client trickling one byte every few minutes can hold a
connection for as long as its head takes to reach 16 KiB. Against untrusted clients, lower the idle
timeout (it also frees idle keep-alive connections sooner) and set `set_max_connections`.

### TLS

`new_tls` pushes the `http/1.1` ALPN and turns kernel TLS off: records are sealed in user space, as
for HTTP/2, where the kernel measured slower.

## WebSocket

### `WebSocketServerFramework`

- `set_handshake_timeout` (10 s): the upgrade request and, with TLS, the TLS handshake. Past it the
  connection is closed and the error callback receives `ExpiredFuture`. The runtime's own handshake
  timeout bounds the same span more cheaply, so a server on `UringRuntime` may set this to `None`.
- `set_max_connections`, `set_shutdown`, `set_local_runtimes`, `set_local_runtime_cb`,
  `set_tcp_params`, `set_tls_config`, `set_error_cb`: as above.
- `set_compression` (none): permessage-deflate (RFC 7692), negotiated per connection. It costs CPU
  on every message; decompression stops at `max_payload_len`, so a small compressed message
  can't expand past it.

### Limits

- **Upgrade request:** 16 KiB and 64 headers; past them, or a malformed or ambiguous upgrade
  (two `Host` or `Sec-WebSocket-Key` headers, a missing `Upgrade` or `Connection` token, a wrong
  key or version), it is answered 400.
- **Message size:** `max_payload_len` (64 MiB, `WebSocket::max_payload_len_mut`) for a whole
  message, fragments included; a larger one is closed with 1009. This is the largest memory a
  connection can hold. Lower it to what the application needs: an echo or chat server rarely
  needs more than a few KiB.
- **Control frames:** at most 125 bytes, never fragmented (1002 otherwise).
- **Protocol errors:** reserved bits or opcodes, an unmasked client frame, a continuation out of
  place, a bad close code are closed with 1002; invalid UTF-8 in text or a close reason with 1007.
  Non-minimal length encodings are accepted: RFC 6455 constrains the sender only.
- **No-masking extension** (`WebSocketAcceptor::set_no_masking`, draft-damjanovic): used only when
  the client asks for it.

### Memory per connection

- the message being reassembled: up to `max_payload_len`;
- the network buffer: frames already read are dropped before the next is read, so a client that
  floods frames (pings it never reads the pongs of, say) holds about one frame's worth. Before
  c74c2cd1 that buffer grew instead: 8 MiB a connection within a second of such a flood;
- a peer that stops reading: writes wait once the runtime holds `tx_high_water` for it, and the
  idle timeout closes it.

### Conformance

The Autobahn fuzzingclient suite (all cases, compression included) last ran on 3 Nov 2026 against
three server modes (drain, uring, uring with direct descriptors): in each, 512 OK, 2 non-strict
(6.4.3 and 6.4.4: invalid UTF-8 in a fragment is found when the message is complete, not at the
first bad byte) and 3 informational (7.1.6, 7.13.1, 7.13.2), no failures. The reports are not in
the repository (`.scripts/autobahn/reports/` is local); the in-repo frame tests
(`wtx/src/web_socket/frame_tests.rs`) cover Autobahn's close, ping, UTF-8 and protocol-error
cases against a real server on every test run.
