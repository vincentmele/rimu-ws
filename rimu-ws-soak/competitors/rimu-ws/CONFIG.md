# rimu-ws: production configuration

- **Source:** this directory. An echo server on rimu-ws from this repository, built with
  `crypto-ring`, `io-uring`, `optimizations-std` and `web-socket-server-framework`.
- **Licence:** Apache-2.0, like the rest of `rimu-ws-soak`.
- **Server:**
  - `WebSocketServerFramework` on `UringExecutor` (io_uring), one runtime per thread.
  - The plain echo loop from `wtx-examples/examples/web-socket-server-framework.rs`.
  - Listens on `0.0.0.0:8080`, path `/`.

| Setting | Value | Where it is documented |
|---|---|---|
| Largest message | 1 MiB | `WebSocket::max_payload_len_mut` (`wtx/src/web_socket.rs`); the default is `MAX_PAYLOAD_LEN`, 64 MiB (`wtx/src/lib.rs`) |
| Write buffer | 256 KiB | `UringParams::set_tx_high_water` (`wtx/src/executor/uring_executor.rs`) |
| Handshake timeout | 10 s | `UringParams::set_handshake_timeout`. The framework's own timer is off, as `WebSocketServerFramework::set_handshake_timeout` advises on io_uring. |
| Idle timeout | 300 s | `UringParams::set_idle_timeout` |
| Connection limit | not set | `WebSocketServerFramework::set_max_connections` exists. The comparison sets no connection limit on any server, because tier 1 doesn't judge one. |
| Upgrade validation | always on | the RFC 6455 4.2.1 checks in `wtx/src/web_socket/handshake.rs` |

Nothing was looked for and not found: every common setting exists.
