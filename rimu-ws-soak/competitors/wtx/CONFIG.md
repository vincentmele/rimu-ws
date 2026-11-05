# wtx (original): production configuration

- **Source:** HttpArena `frameworks/wtx-ws` at HttpArena commit `fdb4aae`: wtx 0.48 (crates.io)
  on tokio, through `WebSocketServerFramework`. `production.patch` is applied on top.
- **Server:** listens on `0.0.0.0:8080`, path `/ws`.
- **Licence:** the patch is the entry's own, under HttpArena's MIT licence.

| Setting | Value | Where it is documented |
|---|---|---|
| Largest message | 1 MiB (`production.patch`) | `WebSocket::max_payload_len_mut` (wtx 0.48.1 `src/web_socket.rs`); the default is 64 MiB |
| Write buffer | **none available** | wtx 0.48's tokio path writes each frame and awaits it |
| Handshake timeout | **none available** | `WebSocketServerFramework` in 0.48 has `set_compression`, `set_error_cb`, `set_local_runtime_cb`, `set_local_runtimes`, `set_tcp_params` and `set_tls_config`, and nothing else; rimu-ws added the timeouts after the fork |
| Idle timeout | **none available** | as above |
| TCP_NODELAY | off | kept as the entry sets it (`TcpParams::tcp_nodelay(false)`) |

`validate-ws.py` passes all 7 checks.
