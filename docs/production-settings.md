# Production settings

The settings rimu-ws recommends for a WebSocket server on the public internet, in front of clients
it doesn't control. They are what `rimu-ws-soak` holds rimu-ws, and every server it is compared
with, to (`rimu-ws-soak/RULES.md`). Where the library's default differs, set the value yourself.

| Setting | Recommended | How to set it | Library default |
|---|---|---|---|
| Largest message (and frame) | 1 MiB | `*ws.max_payload_len_mut() = 1 << 20` in the connection handler | **64 MiB** (`MAX_PAYLOAD_LEN`) |
| Write buffer: queued bytes before writes wait | 256 KiB | `UringParams::set_tx_high_water(256 * 1024)` | 256 KiB |
| Handshake timeout | 10 s | `UringParams::set_handshake_timeout(Some(10 s))` on io_uring; `WebSocketServerFramework::set_handshake_timeout` elsewhere | 10 s |
| Idle timeout | 300 s | `UringParams::set_idle_timeout(Some(300 s))` | 300 s on io_uring; **none** on the tokio path |

- **The handshake timer:** on io_uring, the runtime bounds handshakes more cheaply than the
  framework's per-connection timer. A server there can call
  `WebSocketServerFramework::set_handshake_timeout(None)`.
- **An example:** `rimu-ws-soak/competitors/rimu-ws/src/main.rs` is a complete echo server with
  these settings.
