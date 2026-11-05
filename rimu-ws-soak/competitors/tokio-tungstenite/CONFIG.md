# tokio-tungstenite: production configuration

- **Source:** this directory. tokio-tungstenite 0.30.0 and tungstenite 0.30.0, through
  `accept_async_with_config`.
- **Server:** an echo loop that reads until the stream ends, which is the documented pattern;
  tungstenite answers pings and close frames itself. `0.0.0.0:8080`, path `/`, on a multi-thread
  tokio runtime.
- **Licence:** Apache-2.0, like the rest of `rimu-ws-soak`.

| Setting | Value | Where it is documented |
|---|---|---|
| Largest message | 1 MiB | `WebSocketConfig::max_message_size` (tungstenite `src/protocol/mod.rs`); the default is 64 MiB |
| Largest frame | 1 MiB | `WebSocketConfig::max_frame_size`; the default is 16 MiB |
| Write buffer | `write_buffer_size` 128 KiB (the default); `max_write_buffer_size` 1.375 MiB | `WebSocketConfig::max_write_buffer_size`, unlimited by default. Its doc says it "should always be at least `write_buffer_size + 1 message`", so the common 256 KiB is added to 128 KiB + 1 MiB. |
| Handshake timeout | **none available** | Nothing in `accept_async_with_config` or `WebSocketConfig`. |
| Idle timeout | **none available** | Nothing in `WebSocketConfig`. |
| Upgrade validation | the library's own | `tungstenite::handshake::server` |

**Known before the soak:** HttpArena's `validate-ws.py` fails one check, "reject non-upgrade GET".
tungstenite closes the connection without an HTTP response instead of answering 400. Echo,
ping/pong, close and the bad-upgrade check pass.
