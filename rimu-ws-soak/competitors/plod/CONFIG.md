# plod: production configuration

- **Source:** HttpArena `frameworks/plod` at HttpArena commit `fdb4aae`, with `production.patch` on
  top. It uses Plod `v0.5.9` on goose-http `v0.5.12` (https://github.com/kaitk/goose-http), Goose
  `v2026.3`, an io_uring loop per worker, and the single-container `Dockerfile`. It serves
  `plod::ws_upgrade` and `plod::ws_read` on `0.0.0.0:8080`, path `/ws`.
- **Licence:** the patch is the entry's own, under HttpArena's MIT licence.

| Setting | Value | Where it is documented |
|---|---|---|
| Largest message | 1 MiB (`production.patch`) | `http::WebSocket.limit`, "the longest message taken ... a longer one closes the connection with 1009" (`websocket.goose`); the default is 64 KiB |
| Handshake timeout | 10 s (the default) | `Config.request_ms`, "a request head has request_ms from its first byte to arrive whole" (`http.goose`) |
| Idle timeout | 300 s (`production.patch`) | `Config.idle_ms`; the default is 60 s. It applies to WebSockets too (`docs/api.md`). |
| Stalled reader | 10 s (the default) | `Config.write_ms`, "a response write_ms to move on once the client stops taking it" |
| Write buffer | 8 KiB flush threshold (the default) | `Config.write_buffer`. It is when to send, not a cap. |
| Gather budget | the default | a WebSocket holding part of a message is promised `limit` + 131 bytes of the worker's budget; past it, close 1013 (`docs/api.md`, WebSocket) |
