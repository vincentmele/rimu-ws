# viltrum: production configuration

- **Source:** HttpArena `frameworks/viltrum` at HttpArena commit `fdb4aae`, with `production.patch`
  on top. It builds viltrum `v1.15.1` (https://github.com/Tuntii/viltrum) with V 0.5.2: one
  `SO_REUSEPORT` epoll worker per CPU, `app.ws("/ws")`, on `0.0.0.0:8080`.
- **Licence:** the patch is the entry's own, under HttpArena's MIT licence.

| Setting | Value | Where it is documented |
|---|---|---|
| Largest message | 1 MiB (`production.patch`; also the default) | `WsHandler.max_message`, "caps a message, fragments included; larger ones close with 1009" (`viltrum.v`) |
| Idle timeout | 300 s (`production.patch`) | `WsHandler.idle_timeout`; the default is 120 s |
| Handshake timeout | 10 s (`production.patch`) | `Options.read_timeout`, "from a request's first byte to its last" (`engine/options.v`); the default is 30 s |
| Write buffer | 256 KiB (`production.patch`) | `Options.max_pending`; the default is 1 MiB. A WebSocket whose unread output passes 4× it is closed with 1008 (`engine/ws.v`). |
