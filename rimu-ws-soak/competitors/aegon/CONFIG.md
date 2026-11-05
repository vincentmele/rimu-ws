# aegon: production configuration

- **Source:** HttpArena `frameworks/aegon` at HttpArena commit `fdb4aae`, with `production.patch`
  on top. It builds Aegon at commit `2ba8fd9` (https://github.com/UdayKhare09/Aegon), a C++26
  framework on io_uring, and serves its built-in WebSocket echo (`router.ws("/ws")`) on
  `0.0.0.0:8080`. It also opens its other HttpArena listeners: 8082, plus TLS 8081 and 8443 when
  certificates exist.
- **Licence:** the patch is the entry's own, under HttpArena's MIT licence.

| Setting | Value | Where it is documented |
|---|---|---|
| Largest message | 1 MiB (`production.patch`) | `Server::ws_max_message_size` (`src/http/Server.h`); `WebSocketConfig::max_message_size` defaults to 16 MiB and closes with 1009 (`src/http/ServerConfig.h`) |
| Largest frame | 1 MiB (`production.patch`) | `Server::ws_max_frame_size`; the default is 16 MiB |
| Masking required | on (the default) | `WebSocketConfig::require_masked_frames` |
| Request header limits | 64 KiB, 100 headers, 8 KiB URI (the defaults) | `ProtocolLimits` |
| Write buffer | **none available** | `WebSocketConfig` has only `initial_buffer_capacity` |
| Handshake timeout | **none available** | nothing in `ServerConfig`; `TcpConfig` has only TCP keepalive |
| Idle timeout | **none available** | as above; `auto_ping_interval_sec` and `ping_timeout_sec` only apply when the server pings, which is off by default |
