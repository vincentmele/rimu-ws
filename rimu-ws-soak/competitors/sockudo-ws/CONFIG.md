# sockudo-ws: production configuration

- **Source:** this directory. sockudo-ws 3.1.0 at commit `35933d7`
  (https://github.com/sockudo/sockudo-ws), through `WebSocketServer::accept` over HTTP/1.1.
- **Server:** an echo loop; the stream answers pings and close frames itself. `0.0.0.0:8080`, path
  `/`, on a multi-thread tokio runtime.
- **Licence:** Apache-2.0, like the rest of `rimu-ws-soak`.

| Setting | Value | Where it is documented |
|---|---|---|
| Largest message | 1 MiB | `Config::max_message_size` (`src/lib.rs`); the default is 64 MiB |
| Largest frame | 1 MiB | `Config::max_frame_size`; the default is 16 MiB |
| Write buffer | 256 KiB | `Config::max_backpressure`, "queued-write backpressure threshold"; the default is 1 MiB. Its doc says it "is not an outbound message size limit or a peak memory bound". |
| Idle timeout | 300 s | `Config::idle_timeout`; the default is 120 s |
| Handshake timeout | **none available** | Neither `WebSocketServer::accept` nor `Config` has one. The request header is capped at 8 KiB (`MAX_HEADER_SIZE` in `src/handshake.rs`). |
| Other defaults kept | `auto_ping` (30 s), `pong_timeout` 10 s, `close_timeout` 5 s, `write_coalescing` | `Config` |

**Known before the soak:** HttpArena's `validate-ws.py` fails one check, "reject non-upgrade GET".
The connection is closed without an HTTP response.
