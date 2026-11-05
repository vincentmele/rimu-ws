# zix: production configuration

- **Source:** HttpArena `frameworks/zix-ws` at HttpArena commit `fdb4aae`, run as written (no
  patch). Licence: the entry's own, under HttpArena's MIT licence.
- **Which entry:** the leaderboard's zix echo-ws results come from `zix-ws`, under the display name
  zix. `frameworks/zix` serves no WebSocket.
- **Server:** the zix.Http1 engine, branch `0.5.x` (fetched at build, so not pinned to a commit).
  `.URING` dispatch, the engine's own echo loop (`zix.Http1.WebSocket`), listening on `[::]:8080`,
  path `/ws`.

| Setting | Value | Where it is documented |
|---|---|---|
| WebSocket receive buffer | 32 KiB (as the entry sets it) | `ws_recv_buf` (`src/tcp/http1/config.zig`): "under .URING the frame-accumulation buffer". It is a buffer size, not a message limit. |
| Largest message | **none available** | no WebSocket message or frame limit in `zix.Http1` |
| Write buffer | 16 KiB send buffer (as the entry sets it) | `uring_send_buf_size`: "a larger response grows the buffer up to an internal ceiling" |
| Handshake timeout | **none available** under `.URING` | `conn_timeout_ms` is "No-op under .EPOLL and .URING"; `body_read_timeout_ms` covers request bodies only |
| Idle timeout | **none available** under `.URING` | as above |
| Upgrade validation | the entry's | `src/handlers/ws.zig` checks only `Upgrade: websocket` and the key's presence |

**Notes on its results (the rules are not widened for it; the user's decision, 5 Nov):**

- **Close reply without a code.** zix answers a client's close 1000 with a close frame that carries
  no status code. RFC 6455 5.5.1 says an endpoint "typically echos" the code, which is not a
  requirement. The soak expects 1000 back, so these runs count as MUST failures ("close code None,
  expected 1000").
- **Resets on messages over 32 KiB.** A message larger than `ws_recv_buf` (32 KiB) gets a TCP reset
  with no close frame. The design's "limit below the common size" mark covers a refusal with 1009;
  the soak only marks 1009. So these resets count as failures ("server closed during echo"), not
  marks.
