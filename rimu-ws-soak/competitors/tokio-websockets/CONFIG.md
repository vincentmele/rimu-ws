# tokio-websockets: production configuration

- **Source:** HttpArena `frameworks/tokio-websockets` at HttpArena commit `fdb4aae`, with
  `production.patch` on top. It uses tokio-websockets 0.13 through `ServerBuilder::accept`, with one
  `current_thread` runtime per core and `SO_REUSEPORT`, listening on `0.0.0.0:8080`, path `/ws`.
- **Licence:** the patch is the entry's own, under HttpArena's MIT licence.

| Setting | Value | Where it is documented |
|---|---|---|
| Largest message | 1 MiB (`production.patch`) | `Limits::max_payload_len` (0.13.3 `src/proto/types.rs`); the default is 64 MiB. The entry had `Limits::unlimited()`. |
| Outgoing frame size | 4 MiB (the default) | `Config::frame_size` splits outgoing messages. The entry had `usize::MAX`; the patch restores the default. |
| Flush threshold | 8 KiB (the default) | `Config::flush_threshold`. It is when to flush, not a cap on queued bytes. |
| Write buffer limit | **none available** | |
| Handshake timeout | **none available** | |
| Idle timeout | **none available** | |

**The echo loop.** The entry calls `send(..).await.unwrap()` in a build with `panic = "abort"`, so
one failed send (a client reset) would abort the whole server. The library's own
`examples/echo_server.rs` also unwraps, but in a spawned task under the default `panic = "unwind"`,
where a failed send ends only that connection. The patch returns from the connection on a failed
send, which is the example's effect.
