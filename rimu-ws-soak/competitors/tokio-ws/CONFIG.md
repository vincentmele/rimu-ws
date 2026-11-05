# tokio-ws: production configuration

- **Source:** HttpArena `frameworks/tokio-ws` at HttpArena commit `fdb4aae`, run as written (no
  patch). Licence: the entry's own, under HttpArena's MIT licence.
- **What it is:** a hand-rolled WebSocket echo loop on raw tokio, with no WebSocket library. It does
  its own RFC 6455 handshake, frame parser and masking, with one `current_thread` runtime per core
  and `SO_REUSEPORT`. It listens on `0.0.0.0:8080`, path `/ws`.

**No settings available.** It has no configuration of any kind. The only limit is a hard-coded
16 MiB `MAX_FRAME` on a frame's declared length (`src/main.rs`), larger than the common 1 MiB.
There is no message limit, write buffer, or handshake or idle timeout.
