# ringzero-ws: production configuration

- **Source:** HttpArena `frameworks/ringzero-ws` at HttpArena commit `fdb4aae`, run as written (no
  patch). Licence: the entry's own, under HttpArena's MIT licence.
- **What it is:** a hand-rolled WebSocket echo loop in C on raw io_uring (liburing), with no
  WebSocket library. It has one ring per core, multishot accept and recv into a provided buffer
  ring, and its own RFC 6455 handshake and frame parser. It listens on `0.0.0.0:8080`, path `/ws`.

**No settings available.** Its tunables are compile-time constants about rings and buffers. The
only limit is a hard-coded 16 MiB `MAX_FRAME` (`main.c`), larger than the common 1 MiB. There is no
message limit, write buffer, or handshake or idle timeout.

**Known before the soak** (smoke, 5 Nov):

- **It never closes TCP after a closing handshake.** It echoes the client's close and then leaves
  the connection open. RFC 6455 5.5.1 says it MUST close it, so every echo-style scenario fails.
- **It crashes under ordinary load.** With 20 clients of the `baseline` profile it aborted within
  seconds: glibc printed "double free or corruption (top)" and the exit code was 139.
- It starts 64 reactors regardless of the container's 12 CPUs.

HttpArena's `validate-ws.py` passes, because it never checks for the TCP close.
