# minima-ws: production configuration

- **Source:** HttpArena `frameworks/minima-ws` at HttpArena commit `fdb4aae`, run as written (no
  patch). Licence: the entry's own, under HttpArena's MIT licence.
- **What it is:** a hand-rolled WebSocket echo on the Minima engine, a from-scratch C# io_uring
  server (.NET 10), with its own RFC 6455 handshake and frame parser. It listens on 8080, path `/ws`.

**No WebSocket settings available.** `ServerConfig.cs` holds engine tunables only (rings, buffers,
reactors). The only limit is a hard-coded 16 MiB `MaxFrame` (`Program.cs`), larger than the common
1 MiB. There is no message limit, write buffer, or handshake or idle timeout.

**Known before the soak** (smoke, 5 Nov): it echoes, and answers a client's close, but never closes
TCP afterwards (RFC 6455 5.5.1: MUST). Every echo-style run waits out the harness's 2 s close
deadline, so a 10 s smoke with 20 clients made only 61 runs, all failed ("still open"). HttpArena's
`validate-ws.py` passes, because it never checks for the TCP close.
