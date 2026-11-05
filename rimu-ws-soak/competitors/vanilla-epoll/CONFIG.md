# vanilla-epoll: production configuration

- **Source:** HttpArena `frameworks/vanilla-epoll` at HttpArena commit `fdb4aae`, run as written (no
  patch). Licence: the entry's own, under HttpArena's MIT licence.
- **Server:** vanilla (https://github.com/enghitalo/vanilla), a V HTTP server on epoll. The WebSocket
  echo is the entry's own handler (`ws_echo_conn` in `main.v`), built on vanilla's frame codec
  (`vanilla.websocket`) and its connection takeover (`core.queue_takeover`). It listens on
  `0.0.0.0:8080`, path `/ws`.

**No WebSocket settings available.** `vanilla.websocket` is a frame codec with no limits or timeouts,
and the handler is the entry's own code. It refuses some frames with close 1003 (unsupported)
rather than reassembling them (`main.v`, around line 1340).

**Known before the soak** (smoke, 5 Nov):

- It panics at start without `/data/static`. HttpArena mounts `data/static` and `data/dataset.json`
  into every entry, and `competitor.sh` now does the same for every competitor.
- It binds 8081 for TLS as well; another HttpArena benchmark holding 8081 on the host network stops
  it from starting.
- With those in place, its RSS was 3.1 GB before any load. That passed the 2 GiB ceiling and slowed
  it inside the 3 GiB container cap, so `validate-ws.py` timed out. It is built with `-gc none`. The
  cause of the 3 GB is not yet confirmed, and it will be re-checked on a quiet box.
