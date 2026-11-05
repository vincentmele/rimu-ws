# uWebZockets: production configuration

- **Source:** HttpArena `frameworks/uwebzockets` at HttpArena commit `fdb4aae`, with
  `production.patch` on top. It builds uWebZockets 1.8.0 (commit `d94b4e5`,
  https://github.com/farbenbuilds/uWebZockets), a Zig framework on libxev, and serves
  `app.ws("/ws")` on `0.0.0.0:8080`, in a cluster of one worker per CPU (8 workers for this
  container's 12 CPUs, by the entry's own steps).
- **Licence:** the patch is the entry's own, under HttpArena's MIT licence.

| Setting | Value | Where it is documented |
|---|---|---|
| Largest message | 1 MiB (`production.patch`) | `WsBehavior.max_message_size`, "maximum decoded payload accepted across a fragmented message" (`src/router/radix.zig`); the default is 16 KiB |
| Largest frame | 1 MiB (`production.patch`) | `WsBehavior.max_frame_size`; the default is 16 KiB |
| Per-connection message slab | 1 MiB (`production.patch`) | `ServerConfig.max_ws_message_size` (`src/router/config.zig`); `valid_ws_limits` requires it to be at least `max_message_size` |
| Write buffer | 256 KiB (`production.patch`) | `ServerConfig.write_queue_size`, "bounded pending-output bytes per connection"; the entry had 16 KiB |
| Idle timeout | 300 s (`production.patch`) | `ServerConfig.idle_timeout_ms`; the default is 120 s |
| Connections per worker | **192** (`production.patch`) | `ServerConfig.max_connections`. The startup slab holds a whole message and write queue per connection, so the entry's 2,560 a worker at 1 MiB would reserve about 26 GiB. 192 a worker (1,536 in all) keeps the slabs within the container's 3 GiB cap. Connections past it are refused, which the tier 1 descriptor flood will show. |
| Handshake timeout | **none separate** | the idle timeout covers a connection that stops sending |

The entry also starts h2c, TLS and HTTP/3 listeners on other ports. They are not tested here.
