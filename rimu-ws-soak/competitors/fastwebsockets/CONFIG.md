# fastwebsockets: production configuration

- **Source:** this directory. fastwebsockets 0.10.0 (crates.io), with its `upgrade` feature over
  hyper 1, as in its `echo_server` example, with `FragmentCollector`.
- **Server:** `0.0.0.0:8080`, path `/`, on a multi-thread tokio runtime.
- **Licence:** Apache-2.0, like the rest of `rimu-ws-soak`.

| Setting | Value | Where it is documented |
|---|---|---|
| Largest message | 1 MiB | `WebSocket::set_max_message_size` (`src/lib.rs`); the default is 64 MiB |
| Upgrade validation | `upgrade::is_upgrade_request` before `upgrade::upgrade`, 400 otherwise | `src/upgrade.rs`. It only checks the `Connection` and `Upgrade` headers; `upgrade` checks the key. |
| Auto pong and auto close | on (the defaults) | `set_auto_pong`, `set_auto_close` |
| Largest frame | **no separate setting** | the message limit applies |
| Write buffer | **none available** | `set_writev_threshold` only chooses between vectored and plain writes; writes are awaited one at a time |
| Handshake timeout | 10 s, hyper's | `hyper::server::conn::http1::Builder::header_read_timeout`, with `hyper_util::rt::TokioTimer`. fastwebsockets has none of its own; its upgrade runs on hyper, so a production user sets hyper's. |
| Idle timeout | **none available** | |

`validate-ws.py` passes all 7 checks.
