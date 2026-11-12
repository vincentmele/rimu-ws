# HTTP/1.1 and WebSocket conformance fixes: validator and h1 A/B on colossus — 12 Nov 2026 (12:19–12:28 UTC)

A regression check of the conformance fixes on the `fix/conformance-gaps` branch: new tests, ported from llhttp,
h2o, Envoy, lighttpd, httpd, gorilla and Autobahn, and the parser, chunked-body, connection-core and WebSocket changes
that make them pass (summary below). The question was whether the extra checks on every request (one SIMD scan of the
request line, the `Host` check) cost anything measurable.

## Machine and method
colossus (AMD Ryzen 9 5900X, 12 cores / 24 threads, kernel 7.0.0-38). Servers on CPUs 0-5,12-17, gcannon on 6-10,18-22
(core 11/23 left to colossus's live services), no sysctl or service changes.

- Builds: the HttpArena `rimu-ws-h1` entry (its `Cargo.toml`, `Cargo.lock` and the checkout's `arena-h1` server), made
  twice alike (release, `--locked`, `-C target-cpu=native`, as the entry's Dockerfile): A = `main` ef0f7abb, B = the
  same tree with the fixes. The server source is identical in both; only the rimu-ws sources differ. Run natively (no
  container), TLS listener off (no `/certs`).
- Load (`data/ab.sh`): HttpArena's gcannon shapes — baseline (`get.raw,post_cl.raw,post_chunked.raw`, 4,096
  connections, `-p 1`), limited-conn (the same with `-r 10`) and json-comp (`json-gzip-{25,40,50}.raw`, 4,096
  connections, `-r 25`); `-t 10 -d 5s`. 4 passes, the order A,B then B,A alternating; per pass and build, 3 runs per
  profile and the best kept; server cpu from `/proc/<pid>/stat` over each run. Medians over the passes
  (`data/summary.py`).
- Quiet machine: each pass waited until no process outside the run used more than half a CPU. Another session's
  archiver held about 3 CPUs until 12:19; all four passes then started clean (the logged load of 13–14 is the run's
  own server and generator).
- json-tls and 8gbit were not run: HttpArena drives them with wrk, which is not installed here.

## Validator
HttpArena's `scripts/validate.sh rimu-ws-h1` on an image built from the fixed tree (scratch HttpArena clone, entry
filled by its `local-src.sh`): **55 passed, 0 failed; fragmentation checks 9 passed, 0 failed; nothing skipped**
(`data/validate.log`).

## A/B

| profile | A (`main`) req/s | B (fixes) req/s | B vs A | pass spread A / B | cpu µs/req A → B | verdict |
|---|---|---|---|---|---|---|
| baseline | 804,950 | 803,640 | −0.16 % | 1.1 / 0.3 % | 14.53 → 14.60 (+0.45 %) | ok |
| limited-conn | 493,315 | 491,975 | −0.27 % | 1.6 / 0.7 % | 19.23 → 19.16 (−0.37 %) | ok |
| json-comp | 257,330 | 258,210 | +0.34 % | 0.2 / 0.5 % | 46.96 → 46.83 (−0.28 %) | ok |

Paired per pass, B vs A in req/s: baseline −0.8 / −0.2 / −0.0 / −0.1 %, limited-conn +0.9 / −0.1 / −0.5 / −0.0 %,
json-comp +0.6 / +0.1 / +0.7 / +0.0 %. Every change is inside A's own pass-to-pass spread, and 0 non-2xx responses in
every run. **No measurable cost.**

## What the fixes change
- Request line: an unknown uppercase method is a 501 (other tokens stay 400); HTTP/1.x with a minor version above 1 is
  served as 1.1 and another major version is a 505; a request line over 16 KiB is a 414 (an oversized head with lines is
  still a 431); an authority-shaped target outside CONNECT, a `#`, raw non-ASCII bytes and bare-LF line endings are 400.
- `Host`: userinfo, extra colons, a path or a port above 65535 is a 400; an empty value stays allowed.
- Chunked trailers: names must be tokens and values free of control characters, and more than 64 fields is a 431.
- `Expect: 100-continue`: an interim 100 while the body is still to come (none when it came with the head).
- A body cut short by the client's half-close is answered 400 (a head cut short is still closed silently).
- WebSocket: a duplicated `Host` in the upgrade request is refused; a client closes (1002) on a masked server frame.
  Non-minimal length encodings stay accepted, by choice (RFC 6455 binds the sender only).

## Data
`data/summary.txt` (the table above), `data/ab.log` (every run), `data/raw/` (gcannon outputs with server cpu ticks,
server logs), `data/ab.sh` (the run; its paths are the session's scratch directories), `data/summary.py`,
`data/validate.log`.
