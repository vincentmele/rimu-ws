# HTTP/1.1 and WebSocket conformance fixes: validator and h1 A/B on colossus — 12 Nov 2026 (12:19–14:32 UTC)

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
- json-tls, 8gbit and latency-10k followed later that day, once wrk and zrk were installed:
  [TLS and paced profiles](#tls-and-paced-profiles-14131432-utc).

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

## TLS and paced profiles (14:13–14:32 UTC)

The profiles the first run could not drive, measured the same way (same machine, CPU split, alternating
order, 4 passes) with HttpArena's other generators: wrk 4.1.0 and zrk 3.0.0. The builds this time:
A = ef0f7abb (before the conformance work, as above), B = `main` 37e36643, which adds to the fixes
above the WebSocket network-buffer fix (c74c2cd1), the empty-method 400 and a production guide. Both
run natively with HttpArena's certificate pair (`CERT_DIR`), TLS on 8081.

**Open loop, wrk** (`data/ab-tls.sh`; 5 s runs, best of 3 per start, medians over the passes,
`data/summary_tls.py`):

| profile | A req/s | B req/s | B vs A | pass spread A / B | cpu µs/req A → B |
|---|---|---|---|---|---|
| json-tls (`json-tls-rotate.lua`, 4,096 connections) | 269,356 | 269,623 | +0.10 % | 0.7 / 1.7 % | 28.55 → 28.45 (−0.34 %) |
| 8gbit, open loop (`8gbit-rotate.lua`: 10 KB bodies, 512 connections) | 132,206 | 130,416 | −1.35 % | 4.8 / 4.6 % | 89.43 → 91.05 (+1.81 %) |

json-tls is level. The open-loop 8gbit is inconclusive: paired per pass B was +3.3 % to −4.6 % against
A, inside each build's own ~4.7 % spread (the 11 Nov colossus runs found the same noise on this
profile). HttpArena itself no longer drives 8gbit this way; the paced run below is its shape.

**Paced, zrk** (`data/ab-zrk.sh`): 8gbit as HttpArena runs it (`POST /echo` over TLS, one 10 KiB
body, 512 connections, 50,000 req/s, 5 s, 3 runs per start) and latency-10k (`GET /baseline11`, 1,024
connections, 10,000 req/s, 20 s, 1 run per start). Both reached their rate (rate ratio 0.990 and 0.998
for both builds), so they are judged by server cpu per request and latency. Medians over every run of
passes 1–3 (`data/summary_zrk_allruns.py`):

| profile | metric | A | B | B vs A |
|---|---|---|---|---|
| 8gbit | cpu µs/req | 36.59 | 36.58 | −0.0 % |
| | mean latency | 120.8 µs | 119.3 µs | −1.2 % |
| | p99 | 149 µs | 159 µs | +6.7 % |
| latency-10k | cpu µs/req | 21.63 | 21.64 | +0.0 % |
| | mean latency | 70.1 µs | 66.4 µs | −5.3 % |
| | p99 | 77 µs | 77 µs | 0 % |

8gbit's p99 differs by 10 µs where each build's runs range from 135 to 201 µs; p99.9 is in the
milliseconds for both builds and too noisy to tell them apart. **Pass 4 is left out:** it started
after an 8½-minute wait for other sessions' builds, and both builds had outlier runs in it (a 5 ms
and a 2.9 ms p99); with it, 8gbit's mean reads +4.4 %, carried by those runs (all four passes:
`data/summary-zrk-allruns.txt`; one run per start, the least cpu of three: `data/summary-zrk.txt`).
0 non-2xx responses in every run of both generators. **No measurable cost** on the TLS or paced
profiles either.

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
- First run (gcannon): `data/summary.txt` (the table above), `data/ab.log` (every run), `data/raw/` (gcannon outputs
  with server cpu ticks, server logs), `data/ab.sh` (the run; its paths are the session's scratch directories),
  `data/summary.py`, `data/validate.log`.
- TLS and paced runs: `data/ab-tls.sh`, `data/ab-tls.log`, `data/summary_tls.py`, `data/summary-tls.txt`,
  `data/raw-tls/` (wrk outputs, server logs); `data/ab-zrk.sh`, `data/ab-zrk.log`, `data/summary_zrk.py`,
  `data/summary_zrk_allruns.py`, `data/summary-zrk.txt`, `data/summary-zrk-allruns.txt`, `data/raw-zrk/` (zrk JSON
  summaries, server logs).
