# Sockguard Benchmarks

This document exists for two purposes:

1. **Regression check.** A baseline we can re-run before every release to catch
   latency or throughput regressions in the Go reverse-proxy core.
2. **Same-class sanity check.** A head-to-head against
   [`wollomatic/socket-proxy`](https://github.com/wollomatic/socket-proxy), the
   closest peer — another Go-based Docker socket proxy with a similar
   architecture. If sockguard were meaningfully slower than wollomatic on
   identical scenarios, that would be a signal the rule engine or middleware
   chain has a bug.

It is **not** a marketing artifact. We intentionally do not compare against
`tecnativa/docker-socket-proxy` or the LinuxServer build: both are HAProxy
underneath. HAProxy is a 20-year-old C event loop that will beat any Go
reverse proxy on raw RPS and tail latency, and that comparison doesn't tell
you anything useful about a security-focused proxy. Sockguard's value is in
what it filters (request body inspection, per-owner isolation, per-client
ACLs, structured access logs) not in how many requests per second it can push
through a fast path.

## Setup

- **Hardware:** Apple M4 Pro, 14 cores, macOS 26.5.
- **Go:** 1.26.3.
- **Run date:** 2026-05-25.
- **Sockguard:** app code at `8aed5dd` plus the benchmark-harness updates in
  this changeset, built from `app/cmd/sockguard`. Config at
  [`benchmarks/config.yaml`](benchmarks/config.yaml) — allows `GET /_ping` and
  `GET /containers/json`, denies everything else by default-deny rule with
  `response.deny_verbosity: minimal`, access log disabled, health endpoint
  disabled.
- **Wollomatic:** `github.com/wollomatic/socket-proxy` installed via
  `go install` at
  `v0.0.0-20260518091831-61fc4e8da2d1`. Config passed via flags in
  `benchmarks/run.sh`: `-allowGET` regex matching
  `/_ping$|/containers/json$`, no `-allowPOST` (so every POST is denied by
  default, matching sockguard's posture).
- **Upstream:** a tiny Go mock Docker daemon
  ([`benchmarks/cmd/mockdocker`](benchmarks/cmd/mockdocker/main.go)) listening
  on a loopback unix socket, serving three endpoints:
  - `GET /_ping` → 200, body `"OK"` (tiny)
  - `GET /containers/json` → 200, JSON array of 5 fake containers (~2 KiB)
  - `POST /exec/{id}/start` → 204 (the deny target — sockguard and wollomatic
    should never forward this to us)
- **Load generator:** a Go program
  ([`benchmarks/cmd/loadgen`](benchmarks/cmd/loadgen/main.go)) that pins a
  persistent `http.Client` per worker to the unix socket under test. Measures
  p50/p90/p99/max latency, RPS, error counts, and goroutine growth. Emits
  one JSON line per scenario. The run timer stops launching new requests but
  lets already-started requests finish, so benchmark-window shutdown is not
  counted as a client-observed error.
- **Scenarios:** 3 endpoints × 3 concurrency levels (10, 50, 200) × 20s each,
  with a 2 s warmup against sockguard before the real runs so connection
  pools are primed. Baseline ("no proxy") runs hit the mock directly to
  measure the cost of the proxy hop.

All three processes run on loopback unix sockets on the same host, so the
numbers are overhead-dominated by unix IPC and Go HTTP-server costs, not by
network RTT.

## Results

The harness writes full JSON output to `benchmarks/results.jsonl`, which is
ignored by git. Summary below.

### Allow path — `GET /_ping`

| Concurrency | Baseline (direct) | Sockguard | Wollomatic |
|---|---|---|---|
| 10  | 110.8k rps, p50 79µs  | 33.9k rps, p50 249µs  | 25.7k rps, p50 356µs  |
| 50  | 216.1k rps, p50 157µs | 52.5k rps, p50 696µs  | 36.9k rps, p50 1173µs |
| 200 | 251.3k rps, p50 428µs | 65.8k rps, p50 1995µs | 57.5k rps, p50 2885µs |

### Allow path — `GET /containers/json`

| Concurrency | Baseline (direct) | Sockguard | Wollomatic |
|---|---|---|---|
| 10  | 109.1k rps, p50 80µs  | 26.8k rps, p50 343µs  | 25.5k rps, p50 358µs  |
| 50  | 219.2k rps, p50 156µs | 41.6k rps, p50 1001µs | 36.8k rps, p50 1174µs |
| 200 | 247.4k rps, p50 437µs | 54.3k rps, p50 3036µs | 58.1k rps, p50 2867µs |

### Deny path — `POST /exec/x/start`

Both proxies short-circuit without forwarding to upstream. Sockguard returns
`403 Forbidden`, wollomatic returns `405 Method Not Allowed` — different HTTP
semantics, same effect.

| Concurrency | Baseline (direct 204) | Sockguard (403) | Wollomatic (405) |
|---|---|---|---|
| 10  | 112.6k rps, p50 82µs  | 104.0k rps, p50 83µs  | 110.4k rps, p50 79µs  |
| 50  | 226.1k rps, p50 175µs | 216.4k rps, p50 160µs | 213.4k rps, p50 159µs |
| 200 | 259.8k rps, p50 543µs | 247.0k rps, p50 421µs | 247.7k rps, p50 427µs |

### Errors

Across all 18 proxy runs (3 scenarios × 3 concurrencies × 2 proxies):

- **Sockguard:** 0 non-2xx/403 responses, 0 client-observed errors.
- **Wollomatic:** 314 spurious `502 Bad Gateway` responses at
  `concurrency=200` on the allow-path scenarios (28 on `/_ping`, 286 on
  `/containers/json`) plus 46 client-observed dial errors on `/_ping`
  (`connect: connection refused`). That is a small fraction of the sustained
  200-way run, but it is still a useful operational signal: the same mock
  daemon and the same load generator saw zero Sockguard errors.

## What the numbers say

1. **Sockguard leads most allow-path scenarios, with a tighter race at
   concurrency 200.** On `GET /_ping`, Sockguard is 14-42 % ahead of
   Wollomatic in RPS and has lower p50 latency at every concurrency. On
   `GET /containers/json`, Sockguard is ahead at concurrency 10 and 50;
   Wollomatic edges ahead by about 7 % at concurrency 200 on this run.
2. **Deny-path performance is effectively tied.** Wollomatic is ahead at
   concurrency 10, Sockguard is narrowly ahead at concurrency 50, and the
   200-way run is a wash. Both proxies short-circuit denied requests without
   forwarding to upstream, which is the behavior that matters for a hardened
   default-deny config.
3. **Both proxies add ~4-5× allow-path overhead over direct upstream.**
   This is the cost of a full Go `httputil.ReverseProxy` chain with rule
   evaluation, access-log meta, and request-body inspection plumbing. It
   is not a bug, and it is not unique to sockguard. If you need
   near-zero overhead you want HAProxy; if you need rules, you want a
   Go-based proxy.
4. **Sockguard has a cleaner error profile under load.** Zero non-2xx/3xx
   beyond the expected 403 denies, across 20 s × 9 sockguard scenarios.
   Wollomatic's 314 `502` responses plus 46 client-side dial failures at
   `concurrency=200` are a reminder that operational stability under burst
   concurrency matters as much as peak RPS.

This is *not* a "sockguard wins everything" story; both proxies pay the
same Go reverse-proxy overhead and both deny paths short-circuit correctly.
On this run Sockguard is the cleaner and usually faster same-class Go proxy,
while Wollomatic wins one high-concurrency allow-path row.

## What this does NOT measure

- **Real Docker daemon.** The mock is tiny and deterministic; a real
  `dockerd` has variable-size JSON, SQLite syscalls, and its own scheduling
  overhead.
- **Hijack / exec streams.** Attach and exec use HTTP upgrade into long-lived
  bidirectional TCP streams; the benchmark does not exercise those paths.
- **TLS.** All three proxies here run on plain loopback unix sockets.
  Sockguard's mTLS 1.3 fast path for remote TCP listeners is not exercised
  in this harness.
- **Memory growth.** `loadgen` captures goroutine counts before and after
  but does not track RSS or heap size across long runs. A dedicated leak
  soak is a separate exercise.
- **Body-inspection overhead.** `POST /containers/create` with a real body
  is the interesting workload for body inspection; the benchmark here
  hits the fast deny path on `POST /exec/x/start` instead. Body-inspection
  micro-benchmarks live in `app/internal/filter/bench_test.go`.

## Reproducing the run

```bash
# 1. Install wollomatic/socket-proxy (optional — the harness skips it if
#    /tmp/socket-proxy is missing, but then the comparison table is empty).
GOBIN=/tmp go install \
  github.com/wollomatic/socket-proxy/cmd/socket-proxy@v0.0.0-20260518091831-61fc4e8da2d1

# 2. Run the benchmark. Default duration is 20 s per scenario; pass an
#    override as the first argument (Go time.Duration syntax) for a faster
#    sanity check.
./benchmarks/run.sh          # 20 s per scenario (~6 min total)
./benchmarks/run.sh 5s       # 5 s per scenario (~90 s total)
```

The harness builds sockguard, mockdocker, and loadgen from this checkout,
starts mockdocker, starts sockguard pointed at mockdocker, starts wollomatic
pointed at mockdocker, runs every scenario against each, and writes one JSON
line per run to `benchmarks/results.jsonl`. Build artifacts live under a
temporary directory that is cleaned up on exit; log files for each process
are captured in `benchmarks/sockguard.log`, `benchmarks/wollomatic.log`, and
`benchmarks/mockdocker.log` for debugging.

No Docker daemon required, no containers. The Sockguard/mockdocker/loadgen
harness is stdlib Go; the Wollomatic binary is optional and pinned above for
the comparison run.
