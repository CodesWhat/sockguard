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

- **Hardware:** Apple M4 Pro, 14 cores, macOS 25.4.
- **Go:** 1.26.2.
- **Run date:** 2026-05-14 (against `feat/v1.0-prep` HEAD; effectively v0.8.1 + the v1.0-prep rename / dep / quality commits).
- **Sockguard:** current branch HEAD at the time of the run (built from
  `app/cmd/sockguard`). Config at
  [`benchmarks/config.yaml`](benchmarks/config.yaml) — allows `GET /_ping` and
  `GET /containers/json`, denies everything else by default-deny rule with
  `response.deny_verbosity: minimal`, access log disabled, health endpoint
  disabled.
- **Wollomatic:** `github.com/wollomatic/socket-proxy` installed via
  `go install`. Config passed via flags in `benchmarks/run.sh`: `-allowGET`
  regex matching `/_ping$|/containers/json$`, no `-allowPOST` (so every POST
  is denied by default, matching sockguard's posture).
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
  one JSON line per scenario.
- **Scenarios:** 3 endpoints × 3 concurrency levels (10, 50, 200) × 20s each,
  with a 2 s warmup against sockguard before the real runs so connection
  pools are primed. Baseline ("no proxy") runs hit the mock directly to
  measure the cost of the proxy hop.

All three processes run on loopback unix sockets on the same host, so the
numbers are overhead-dominated by unix IPC and Go HTTP-server costs, not by
network RTT.

## Results

Full JSON output at
[`benchmarks/results.jsonl`](benchmarks/results.jsonl). Summary below.

### Allow path — `GET /_ping`

| Concurrency | Baseline (direct) | Sockguard | Wollomatic |
|---|---|---|---|
| 10  | 104.2k rps, p50 82µs  | 30.9k rps, p50 262µs  | 19.1k rps, p50 462µs  |
| 50  | 169.1k rps, p50 193µs | 42.3k rps, p50 866µs  | 33.1k rps, p50 1312µs |
| 200 | 221.3k rps, p50 516µs | 56.9k rps, p50 2352µs | 44.7k rps, p50 3807µs |

### Allow path — `GET /containers/json`

| Concurrency | Baseline (direct) | Sockguard | Wollomatic |
|---|---|---|---|
| 10  | 101.3k rps, p50 84µs  | 24.7k rps, p50 356µs  | 18.3k rps, p50 484µs  |
| 50  | 175.4k rps, p50 187µs | 37.9k rps, p50 1085µs | 31.0k rps, p50 1399µs |
| 200 | 217.4k rps, p50 527µs | 47.6k rps, p50 3590µs | 42.4k rps, p50 4076µs |

### Deny path — `POST /exec/x/start`

Both proxies short-circuit without forwarding to upstream. Sockguard returns
`403 Forbidden`, wollomatic returns `405 Method Not Allowed` — different HTTP
semantics, same effect.

| Concurrency | Baseline (direct 204) | Sockguard (403) | Wollomatic (405) |
|---|---|---|---|
| 10  | 104.8k rps, p50 87µs  | 95.3k rps,  p50 89µs  | 81.4k rps,  p50 102µs |
| 50  | 192.2k rps, p50 199µs | 194.3k rps, p50 174µs | 172.7k rps, p50 190µs |
| 200 | 232.2k rps, p50 623µs | 230.0k rps, p50 482µs | 226.7k rps, p50 513µs |

### Errors

Across all 18 proxy runs (3 scenarios × 3 concurrencies × 2 proxies):

- **Sockguard:** 0 non-2xx/403 responses, 0 client-observed errors.
- **Wollomatic:** **1,497 spurious `502 Bad Gateway` responses** at
  `concurrency=200` on the allow-path scenarios (1,031 on `/_ping`, 466 on
  `/containers/json`) — roughly 0.08 % of requests on those scenarios. Plus
  487 client-observed errors on the deny path at `concurrency=200`. Likely
  upstream connection-pool exhaustion under sustained concurrency; the mock
  daemon is healthy and sockguard against the same upstream on the same run
  saw zero such errors. Not a reason to switch proxies, but a useful
  operational data point.

## What the numbers say

1. **Sockguard now leads wollomatic on every scenario.** On allow paths,
   sockguard is meaningfully faster — 22-62 % higher RPS and 12-43 % lower
   p50 latency depending on concurrency, widening at low concurrency where
   per-request overhead dominates. On the deny path, sockguard is 1-17 %
   ahead in RPS with p50 latency consistently equal or lower. The v0.8.x
   hot-path work (method-keyed inspector dispatch, lock-free
   `sockguard_inflight_requests` gauge, `sync.Map` rate-limit buckets,
   lock-free `metrics.Registry` between observe and scrape) shows up
   directly in these numbers — compared with the prior recorded numbers
   the same hardware now runs ~35-50 % more RPS through the sockguard
   allow path.
2. **Both proxies add ~4-5× allow-path overhead over direct upstream.**
   This is the cost of a full Go `httputil.ReverseProxy` chain with rule
   evaluation, access-log meta, and request-body inspection plumbing. It
   is not a bug, and it is not unique to sockguard. If you need
   near-zero overhead you want HAProxy; if you need rules, you want a
   Go-based proxy and sockguard is the fastest one in this class on this
   benchmark today.
3. **Deny is cheaper than allow.** Both proxies short-circuit without
   dialing upstream, so denied requests run at or near direct-upstream
   throughput. This is the expected behavior for a default-deny proxy and
   is reassuring for hardened configs where most traffic is refused.
4. **Sockguard has a cleaner error profile under load.** Zero non-2xx/3xx
   beyond the expected 403 denies, across 20 s × 9 sockguard scenarios.
   Wollomatic's 1,500-ish 502 responses + 487 client errors at
   `concurrency=200` are a reminder that operational stability under
   burst concurrency matters as much as peak RPS.

This is *not* a "sockguard wins everything" story; both proxies pay the
same Go reverse-proxy overhead and both deny paths short-circuit
correctly. But on this run sockguard is the faster of the two same-class
Go proxies on every scenario, with a cleaner error profile under
sustained 200-way concurrency.

## What this does NOT measure

- **Real Docker daemon.** The mock is tiny and deterministic; a real
  `dockerd` has variable-size JSON, SQLite syscalls, and its own scheduling
  overhead.
- **Hijack / exec streams.** Attach and exec use HTTP upgrade into long-lived
  bidirectional TCP streams; the benchmark does not exercise those paths.
- **TLS.** All three proxies here run on plain loopback unix sockets.
  Sockguard's mTLS 1.3 fast path for remote TCP listeners has its own
  microbenchmark under `app/internal/testcert` but is not exercised in this
  harness.
- **Memory growth.** `loadgen` captures goroutine counts before and after
  but does not track RSS or heap size across long runs. A dedicated leak
  soak is a separate exercise.
- **Body-inspection overhead.** `POST /containers/create` with a real body
  is the interesting workload for body inspection; the benchmark here
  hits the fast deny path on `POST /exec/x/start` instead. Body-inspection
  micro-benchmarks live in `app/internal/filter/bench_test.go` and
  `app/internal/ownership/bench_test.go`.

## Reproducing the run

```bash
# 1. Install wollomatic/socket-proxy (optional — the harness skips it if
#    /tmp/socket-proxy is missing, but then the comparison table is empty).
GOBIN=/tmp go install github.com/wollomatic/socket-proxy/cmd/socket-proxy@latest

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

No external dependencies, no Docker daemon required, no containers. The
whole harness is stdlib Go.
