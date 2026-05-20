#!/usr/bin/env bash
#
# soak.sh — long-running RSS + goroutine-noise soak for sockguard.
#
# Closes the "BENCHMARKS.md explicitly defers RSS/leak tracking as a
# separate exercise" gap that QA-3 owns. Builds mockdocker + sockguard
# + loadgen from this checkout, starts mockdocker and sockguard on
# unix sockets, hammers sockguard at a configurable concurrency for a
# configurable duration, and samples the sockguard process's RSS and
# thread count every minute. After the run, computes RSS delta versus
# the post-warmup baseline and fails the run if growth exceeds the
# configured threshold — the leak signal the v1.0 exit criteria call
# out.
#
# Usage:
#   scripts/soak.sh [--duration <go-duration>] [--concurrency <int>]
#                   [--rss-growth-threshold-bytes <int>] [--dry-run]
#
# Defaults:
#   --duration                       1h        (override per environment;
#                                               github-hosted job ceiling is 6h)
#   --concurrency                    20        (steady-state, not stress)
#   --rss-growth-threshold-bytes     67108864  (= 64 MiB)
#
# --dry-run prints the resolved invocation plan and exits 0 without
# building or starting anything — the test seam scripts/soak.test.mjs
# uses to assert the option surface stays stable.

set -euo pipefail

DURATION="1h"
CONCURRENCY=20
# 64 MiB. Sockguard's working-set under steady-state load is well under
# this; a real leak shows up as monotonic growth far past it.
RSS_GROWTH_THRESHOLD_BYTES=67108864
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --duration)
      [ $# -ge 2 ] || { echo "soak.sh: --duration needs a value" >&2; exit 2; }
      DURATION="$2"; shift 2 ;;
    --concurrency)
      [ $# -ge 2 ] || { echo "soak.sh: --concurrency needs a value" >&2; exit 2; }
      CONCURRENCY="$2"; shift 2 ;;
    --rss-growth-threshold-bytes)
      [ $# -ge 2 ] || { echo "soak.sh: --rss-growth-threshold-bytes needs a value" >&2; exit 2; }
      RSS_GROWTH_THRESHOLD_BYTES="$2"; shift 2 ;;
    --dry-run)
      DRY_RUN=1; shift ;;
    -h|--help)
      sed -n '1,30p' "$0"; exit 0 ;;
    *)
      echo "soak.sh: unknown flag $1" >&2; exit 2 ;;
  esac
done

# Validate flags before doing anything expensive — the test relies on
# this firing in dry-run too.
case "${DURATION}" in
  *[0-9]s|*[0-9]m|*[0-9]h) ;;
  *) echo "soak.sh: --duration must end in s/m/h (got: ${DURATION})" >&2; exit 2 ;;
esac
case "${CONCURRENCY}" in
  ''|*[!0-9]*) echo "soak.sh: --concurrency must be a positive integer" >&2; exit 2 ;;
  0) echo "soak.sh: --concurrency must be > 0" >&2; exit 2 ;;
esac
case "${RSS_GROWTH_THRESHOLD_BYTES}" in
  ''|*[!0-9]*) echo "soak.sh: --rss-growth-threshold-bytes must be a non-negative integer" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"
MOCK_SOCK="/tmp/sg-soak-mock.sock"
PROXY_SOCK="/tmp/sg-soak-proxy.sock"
SAMPLE_INTERVAL_SECONDS=60

if [ "${DRY_RUN}" -eq 1 ]; then
  cat <<EOF
soak.sh dry-run plan:
  duration:                ${DURATION}
  concurrency:             ${CONCURRENCY}
  rss-growth-threshold:    ${RSS_GROWTH_THRESHOLD_BYTES} bytes
  sample interval:         ${SAMPLE_INTERVAL_SECONDS}s
  mock socket:             ${MOCK_SOCK}
  proxy socket:            ${PROXY_SOCK}
  load mix:                allow ${PROXY_SOCK} GET /_ping, allow GET /containers/json,
                           deny POST /exec/x/start
EOF
  exit 0
fi

BUILD_DIR="$(mktemp -d)"
SAMPLES_TSV="$(mktemp)"
trap 'rm -rf "${BUILD_DIR}"; rm -f "${SAMPLES_TSV}"' EXIT

echo "==> Building sockguard, mockdocker, loadgen"
(cd "${REPO_ROOT}/app" && go build -o "${BUILD_DIR}/sockguard" ./cmd/sockguard/)
(cd "${BENCH_DIR}"     && go build -o "${BUILD_DIR}/mockdocker" ./cmd/mockdocker/)
(cd "${BENCH_DIR}"     && go build -o "${BUILD_DIR}/loadgen"    ./cmd/loadgen/)

echo "==> Starting mockdocker on ${MOCK_SOCK}"
rm -f "${MOCK_SOCK}"
"${BUILD_DIR}/mockdocker" -socket "${MOCK_SOCK}" >/dev/null 2>&1 &
MOCK_PID=$!
trap 'kill "${MOCK_PID}" 2>/dev/null || true; rm -f "${MOCK_SOCK}" "${PROXY_SOCK}"; rm -rf "${BUILD_DIR}"; rm -f "${SAMPLES_TSV}"' EXIT

for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ -S "${MOCK_SOCK}" ] && break
  sleep 0.2
done
[ -S "${MOCK_SOCK}" ] || { echo "mockdocker socket never appeared" >&2; exit 1; }

echo "==> Starting sockguard on ${PROXY_SOCK}"
rm -f "${PROXY_SOCK}"
"${BUILD_DIR}/sockguard" serve --config "${BENCH_DIR}/config.yaml" >/dev/null 2>&1 &
PROXY_PID=$!
trap 'kill "${MOCK_PID}" "${PROXY_PID}" 2>/dev/null || true; rm -f "${MOCK_SOCK}" "${PROXY_SOCK}"; rm -rf "${BUILD_DIR}"; rm -f "${SAMPLES_TSV}"' EXIT

for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ -S "${PROXY_SOCK}" ] && break
  sleep 0.2
done
[ -S "${PROXY_SOCK}" ] || { echo "sockguard socket never appeared" >&2; exit 1; }

# RSS sampler reads VmRSS (Linux) or `ps -o rss=` (macOS) for a stable
# kilobyte count regardless of the runner host kernel. Threads come
# from /proc/PID/status (Linux) or the same `ps` fallback.
read_rss_kb() {
  local pid="$1"
  if [ -r "/proc/${pid}/status" ]; then
    awk '/^VmRSS:/ {print $2}' "/proc/${pid}/status"
  else
    ps -o rss= -p "${pid}" | tr -d ' '
  fi
}
read_threads() {
  local pid="$1"
  if [ -r "/proc/${pid}/status" ]; then
    awk '/^Threads:/ {print $2}' "/proc/${pid}/status"
  else
    ps -M -p "${pid}" 2>/dev/null | tail -n +2 | wc -l | tr -d ' '
  fi
}

# Warmup so the post-warmup baseline reflects steady-state working
# set, not first-allocation overhead.
echo "==> Warmup (15s)"
"${BUILD_DIR}/loadgen" \
  -socket "${PROXY_SOCK}" -method GET -path /_ping \
  -concurrency "${CONCURRENCY}" -duration 15s -scenario soak-warmup \
  >/dev/null

BASELINE_RSS_KB="$(read_rss_kb "${PROXY_PID}")"
BASELINE_THREADS="$(read_threads "${PROXY_PID}")"
echo "==> Post-warmup baseline: RSS=${BASELINE_RSS_KB}KB threads=${BASELINE_THREADS}"

# Convert Go duration to seconds for the sampler loop. Only s/m/h are
# accepted (validated above), so the arithmetic is straightforward.
duration_to_seconds() {
  local raw="$1"
  local suffix="${raw: -1}"
  local value="${raw%?}"
  case "${suffix}" in
    s) echo "${value}" ;;
    m) echo "$(( value * 60 ))" ;;
    h) echo "$(( value * 3600 ))" ;;
  esac
}
TOTAL_SECONDS="$(duration_to_seconds "${DURATION}")"

# Three load workers run concurrently for the full duration, each
# pinned to one scenario. This mirrors a realistic mix: most traffic
# is read-side; deny path is exercised steadily so a leak in the
# deny-response codepath is also surfaced.
WORKER_LOG_DIR="$(mktemp -d)"
trap 'kill "${MOCK_PID}" "${PROXY_PID}" 2>/dev/null || true; rm -f "${MOCK_SOCK}" "${PROXY_SOCK}"; rm -rf "${BUILD_DIR}" "${WORKER_LOG_DIR}"; rm -f "${SAMPLES_TSV}"' EXIT

run_worker() {
  local label="$1" method="$2" path="$3"
  "${BUILD_DIR}/loadgen" \
    -socket "${PROXY_SOCK}" \
    -method "${method}" \
    -path "${path}" \
    -concurrency "${CONCURRENCY}" \
    -duration "${DURATION}" \
    -scenario "${label}" \
    > "${WORKER_LOG_DIR}/${label}.json" &
}

echo "==> Soaking for ${DURATION} (concurrency ${CONCURRENCY}/worker)"
run_worker "soak_ping"        GET  /_ping
run_worker "soak_containers"  GET  /containers/json
run_worker "soak_exec_deny"   POST /exec/x/start

echo "elapsed_s	rss_kb	threads" > "${SAMPLES_TSV}"
SAMPLE_END="$(( $(date +%s) + TOTAL_SECONDS ))"
SAMPLE_START="$(date +%s)"
while [ "$(date +%s)" -lt "${SAMPLE_END}" ]; do
  sleep "${SAMPLE_INTERVAL_SECONDS}"
  if ! kill -0 "${PROXY_PID}" 2>/dev/null; then
    echo "==> sockguard exited mid-soak — aborting" >&2
    exit 1
  fi
  printf '%s\t%s\t%s\n' \
    "$(( $(date +%s) - SAMPLE_START ))" \
    "$(read_rss_kb "${PROXY_PID}")" \
    "$(read_threads "${PROXY_PID}")" \
    >> "${SAMPLES_TSV}"
done

wait

FINAL_RSS_KB="$(read_rss_kb "${PROXY_PID}")"
FINAL_THREADS="$(read_threads "${PROXY_PID}")"
RSS_DELTA_KB=$(( FINAL_RSS_KB - BASELINE_RSS_KB ))
RSS_DELTA_BYTES=$(( RSS_DELTA_KB * 1024 ))

echo "==> Soak complete"
echo "    baseline: RSS=${BASELINE_RSS_KB}KB threads=${BASELINE_THREADS}"
echo "    final:    RSS=${FINAL_RSS_KB}KB threads=${FINAL_THREADS}"
echo "    delta:    RSS=+${RSS_DELTA_KB}KB (${RSS_DELTA_BYTES} bytes) threads=$(( FINAL_THREADS - BASELINE_THREADS ))"
echo "    samples written to ${SAMPLES_TSV}"

if [ "${RSS_DELTA_BYTES}" -gt "${RSS_GROWTH_THRESHOLD_BYTES}" ]; then
  echo "==> FAIL: RSS growth ${RSS_DELTA_BYTES} bytes exceeds threshold ${RSS_GROWTH_THRESHOLD_BYTES} bytes" >&2
  exit 1
fi

# Surface per-worker loadgen JSON so the workflow can attach it as an
# artifact; the line-delimited format matches the synthetic benchmark.
cat "${WORKER_LOG_DIR}"/*.json
