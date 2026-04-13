#!/usr/bin/env bash
#
# run.sh — orchestrate the sockguard synthetic benchmark.
#
# Builds mockdocker, loadgen, and sockguard from this checkout, starts
# mockdocker + sockguard on unix sockets, runs each scenario against
# both the bare mock (baseline) and the sockguard proxy (with-proxy),
# and emits newline-delimited JSON for every run.
#
# The JSON output is designed to be pasted straight into BENCHMARKS.md
# or piped through jq. No external deps beyond the Go toolchain.
#
# Usage: benchmarks/run.sh [duration]
#   duration: per-scenario duration in Go time.Duration syntax (default 20s)

set -euo pipefail

DURATION="${1:-20s}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "${BUILD_DIR}"' EXIT

MOCK_SOCK="/tmp/sg-bench-mock.sock"
PROXY_SOCK="/tmp/sg-bench-proxy.sock"
WOLLO_SOCK="/tmp/sg-bench-wollomatic.sock"
WOLLO_BIN="${WOLLO_BIN:-/tmp/socket-proxy}"

echo "==> Building sockguard, mockdocker, loadgen"
(cd "${REPO_ROOT}/app"    && go build -o "${BUILD_DIR}/sockguard"   ./cmd/sockguard/)
(cd "${BENCH_DIR}"        && go build -o "${BUILD_DIR}/mockdocker" ./cmd/mockdocker/)
(cd "${BENCH_DIR}"        && go build -o "${BUILD_DIR}/loadgen"    ./cmd/loadgen/)

MOCK_LOG="${BENCH_DIR}/mockdocker.log"
: > "${MOCK_LOG}"

echo "==> Starting mockdocker on ${MOCK_SOCK}"
rm -f "${MOCK_SOCK}"
"${BUILD_DIR}/mockdocker" -socket "${MOCK_SOCK}" >"${MOCK_LOG}" 2>&1 &
MOCK_PID=$!
trap 'kill "${MOCK_PID}" 2>/dev/null || true; rm -f "${MOCK_SOCK}" "${PROXY_SOCK}"; rm -rf "${BUILD_DIR}"' EXIT

# Wait for mock socket
for i in 1 2 3 4 5 6 7 8 9 10; do
  [ -S "${MOCK_SOCK}" ] && break
  sleep 0.2
done

SG_LOG="${BENCH_DIR}/sockguard.log"
: > "${SG_LOG}"

echo "==> Starting sockguard on ${PROXY_SOCK}"
rm -f "${PROXY_SOCK}"
"${BUILD_DIR}/sockguard" serve --config "${BENCH_DIR}/config.yaml" >"${SG_LOG}" 2>&1 &
PROXY_PID=$!
trap 'kill "${MOCK_PID}" "${PROXY_PID}" 2>/dev/null || true; rm -f "${MOCK_SOCK}" "${PROXY_SOCK}"; rm -rf "${BUILD_DIR}"' EXIT

for i in 1 2 3 4 5 6 7 8 9 10; do
  [ -S "${PROXY_SOCK}" ] && break
  sleep 0.2
done
[ -S "${PROXY_SOCK}" ] || { echo "proxy socket never appeared"; exit 1; }

# Optional: start wollomatic/socket-proxy on the same upstream for a head-to-head
# regression check. Skipped if the binary is missing.
WOLLO_PID=""
WOLLO_LOG="${BENCH_DIR}/wollomatic.log"
: > "${WOLLO_LOG}"
if [ -x "${WOLLO_BIN}" ]; then
  echo "==> Starting wollomatic/socket-proxy on ${WOLLO_SOCK}"
  rm -f "${WOLLO_SOCK}"
  "${WOLLO_BIN}" \
    -socketpath "${MOCK_SOCK}" \
    -proxysocketendpoint "${WOLLO_SOCK}" \
    -proxysocketendpointfilemode 438 \
    -allowGET '/_ping$|/containers/json$' \
    -loglevel ERROR \
    >"${WOLLO_LOG}" 2>&1 &
  WOLLO_PID=$!
  trap 'kill "${MOCK_PID}" "${PROXY_PID}" ${WOLLO_PID:-} 2>/dev/null || true; rm -f "${MOCK_SOCK}" "${PROXY_SOCK}" "${WOLLO_SOCK}"; rm -rf "${BUILD_DIR}"' EXIT
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -S "${WOLLO_SOCK}" ] && break
    sleep 0.2
  done
  [ -S "${WOLLO_SOCK}" ] || { echo "wollomatic socket never appeared (see ${WOLLO_LOG})"; WOLLO_PID=""; }
else
  echo "==> wollomatic binary not found at ${WOLLO_BIN}; skipping wollomatic scenarios"
fi

RESULTS="${BENCH_DIR}/results.jsonl"
: > "${RESULTS}"

run_one() {
  local label="$1" socket="$2" method="$3" path="$4" concurrency="$5"
  "${BUILD_DIR}/loadgen" \
    -socket "${socket}" \
    -method "${method}" \
    -path "${path}" \
    -concurrency "${concurrency}" \
    -duration "${DURATION}" \
    -scenario "${label}" >> "${RESULTS}"
}

# Short warmup so connection pools are primed.
echo "==> Warmup"
"${BUILD_DIR}/loadgen" \
  -socket "${PROXY_SOCK}" -method GET -path /_ping \
  -concurrency 10 -duration 2s -scenario warmup >/dev/null

echo "==> Benchmarking"
# Scenario grid: (endpoint, expected-action) × concurrency
for conc in 10 50 200; do
  # Baseline — direct to mock (no proxy in the path at all).
  run_one "ping_baseline"          "${MOCK_SOCK}"   GET  /_ping           "${conc}"
  run_one "containers_baseline"    "${MOCK_SOCK}"   GET  /containers/json "${conc}"
  run_one "exec_baseline"          "${MOCK_SOCK}"   POST /exec/x/start    "${conc}"

  # Through sockguard — allow path.
  run_one "ping_sockguard_allow"       "${PROXY_SOCK}" GET  /_ping           "${conc}"
  run_one "containers_sockguard_allow" "${PROXY_SOCK}" GET  /containers/json "${conc}"
  # Through sockguard — deny path. exec/*/start is denied by config.yaml.
  run_one "exec_sockguard_deny"        "${PROXY_SOCK}" POST /exec/x/start    "${conc}"

  # Through wollomatic/socket-proxy — same scenarios, for a same-class
  # (Go-based) head-to-head regression check.
  if [ -n "${WOLLO_PID}" ]; then
    run_one "ping_wollomatic_allow"       "${WOLLO_SOCK}" GET  /_ping           "${conc}"
    run_one "containers_wollomatic_allow" "${WOLLO_SOCK}" GET  /containers/json "${conc}"
    run_one "exec_wollomatic_deny"        "${WOLLO_SOCK}" POST /exec/x/start    "${conc}"
  fi
done

echo "==> Done"
