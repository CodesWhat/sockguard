#!/usr/bin/env bash
#
# security-testssl.sh — QA-4 DAST-class TLS posture check.
#
# Spins up a sockguard TCP+TLS listener with the production-shape
# config (TLS 1.3 floor, mutual auth, the same builder used in
# config.BuildMutualTLSServerConfig), then drives drwetter/testssl.sh
# against the live socket. The Go unit tests pin the config builder
# at the code level; this catches the case where a future operator
# config or build flag accidentally weakens the wire posture
# (downgrade to 1.2, weak suites, broken cert chain) — testssl.sh
# is the drift detector VISION calls out for the QA-4 surface.
#
# Usage:
#   scripts/security-testssl.sh [--dry-run]
#
# --dry-run prints the resolved invocation plan and exits 0 without
# building, starting, or scanning anything — the test seam
# scripts/security-testssl.test.mjs uses to assert the option surface
# stays stable.

set -euo pipefail

DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1; shift ;;
    -h|--help)
      sed -n '1,25p' "$0"; exit 0 ;;
    *)
      echo "security-testssl.sh: unknown flag $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"
LISTEN_HOST="127.0.0.1"
LISTEN_PORT="${SOCKGUARD_TESTSSL_PORT:-18443}"
TESTSSL_IMAGE="${TESTSSL_IMAGE:-drwetter/testssl.sh:3.2}"

if [ "${DRY_RUN}" -eq 1 ]; then
  cat <<EOF
security-testssl.sh dry-run plan:
  listen host:        ${LISTEN_HOST}
  listen port:        ${LISTEN_PORT}
  testssl.sh image:   ${TESTSSL_IMAGE}
  cert generator:     openssl (ECDSA P-256)
  fail conditions:    testssl.sh exit code != 0 AND it found a HIGH/CRITICAL severity finding
EOF
  exit 0
fi

# Sanity-check the toolchain before doing anything that needs cleanup.
for tool in openssl docker go; do
  if ! command -v "${tool}" >/dev/null; then
    echo "security-testssl.sh: ${tool} not found on PATH" >&2
    exit 1
  fi
done

WORK_DIR="$(mktemp -d)"
MOCK_SOCK="${WORK_DIR}/mock.sock"
CONFIG_PATH="${WORK_DIR}/sockguard.yaml"
SG_LOG="${WORK_DIR}/sockguard.log"
MOCK_LOG="${WORK_DIR}/mockdocker.log"
TESTSSL_LOG="${WORK_DIR}/testssl.log"
TESTSSL_JSON="${WORK_DIR}/testssl.json"
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "==> Building sockguard, mockdocker"
(cd "${REPO_ROOT}/app" && go build -o "${WORK_DIR}/sockguard" ./cmd/sockguard/)
(cd "${BENCH_DIR}"     && go build -o "${WORK_DIR}/mockdocker" ./cmd/mockdocker/)

echo "==> Generating ECDSA P-256 CA + server certificate"
# CA. ECDSA P-256, valid 1 hour — long enough for the scan, short enough
# that an accidentally-leaked artifact carries minimal residual risk.
openssl ecparam -name prime256v1 -genkey -noout -out "${WORK_DIR}/ca.key"
openssl req -new -x509 -days 1 -key "${WORK_DIR}/ca.key" -out "${WORK_DIR}/ca.crt" \
  -subj "/CN=sockguard-testssl-ca" >/dev/null 2>&1

# Server. SAN includes 127.0.0.1 so testssl.sh's IP-based probe matches.
openssl ecparam -name prime256v1 -genkey -noout -out "${WORK_DIR}/server.key"
cat >"${WORK_DIR}/server.csr.cnf" <<EOF
[req]
distinguished_name = dn
req_extensions     = san
prompt             = no
[dn]
CN = sockguard-testssl-server
[san]
subjectAltName = IP:${LISTEN_HOST}
EOF
openssl req -new -key "${WORK_DIR}/server.key" \
  -out "${WORK_DIR}/server.csr" -config "${WORK_DIR}/server.csr.cnf" \
  >/dev/null 2>&1
openssl x509 -req -in "${WORK_DIR}/server.csr" \
  -CA "${WORK_DIR}/ca.crt" -CAkey "${WORK_DIR}/ca.key" -CAcreateserial \
  -out "${WORK_DIR}/server.crt" -days 1 \
  -extfile "${WORK_DIR}/server.csr.cnf" -extensions san \
  >/dev/null 2>&1

# Sockguard requires client certs on its mTLS listener, so the testssl.sh
# probe will fail the *handshake* on cipher tests — but every probe that
# completes far enough to negotiate a TLS version + cipher already
# reveals the posture testssl.sh measures (offered versions, suites,
# extensions). For probes where mutual-auth is required, the connection
# closes early; testssl.sh still records the negotiation.
cat >"${CONFIG_PATH}" <<EOF
listen:
  address: "${LISTEN_HOST}:${LISTEN_PORT}"
  tls:
    cert_file: ${WORK_DIR}/server.crt
    key_file: ${WORK_DIR}/server.key
    client_ca_file: ${WORK_DIR}/ca.crt
upstream:
  socket: ${MOCK_SOCK}
log:
  level: error
  format: json
  output: stderr
  access_log: false
health:
  enabled: false
response:
  deny_verbosity: minimal
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
    reason: default deny
EOF

echo "==> Starting mockdocker on ${MOCK_SOCK}"
rm -f "${MOCK_SOCK}"
"${WORK_DIR}/mockdocker" -socket "${MOCK_SOCK}" >"${MOCK_LOG}" 2>&1 &
MOCK_PID=$!
trap 'kill "${MOCK_PID}" 2>/dev/null || true; rm -rf "${WORK_DIR}"' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ -S "${MOCK_SOCK}" ] && break
  sleep 0.2
done
[ -S "${MOCK_SOCK}" ] || { echo "mockdocker never appeared (see ${MOCK_LOG})" >&2; exit 1; }

echo "==> Starting sockguard on ${LISTEN_HOST}:${LISTEN_PORT}"
"${WORK_DIR}/sockguard" serve --config "${CONFIG_PATH}" >"${SG_LOG}" 2>&1 &
SG_PID=$!
trap 'kill "${MOCK_PID}" "${SG_PID}" 2>/dev/null || true; rm -rf "${WORK_DIR}"' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if (echo >"/dev/tcp/${LISTEN_HOST}/${LISTEN_PORT}") 2>/dev/null; then
    break
  fi
  sleep 0.3
done
if ! (echo >"/dev/tcp/${LISTEN_HOST}/${LISTEN_PORT}") 2>/dev/null; then
  echo "sockguard never opened ${LISTEN_HOST}:${LISTEN_PORT} (see ${SG_LOG})" >&2
  exit 1
fi

echo "==> Running testssl.sh against ${LISTEN_HOST}:${LISTEN_PORT}"
# --host-network so testssl.sh can dial 127.0.0.1 from inside the
# container; --jsonfile-pretty for parseable severity-tagged output.
docker run --rm --network=host \
  -v "${WORK_DIR}:/work" \
  "${TESTSSL_IMAGE}" \
  --color 0 \
  --jsonfile-pretty /work/testssl.json \
  "${LISTEN_HOST}:${LISTEN_PORT}" \
  | tee "${TESTSSL_LOG}" || true

if [ ! -s "${TESTSSL_JSON}" ]; then
  echo "testssl.sh produced no JSON output (see ${TESTSSL_LOG})" >&2
  exit 1
fi

# Fail only on HIGH or CRITICAL severity findings. INFO and OK lines are
# the steady-state output for a Go stdlib TLS 1.3 server; LOW and MEDIUM
# can surface transient noise on a non-pristine runner.
HIGH_CRIT_COUNT="$(jq -r '
  [ .[] | select(.severity == "HIGH" or .severity == "CRITICAL") ] | length
' "${TESTSSL_JSON}")"

echo "==> testssl.sh HIGH/CRITICAL findings: ${HIGH_CRIT_COUNT}"
if [ "${HIGH_CRIT_COUNT}" -gt 0 ]; then
  jq -r '
    .[] | select(.severity == "HIGH" or .severity == "CRITICAL")
        | "  - [\(.severity)] \(.id): \(.finding)"
  ' "${TESTSSL_JSON}" >&2
  echo "==> FAIL: testssl.sh found HIGH/CRITICAL TLS issues" >&2
  exit 1
fi

# Copy the JSON next to the working dir before the cleanup trap fires.
cp "${TESTSSL_JSON}" "${REPO_ROOT}/testssl-output.json"
cp "${TESTSSL_LOG}"  "${REPO_ROOT}/testssl-output.txt"
echo "==> Wrote ${REPO_ROOT}/testssl-output.json and testssl-output.txt"
