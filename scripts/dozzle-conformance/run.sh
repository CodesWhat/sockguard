#!/usr/bin/env bash
#
# scripts/dozzle-conformance/run.sh: published Dozzle against the dozzle preset
# on a real engine. See README.md.
#
#   run.sh [--sockguard-image REF] [--dozzle-image REF] [--out DIR]
#   run.sh --self-test
#
# Docker comes from the `docker` command on PATH and the script never starts
# an engine itself. To point it at a remote test engine, put a `docker` shim on
# PATH that forwards to that engine's CLI (see README.md).
#
# No `set -e`: a failed assertion is routine control flow, and the remaining
# assertions must still run so one failure doesn't hide the others.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONFIG_PATH="${REPO_ROOT}/app/configs/dozzle.yaml"
KNOWN_ROUTES="${SCRIPT_DIR}/known-routes.json"
CLI=(node "${SCRIPT_DIR}/cli.mjs")

# Dozzle tag matches examples/compose/dozzle/docker-compose.yml and the
# release the preset was derived from.
DOZZLE_IMAGE="amir20/dozzle:v11.5.0"
SOCKGUARD_IMAGE="codeswhat/sockguard:latest"
# Marker, probe and curl client in one pinned image (curlimages/curl 8.23.0).
PROBE_IMAGE="curlimages/curl:8.23.0"
OUT_DIR="${REPO_ROOT}"
SELF_TEST=0

while [ $# -gt 0 ]; do
  case "$1" in
    --sockguard-image)
      SOCKGUARD_IMAGE="${2:?--sockguard-image needs a value}"
      shift 2
      ;;
    --dozzle-image)
      DOZZLE_IMAGE="${2:?--dozzle-image needs a value}"
      shift 2
      ;;
    --out)
      OUT_DIR="${2:?--out needs a value}"
      shift 2
      ;;
    --self-test)
      SELF_TEST=1
      shift
      ;;
    *)
      echo "run.sh: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

ASSERTIONS_JSON='[]'
ROW_FAILED=0

record_result() {
  local name="$1" status="$2" detail="${3:-}"
  ASSERTIONS_JSON="$(jq -c --arg n "$name" --arg s "$status" --arg d "$detail" \
    '. + [{"name":$n,"status":$s,"detail":$d}]' <<<"$ASSERTIONS_JSON")"
  if [ "$status" = "PASS" ]; then
    echo "PASS: ${name}"
  else
    echo "FAIL: ${name} -- ${detail}" >&2
    ROW_FAILED=1
  fi
}

# ---------------------------------------------------------------------------
# --self-test: no Docker, no network. Proves the parsing helpers and the
# drift tripwire fail closed before a live run is trusted.
# ---------------------------------------------------------------------------
if [ "$SELF_TEST" -eq 1 ]; then
  rc=0
  empty="$("${CLI[@]}" drift "$KNOWN_ROUTES" </dev/null)"
  if [ "$(jq -r .status <<<"$empty")" = "FAIL" ]; then
    echo "PASS: drift fails closed on an empty access log"
  else
    echo "FAIL: drift passed on an empty access log" >&2
    rc=1
  fi
  good='{"msg":"request","method":"GET","normalized_path":"/containers/json","decision":"allow","status":200}'
  if [ "$(jq -r .status <<<"$("${CLI[@]}" drift "$KNOWN_ROUTES" <<<"$good")")" = "PASS" ]; then
    echo "PASS: drift passes a reviewed route"
  else
    echo "FAIL: drift rejected a reviewed route" >&2
    rc=1
  fi
  bad='{"msg":"request","method":"POST","normalized_path":"/containers/create","decision":"allow","status":200}'
  if [ "$(jq -r .status <<<"$("${CLI[@]}" drift "$KNOWN_ROUTES" <<<"$bad")")" = "FAIL" ]; then
    echo "PASS: drift fails on an unreviewed route"
  else
    echo "FAIL: drift passed an unreviewed route" >&2
    rc=1
  fi
  exit "$rc"
fi

# Allowlist like the tri-tool harness: only published sockguard images.
SOCKGUARD_IMAGE_ALLOWLIST_RE='^(ghcr\.io/codeswhat/sockguard|docker\.io/codeswhat/sockguard|quay\.io/codeswhat/sockguard|codeswhat/sockguard)(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$'
if [[ ! $SOCKGUARD_IMAGE =~ $SOCKGUARD_IMAGE_ALLOWLIST_RE ]]; then
  echo "run.sh: --sockguard-image '${SOCKGUARD_IMAGE}' is not an allowlisted sockguard image reference" >&2
  exit 2
fi
if [[ ! $DOZZLE_IMAGE =~ ^amir20/dozzle:[A-Za-z0-9._-]+$ ]]; then
  echo "run.sh: --dozzle-image '${DOZZLE_IMAGE}' must be amir20/dozzle:<tag>" >&2
  exit 2
fi

SUFFIX="$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8)"
PROJECT="sg-dozzle-${SUFFIX}"
MARKER_NAME="${PROJECT}-marker"
SENTINEL="SG_DOZZLE_SENTINEL_${SUFFIX}"
EVIDENCE="${OUT_DIR}/dozzle-conformance.json"
LOG_DIR="${OUT_DIR}/dozzle-conformance-logs"
mkdir -p "$LOG_DIR"

export SOCKGUARD_IMAGE DOZZLE_IMAGE PROBE_IMAGE MARKER_NAME SENTINEL
CONFIG_VOLUME="${PROJECT}-config"
export CONFIG_VOLUME

compose() {
  docker compose -p "$PROJECT" -f "${SCRIPT_DIR}/docker-compose.yml" "$@"
}
probe() {
  compose exec -T probe "$@"
}

OVERALL_WRITTEN=0
write_evidence() {
  local sg_digest dz_digest
  sg_digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "$SOCKGUARD_IMAGE" 2>/dev/null || true)"
  dz_digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "$DOZZLE_IMAGE" 2>/dev/null || true)"
  jq -n \
    --arg overall "$([ "$ROW_FAILED" -eq 0 ] && echo PASS || echo FAIL)" \
    --arg project "$PROJECT" --arg sentinel "$SENTINEL" \
    --arg sg "$SOCKGUARD_IMAGE" --arg sgd "$sg_digest" \
    --arg dz "$DOZZLE_IMAGE" --arg dzd "$dz_digest" \
    --argjson assertions "$ASSERTIONS_JSON" \
    --argjson routes "${OBSERVED_ROUTES:-[]}" \
    '{overall:$overall, project:$project, sentinel:$sentinel,
      images:{sockguard:{ref:$sg,digest:$sgd}, dozzle:{ref:$dz,digest:$dzd}},
      observed_routes:$routes, assertions:$assertions}' >"$EVIDENCE"
  OVERALL_WRITTEN=1
}

cleanup() {
  local status=$?
  compose logs --no-color --no-log-prefix sockguard >"${LOG_DIR}/sockguard.log" 2>&1 || true
  compose logs --no-color --no-log-prefix dozzle >"${LOG_DIR}/dozzle.log" 2>&1 || true
  if [ "$OVERALL_WRITTEN" -eq 0 ]; then
    [ "$status" -ne 0 ] && ROW_FAILED=1
    record_result "harness completed" FAIL "exited early with status ${status}"
    write_evidence
  fi
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker rm -f "${PROJECT}-seed" >/dev/null 2>&1 || true
  docker volume rm "$CONFIG_VOLUME" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

OBSERVED_ROUTES='[]'

# Group of the engine's socket, resolved on the engine itself so it works
# against a remote engine too.
DOCKER_SOCK_GID=""
for _ in 1 2 3; do
  docker pull -q "$PROBE_IMAGE" >/dev/null 2>&1 || true
  DOCKER_SOCK_GID="$(docker run --rm -v /var/run/docker.sock:/s:ro --entrypoint stat "$PROBE_IMAGE" -c '%g' /s 2>/dev/null | tail -1)" || true
  [[ ${DOCKER_SOCK_GID} =~ ^[0-9]+$ ]] && break
  sleep 5
done
if [[ ! ${DOCKER_SOCK_GID:-} =~ ^[0-9]+$ ]]; then
  record_result "resolve docker socket gid" FAIL "could not read the group of /var/run/docker.sock on the engine"
  exit 1
fi
export DOCKER_SOCK_GID

# Seed the preset into a named volume (works against a remote engine).
if ! { docker volume create "$CONFIG_VOLUME" &&
  docker create --name "${PROJECT}-seed" -v "${CONFIG_VOLUME}:/c" --entrypoint true "$PROBE_IMAGE" &&
  docker cp "$CONFIG_PATH" "${PROJECT}-seed:/c/sockguard.yaml" &&
  docker rm "${PROJECT}-seed"; } >"${LOG_DIR}/seed.log" 2>&1; then
  record_result "seed sockguard config" FAIL "$(tail -3 "${LOG_DIR}/seed.log" | tr '\n' ' ')"
  exit 1
fi

if ! compose up -d >"${LOG_DIR}/compose-up.log" 2>&1; then
  record_result "compose up" FAIL "$(tail -5 "${LOG_DIR}/compose-up.log" | tr '\n' ' ')"
  exit 1
fi
record_result "compose up" PASS

# 1. Dozzle's container list (SSE feed) includes the marker. The feed never
# ends, so curl is expected to time out (exit 28) after --max-time.
CONTAINER_JSON=""
for _ in $(seq 1 20); do
  sse="$(probe curl -sS -N --max-time 6 http://dozzle:8080/api/events/stream 2>/dev/null || true)"
  if CONTAINER_JSON="$("${CLI[@]}" find-container "$MARKER_NAME" <<<"$sse")"; then
    break
  fi
  CONTAINER_JSON=""
  sleep 2
done
if [ -n "$CONTAINER_JSON" ]; then
  record_result "dozzle container list includes the marker" PASS
else
  record_result "dozzle container list includes the marker" FAIL "marker ${MARKER_NAME} never appeared in /api/events/stream"
fi

# 2. Dozzle's log endpoint returns the sentinel for that container.
if [ -n "$CONTAINER_JSON" ]; then
  ref="$(jq -r '.host + "/" + .id' <<<"$CONTAINER_JSON")"
  logs_ok=0
  for _ in $(seq 1 10); do
    body="$(probe curl -sS --max-time 15 -X POST http://dozzle:8080/api/containers/logs \
      --data-urlencode "container=${ref}" -d stdout=1 -d stderr=1 2>/dev/null || true)"
    if grep -qF "$SENTINEL" <<<"$body"; then
      logs_ok=1
      break
    fi
    sleep 2
  done
  if [ "$logs_ok" -eq 1 ]; then
    record_result "dozzle logs contain the sentinel" PASS
  else
    record_result "dozzle logs contain the sentinel" FAIL "sentinel ${SENTINEL} not in /api/containers/logs response"
  fi
else
  record_result "dozzle logs contain the sentinel" FAIL "skipped, no marker container reference"
fi

# 3 + 4. Sockguard's access log for the allowed flows: no denial, and every
# route shape is in known-routes.json. Snapshot before the forbidden probes.
ALLOWED_LOG="$(compose logs --no-color --no-log-prefix sockguard 2>/dev/null)"
printf '%s\n' "$ALLOWED_LOG" >"${LOG_DIR}/sockguard-allowed-flows.log"
DENIED="$("${CLI[@]}" denied "$KNOWN_ROUTES" <<<"$ALLOWED_LOG")"
if [ "$(jq 'length' <<<"$DENIED")" -eq 0 ]; then
  record_result "no denied call during the allowed flows" PASS
else
  record_result "no denied call during the allowed flows" FAIL "preset denied what Dozzle needs: ${DENIED}"
fi

OBSERVED_ROUTES="$("${CLI[@]}" routes <<<"$ALLOWED_LOG")"
DRIFT="$("${CLI[@]}" drift "$KNOWN_ROUTES" <<<"$ALLOWED_LOG")"
record_result "route-drift tripwire" "$(jq -r .status <<<"$DRIFT")" "$(jq -r .detail <<<"$DRIFT")"

# 5. Forbidden calls through the proxy are denied with 403 and logged as
# denials. Each is something the preset must never allow.
forbidden_ok=1
forbidden_detail=""
for spec in "POST /containers/create" "GET /images/json" "GET /volumes" "POST /containers/${MARKER_NAME}/stop"; do
  method="${spec%% *}"
  path="${spec#* }"
  code="$(probe curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -X "$method" \
    "http://sockguard:2375${path}" 2>/dev/null || true)"
  if [ "$code" != "403" ]; then
    forbidden_ok=0
    forbidden_detail="${forbidden_detail}${spec} returned '${code}' (want 403); "
  fi
done
if [ "$forbidden_ok" -eq 1 ]; then
  record_result "forbidden calls are denied with 403" PASS
else
  record_result "forbidden calls are denied with 403" FAIL "$forbidden_detail"
fi

FINAL_LOG="$(compose logs --no-color --no-log-prefix sockguard 2>/dev/null)"
if "${CLI[@]}" denied <<<"$FINAL_LOG" | jq -e 'any(.method=="POST" and .path=="/containers/create")' >/dev/null; then
  record_result "access log records the denied POST /containers/create" PASS
else
  record_result "access log records the denied POST /containers/create" FAIL "no denial record for POST /containers/create in the sockguard log"
fi

write_evidence
echo "evidence: ${EVIDENCE}"
exit "$ROW_FAILED"
