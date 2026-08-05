#!/usr/bin/env bash
#
# scripts/tri-tool-conformance/run-matrix.sh — driver for #150's published
# Sockguard + Portwing + drydock conformance matrix.
#
# Boots the audited examples/compose/tri-tool bundle (never source-built --
# these are the exact published images operators pull) from pristine state
# for ONE matrix row, runs the ordered assertions from the #150 design doc,
# and writes conformance-<row>.json unconditionally, pass or fail. It exists
# because source-level compat testing did not catch the 2026-07-28 audit's
# failures (broken published image ref, fresh-volume ownership) -- this
# harness only ever pulls what ghcr.io/docker.io/quay.io actually publish.
#
# Usage:
#   run-matrix.sh --row <current-standard|current-edge|legacy-floor>
#                 [--sockguard-image <ref>]
#                 [--portwing-version <ver>] [--drydock-version <ver>]
#   run-matrix.sh --self-test
#
# --self-test exercises the route normalizer (normalize-routes.jq) and the
# known-routes.json diff logic against testdata/access-log-fixture.jsonl.
# It needs jq only -- no Docker, no network -- and is wired into `npm test`
# via scripts/tri-tool-conformance-run-matrix.test.mjs (see that file's
# header for why it lives one directory up).
#
# See README.md in this directory for the full assertion list, the known
# gaps in what could be verified without live published images, and how to
# update known-routes.json when the tripwire fires on a real route.

set -uo pipefail
# Deliberately NOT `set -e`: an assertion failing is expected, routine
# control flow that the rest of the row still needs to run past, not a
# script bug. Every external command whose failure matters is checked
# explicitly.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUNDLE_DIR="${REPO_ROOT}/examples/compose/tri-tool"

# shellcheck source=scripts/tri-tool-conformance/lib.sh
source "${SCRIPT_DIR}/lib.sh"

# busybox pins for the events/logs/lifecycle sentinels and the assertion-8
# (remote update trigger) recreation check. Only NEW_BUSYBOX_REF matches
# app/integration/helpers_test.go's busyboxPinnedRef -- reusing the same pin
# that repo's OWN integration suite already trusts and pre-pulls in its own
# CI job (quality-integration.yml) rather than inventing a second, unrelated
# digest to track; that pre-pull is for that other workflow's runner, not
# this one, so this script pulls both refs itself below. OLD_BUSYBOX_REF is
# a distinct, older busybox release pinned the same way, standing in for
# "the previously deployed version" an update trigger recreates a container
# away from.
OLD_BUSYBOX_REF="busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
NEW_BUSYBOX_REF="busybox:1.37@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0"

ROW=""
SOCKGUARD_IMAGE_INPUT=""
PORTWING_VERSION_INPUT=""
DRYDOCK_VERSION_INPUT=""
SELF_TEST=0

while [ $# -gt 0 ]; do
  case "$1" in
    --row) ROW="${2:-}"; shift 2 ;;
    --row=*) ROW="${1#--row=}"; shift ;;
    --sockguard-image) SOCKGUARD_IMAGE_INPUT="${2:-}"; shift 2 ;;
    --sockguard-image=*) SOCKGUARD_IMAGE_INPUT="${1#--sockguard-image=}"; shift ;;
    --portwing-version) PORTWING_VERSION_INPUT="${2:-}"; shift 2 ;;
    --portwing-version=*) PORTWING_VERSION_INPUT="${1#--portwing-version=}"; shift ;;
    --drydock-version) DRYDOCK_VERSION_INPUT="${2:-}"; shift 2 ;;
    --drydock-version=*) DRYDOCK_VERSION_INPUT="${1#--drydock-version=}"; shift ;;
    --self-test) SELF_TEST=1; shift ;;
    -h|--help) sed -n '1,30p' "$0"; exit 0 ;;
    *) echo "run-matrix.sh: unknown flag $1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# --self-test: no Docker, no network. Proves the normalizer + diff logic
# that assertion 10 depends on actually work before trusting them in a live
# run, and gives lefthook/CI something to check on every push.
# ---------------------------------------------------------------------------

run_self_test() {
  echo "== run-matrix.sh --self-test: route normalizer + tripwire diff logic =="
  local fixture="${SCRIPT_DIR}/testdata/access-log-fixture.jsonl"
  local known="${SCRIPT_DIR}/known-routes.json"
  local failed=0

  if ! jq empty "$known" 2>/tmp/known-routes-lint.err; then
    echo "FAIL: known-routes.json is not valid JSON: $(cat /tmp/known-routes-lint.err)" >&2
    return 1
  fi
  echo "PASS: known-routes.json parses as valid JSON"

  local observed
  observed="$(jq -n -R -f "${SCRIPT_DIR}/normalize-routes.jq" "$fixture")" || {
    echo "FAIL: normalize-routes.jq errored against the fixture" >&2
    return 1
  }

  # The fixture (testdata/access-log-fixture.jsonl) has 10 lines: 6 real
  # access-log lines (5 allowed + 1 denied that IS in known-routes.json),
  # 1 deliberately-unknown denied route (GET /containers/*/attach, which is
  # NOT in known-routes.json -- attach is never allowed by any preset and
  # was never added as an expected-denial-probe shape either), 1
  # access-log-shaped line with normalized_path missing entirely, 1
  # non-access-log line (msg=startup), 1 bare-string JSON value (valid JSON,
  # not an object), and 1 line that isn't JSON at all. The three malformed/
  # partial lines prove tolerance (see below); a correct normalizer still
  # yields exactly 6 unique {method,path} shapes from the 6 real lines.
  local got_count
  got_count="$(jq 'length' <<<"$observed")"
  if [ "$got_count" != "6" ]; then
    echo "FAIL: normalizer produced ${got_count} route shapes from the fixture, want 6" >&2
    echo "$observed" >&2
    failed=1
  else
    echo "PASS: normalizer produced the expected 6 route shapes from the fixture"
  fi

  local unknown
  unknown="$(jq -n -c --argjson observed "$observed" --slurpfile known "$known" '$observed - $known[0].routes')"
  if [ "$unknown" != '[{"method":"GET","path":"/containers/*/attach"}]' ]; then
    echo "FAIL: diff logic did not isolate exactly the fixture's one deliberately-unknown route; got: ${unknown}" >&2
    failed=1
  else
    echo "PASS: diff logic isolated the fixture's one deliberately-unknown route (GET /containers/*/attach)"
  fi

  # And the inverse: every OTHER fixture route must already be recognized,
  # proving the manifest actually covers what real scenario traffic sends
  # rather than the diff trivially passing because known-routes.json is
  # empty or over-broad.
  local known_only
  known_only="$(jq -n -c --argjson observed "$observed" --slurpfile known "$known" \
    '($observed - [{"method":"GET","path":"/containers/*/attach"}]) - $known[0].routes')"
  if [ "$known_only" != "[]" ]; then
    echo "FAIL: fixture routes that should already be in known-routes.json were not recognized: ${known_only}" >&2
    failed=1
  else
    echo "PASS: every other fixture route is already recognized in known-routes.json"
  fi

  # lib.sh's ACCESS_LOG_ROUTE_MATCH_JQ (used by wait_for_access_log_route)
  # must tolerate the same malformed/partial lines normalize-routes.jq does
  # -- the fixture's missing-normalized_path and bare-string-JSON lines both
  # sit AFTER a genuine match (line 2, GET /containers/json) on purpose:
  # under `set -o pipefail`, a jq error on any later line flips jq's own
  # exit status non-zero even after it already printed the match, which
  # would flip this whole pipeline's exit status non-zero too and report
  # the wait as failed despite the match existing. Run it exactly the way
  # wait_for_access_log_route does (same filter, same jq invocation shape)
  # against the fixture and check both the exit status and the match.
  local match_output match_status
  match_output="$(jq -R \
    --arg m "GET" --arg d "allow" --arg p '^/containers/json$' \
    "$ACCESS_LOG_ROUTE_MATCH_JQ" "$fixture" 2>/tmp/access-log-match.err)"
  match_status=$?
  if [ "$match_status" -ne 0 ]; then
    echo "FAIL: ACCESS_LOG_ROUTE_MATCH_JQ exited ${match_status} against the fixture's malformed lines: $(cat /tmp/access-log-match.err)" >&2
    failed=1
  elif ! grep -q '"normalized_path": *"/containers/json"' <<<"$match_output"; then
    echo "FAIL: ACCESS_LOG_ROUTE_MATCH_JQ did not find the expected match past the fixture's malformed lines" >&2
    failed=1
  else
    echo "PASS: ACCESS_LOG_ROUTE_MATCH_JQ tolerates missing-normalized_path and bare-string-JSON lines without poisoning the exit status"
  fi

  # route_drift_status (lib.sh) must fail closed on an empty observed set --
  # PASSing an empty diff would silently rubber-stamp a broken log capture
  # or normalizer as "nothing unexpected happened."
  local empty_status_line empty_status
  empty_status_line="$(route_drift_status '[]')"
  empty_status="${empty_status_line%%|*}"
  if [ "$empty_status" != "FAIL" ]; then
    echo "FAIL: route_drift_status('[]') returned '${empty_status_line}', want a FAIL (fail-closed on zero observed routes)" >&2
    failed=1
  else
    echo "PASS: route_drift_status fails closed on an empty observed-routes set"
  fi

  if [ "$failed" -eq 0 ]; then
    echo "== self-test OK =="
    return 0
  fi
  echo "== self-test FAILED =="
  return 1
}

if [ "$SELF_TEST" -eq 1 ]; then
  run_self_test
  exit $?
fi

if [ -z "$ROW" ]; then
  echo "run-matrix.sh: --row is required (current-standard|current-edge|legacy-floor), or pass --self-test" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Row configuration
# ---------------------------------------------------------------------------

case "$ROW" in
  current-standard)
    COMPOSE_FILES=("${BUNDLE_DIR}/docker-compose.yml" "${BUNDLE_DIR}/docker-compose.conformance-overlay.yml")
    MODE="standard"
    PRESET_FILE="sockguard.yaml"
    PORTWING_VERSION="${PORTWING_VERSION_INPUT:-latest}"
    DRYDOCK_VERSION="${DRYDOCK_VERSION_INPUT:-latest}"
    EXEC_ROW=0
    REMOTE_UPDATE_SUPPORTED=1
    ;;
  current-edge)
    COMPOSE_FILES=("${BUNDLE_DIR}/docker-compose.edge-exec.yml" "${BUNDLE_DIR}/docker-compose.conformance-overlay.yml")
    MODE="edge"
    PRESET_FILE="sockguard-with-exec.yaml"
    PORTWING_VERSION="${PORTWING_VERSION_INPUT:-latest}"
    DRYDOCK_VERSION="${DRYDOCK_VERSION_INPUT:-latest}"
    EXEC_ROW=1
    REMOTE_UPDATE_SUPPORTED=1
    ;;
  legacy-floor)
    # Audited-floor pins from sockguard PR #155 -- deliberately NOT
    # overridable by the workflow's portwing_version/drydock_version
    # inputs. This row exists to keep the COMPATIBILITY promise honest;
    # letting a dispatch input silently drift it would defeat the point.
    COMPOSE_FILES=("${BUNDLE_DIR}/docker-compose.yml" "${BUNDLE_DIR}/docker-compose.conformance-overlay.yml")
    MODE="standard"
    PRESET_FILE="sockguard.yaml"
    PORTWING_VERSION="0.8.1"
    DRYDOCK_VERSION="1.5.2"
    EXEC_ROW=0
    REMOTE_UPDATE_SUPPORTED=0
    ;;
  *)
    echo "run-matrix.sh: unknown --row '${ROW}' (expected current-standard|current-edge|legacy-floor)" >&2
    exit 2
    ;;
esac

SOCKGUARD_IMAGE_RESOLVED="${SOCKGUARD_IMAGE_INPUT:-codeswhat/sockguard:1.5.1}"
PORTWING_IMAGE_RESOLVED="ghcr.io/codeswhat/portwing:${PORTWING_VERSION}"
DRYDOCK_IMAGE_RESOLVED="codeswhat/drydock:${DRYDOCK_VERSION}"

# Defense in depth: the workflow that drives this script has no
# pull_request trigger (it's workflow_dispatch/schedule only, so
# --sockguard-image is maintainer-controlled, never attacker-controlled via
# a PR), but SOCKGUARD_IMAGE still ends up interpolated into a compose file
# and pulled/run -- validate it against the allowlisted sockguard
# registries/repo before it's ever exported, rather than trusting the input
# unchecked.
SOCKGUARD_IMAGE_ALLOWLIST_RE='^(ghcr\.io/codeswhat/sockguard|docker\.io/codeswhat/sockguard|quay\.io/codeswhat/sockguard|codeswhat/sockguard)(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$'
if [[ ! "$SOCKGUARD_IMAGE_RESOLVED" =~ $SOCKGUARD_IMAGE_ALLOWLIST_RE ]]; then
  echo "run-matrix.sh: --sockguard-image '${SOCKGUARD_IMAGE_RESOLVED}' does not match an allowlisted sockguard image reference (ghcr.io|docker.io|quay.io/codeswhat/sockguard or codeswhat/sockguard, optionally :tag and/or @sha256:<digest>)" >&2
  exit 2
fi

export SOCKGUARD_IMAGE="$SOCKGUARD_IMAGE_RESOLVED"
export PORTWING_VERSION
export DRYDOCK_VERSION
export DOCKER_SOCK_GID
DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock 2>/dev/null || stat -f '%g' /var/run/docker.sock)"

PROJECT="ttconf-${ROW}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-$$}"
PRIMARY_SENTINEL_ID=""
SENTINEL_IDS=()
OBSERVED_ROUTES_JSON="[]"
SOCKGUARD_DIGEST="unknown"
PORTWING_DIGEST="unknown"
DRYDOCK_DIGEST="unknown"
ENGINE_VERSION="unknown"
ENGINE_API_VERSION="unknown"

echo "== #150 tri-tool conformance: row=${ROW} mode=${MODE} preset=${PRESET_FILE} project=${PROJECT} =="
echo "   sockguard=${SOCKGUARD_IMAGE_RESOLVED} portwing=${PORTWING_IMAGE_RESOLVED} drydock=${DRYDOCK_IMAGE_RESOLVED}"

# shellcheck disable=SC2329 # invoked indirectly via `trap cleanup EXIT` below
cleanup() {
  local id
  for id in "${SENTINEL_IDS[@]:-}"; do
    [ -n "$id" ] && docker rm -f "$id" >/dev/null 2>&1 || true
  done
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "${BUNDLE_DIR}/portwing_token.txt" "${BUNDLE_DIR}/portwing_ed25519.pem" "${BUNDLE_DIR}/portwing_authorized_keys"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Fresh secrets every run (design doc assertion 1: "fresh secrets every run")
# ---------------------------------------------------------------------------

if [ "$MODE" = "standard" ]; then
  openssl rand -hex 32 > "${BUNDLE_DIR}/portwing_token.txt"
  # Owned by whoever's running this script by default, but portwing reads
  # this secret as UID 65532 (docker-compose.yml's `user: "65532:65532"`) --
  # chown to that UID before the chmod 0400 that follows, or portwing can't
  # read its own secret. Every step here is checked explicitly rather than
  # just `&&`-chaining: a setup failure needs to read as exactly that, not
  # surface later as a misleading auth-handshake failure.
  if ! sudo chown 65532:65532 "${BUNDLE_DIR}/portwing_token.txt"; then
    echo "FATAL: could not chown portwing_token.txt to 65532:65532 (the UID portwing runs as) -- setup error, not a conformance failure" >&2
    exit 1
  fi
  if ! sudo chmod 0400 "${BUNDLE_DIR}/portwing_token.txt"; then
    echo "FATAL: could not chmod portwing_token.txt to 0400 -- setup error, not a conformance failure" >&2
    exit 1
  fi
else
  if ! docker run --rm "$PORTWING_IMAGE_RESOLVED" keygen -comment "tri-tool-conformance-${ROW}" \
      > "${BUNDLE_DIR}/portwing_ed25519.pem" 2>/tmp/keygen.err; then
    echo "FATAL: could not generate Portwing Ed25519 keypair from ${PORTWING_IMAGE_RESOLVED}: $(cat /tmp/keygen.err)" >&2
    exit 1
  fi
  if ! docker run --rm -v "${BUNDLE_DIR}/portwing_ed25519.pem:/key.pem:ro" "$PORTWING_IMAGE_RESOLVED" \
      keygen -pub-from /key.pem -comment "tri-tool-conformance-${ROW}" \
      > "${BUNDLE_DIR}/portwing_authorized_keys" 2>/tmp/keygen-pub.err; then
    echo "FATAL: could not derive the authorized_keys line: $(cat /tmp/keygen-pub.err)" >&2
    exit 1
  fi
  # Every chown/chmod checked explicitly (not `&&`-chained without a check)
  # so a setup failure here fails the row with a clear setup-error message
  # instead of surfacing later as a confusing auth-handshake failure.
  if ! sudo chown 65532:65532 "${BUNDLE_DIR}/portwing_ed25519.pem"; then
    echo "FATAL: could not chown portwing_ed25519.pem to 65532:65532 (the UID portwing runs as) -- setup error, not a conformance failure" >&2
    exit 1
  fi
  if ! sudo chmod 0400 "${BUNDLE_DIR}/portwing_ed25519.pem"; then
    echo "FATAL: could not chmod portwing_ed25519.pem to 0400 -- setup error, not a conformance failure" >&2
    exit 1
  fi
  if ! sudo chown 1000:1000 "${BUNDLE_DIR}/portwing_authorized_keys"; then
    echo "FATAL: could not chown portwing_authorized_keys to 1000:1000 (the UID drydock runs as) -- setup error, not a conformance failure" >&2
    exit 1
  fi
  if ! sudo chmod 0600 "${BUNDLE_DIR}/portwing_authorized_keys"; then
    echo "FATAL: could not chmod portwing_authorized_keys to 0600 -- setup error, not a conformance failure" >&2
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Pre-pull the busybox pins used by the events/logs/lifecycle sentinels and
# the remote-update-trigger recreation check. Neither ref is pulled anywhere
# else ahead of time for this row -- letting `containers/create` implicitly
# trigger the pull on first use inside an assertion works most of the time
# locally, but a slow/flaky pull on a shared CI runner then reads as an
# unrelated timeout in whatever assertion happened to need the image first,
# not what it actually is. Pull both up front and fail the row immediately,
# with a clear message, if either doesn't come down.
# ---------------------------------------------------------------------------

for busybox_ref in "$OLD_BUSYBOX_REF" "$NEW_BUSYBOX_REF"; do
  if ! docker pull "$busybox_ref" >/tmp/busybox-pull.log 2>&1; then
    echo "FATAL: could not pre-pull ${busybox_ref}: $(tail -c 2000 /tmp/busybox-pull.log)" >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Helpers used by more than one assertion
# ---------------------------------------------------------------------------

# shellcheck disable=SC2329 # invoked indirectly via `wait_until ... sockguard_ping_ok`
sockguard_ping_ok() {
  [ "$(probe_curl_status http://localhost/_ping 2>/dev/null)" = "200" ]
}

create_sentinel() {
  local name_arg="$1" image_ref="$2"
  probe_curl -X POST -H 'Content-Type: application/json' \
    -d "$(jq -n --arg img "$image_ref" \
      '{Image:$img, Cmd:["sh","-c","echo tri-tool-conformance-log-marker; sleep 3600"], Labels:{"tri-tool-conformance":"true"}}')" \
    "http://localhost/containers/create?name=${name_arg}"
}

WANT_STATE=""
# shellcheck disable=SC2329 # invoked indirectly via `wait_until ... sentinel_state_matches`
sentinel_state_matches() {
  [ "$(docker inspect --format '{{.State.Status}}' "$PRIMARY_SENTINEL_ID" 2>/dev/null)" = "$WANT_STATE" ]
}

# ---------------------------------------------------------------------------
# Assertion 1: pristine boot
# ---------------------------------------------------------------------------

assert_pristine_boot() {
  local name="pristine-boot"
  compose down -v --remove-orphans >/dev/null 2>&1 || true

  if ! compose up -d sockguard portwing drydock probe >/tmp/compose-up.log 2>&1; then
    record_result "$name" FAIL "docker compose up failed: $(tail -c 2000 /tmp/compose-up.log)"
    return 1
  fi

  # Capture image digests from what `compose up` just started from -- these
  # are the exact bits every assertion in this row exercises. Doing this
  # here instead of via a `docker compose pull` at the end of the row (see
  # resolve_metadata) means an upstream tag moving mid-run can never cause
  # the artifact to record a digest that wasn't actually the one running.
  SOCKGUARD_DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "$SOCKGUARD_IMAGE_RESOLVED" 2>/dev/null || echo unknown)"
  PORTWING_DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "$PORTWING_IMAGE_RESOLVED" 2>/dev/null || echo unknown)"
  DRYDOCK_DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "$DRYDOCK_IMAGE_RESOLVED" 2>/dev/null || echo unknown)"

  if ! wait_until 90 3 sockguard_ping_ok; then
    record_result "$name" FAIL "sockguard never answered a real _ping within 90s of a fresh named-volume boot"
    return 1
  fi

  local vol owner_mode
  vol="$(docker volume ls --filter "label=com.docker.compose.project=${PROJECT}" --format '{{.Name}}' | grep 'sockguard-socket$' | head -1)"
  if [ -z "$vol" ]; then
    record_result "$name" FAIL "could not find the sockguard-socket named volume for project ${PROJECT}"
    return 1
  fi
  owner_mode="$(docker run --rm -v "${vol}:/v:ro" alpine stat -c '%u:%g %a' /v/sockguard.sock 2>/dev/null)"
  if [ "$owner_mode" != "65532:65532 600" ]; then
    record_result "$name" FAIL "socket owner/mode = '${owner_mode}', want '65532:65532 600' with no manual chown"
    return 1
  fi

  record_result "$name" PASS "fresh volume, no manual chown: socket ${owner_mode}, _ping OK"
  return 0
}

# ---------------------------------------------------------------------------
# Assertion 2: auth handshake (+ one negative probe per mode)
# ---------------------------------------------------------------------------

assert_standard_wrong_secret_probe() {
  local name="auth-handshake-wrong-secret-denied"
  local net wrong_secret_file bad_container
  net="$(docker network ls --filter "label=com.docker.compose.project=${PROJECT}" --format '{{.Name}}' | head -1)"
  wrong_secret_file="$(mktemp)"
  openssl rand -hex 32 > "$wrong_secret_file"
  bad_container="tt-conf-badsecret-$$"

  if ! docker run -d --name "$bad_container" --network "$net" \
      -v "${wrong_secret_file}:/run/secrets/portwing_token:ro" \
      -e DD_LOCAL_WATCHER=false \
      -e DD_ANONYMOUS_AUTH_CONFIRM=true \
      -e DD_AGENT_PORTWING_HOST=portwing \
      -e DD_AGENT_PORTWING_PORT=4000 \
      -e DD_AGENT_PORTWING_SECRET__FILE=/run/secrets/portwing_token \
      -e DD_AGENT_ALLOW_INSECURE_SECRET=true \
      "$DRYDOCK_IMAGE_RESOLVED" >/tmp/badsecret.cid 2>/tmp/badsecret.err; then
    record_result "$name" FAIL "could not start the throwaway wrong-secret agent-config probe: $(cat /tmp/badsecret.err)"
    rm -f "$wrong_secret_file"
    return 1
  fi

  local ok=1
  wait_for_container_log_line "$bad_container" '401' 30 && ok=0
  docker rm -f "$bad_container" >/dev/null 2>&1 || true
  rm -f "$wrong_secret_file"

  if [ "$ok" -eq 0 ]; then
    record_result "$name" PASS "throwaway agent config with the wrong shared secret observed a 401, matching the documented failure mode"
  else
    record_result "$name" FAIL "throwaway wrong-secret probe never logged a 401 within 30s"
  fi
}

assert_edge_unknown_key_probe() {
  local name="auth-handshake-unknown-key-rejected"
  local net vol key_file bad_container agent_name="tt-conf-badkey-$$"
  net="$(docker network ls --filter "label=com.docker.compose.project=${PROJECT}" --format '{{.Name}}' | head -1)"
  vol="$(docker volume ls --filter "label=com.docker.compose.project=${PROJECT}" --format '{{.Name}}' | grep 'sockguard-socket$' | head -1)"
  key_file="$(mktemp)"
  bad_container="tt-conf-badkey-$$"

  if ! docker run --rm "$PORTWING_IMAGE_RESOLVED" keygen -comment "$agent_name" > "$key_file" 2>/tmp/badkey-gen.err; then
    record_result "$name" FAIL "could not generate the throwaway unregistered keypair: $(cat /tmp/badkey-gen.err)"
    rm -f "$key_file"
    return 1
  fi

  if ! docker run -d --name "$bad_container" --network "$net" \
      -v "${vol}:/var/run/sockguard:ro" \
      -v "${key_file}:/run/secrets/portwing_key:ro" \
      -e DOCKER_SOCKET=/var/run/sockguard/sockguard.sock \
      -e AGENT_NAME="$agent_name" \
      -e DRYDOCK_URL=http://drydock:3000 \
      -e PRIVATE_KEY_FILE=/run/secrets/portwing_key \
      "$PORTWING_IMAGE_RESOLVED" >/tmp/badkey.cid 2>/tmp/badkey-run.err; then
    record_result "$name" FAIL "could not start the throwaway unknown-key agent-config probe: $(cat /tmp/badkey-run.err)"
    rm -f "$key_file"
    return 1
  fi

  local ok=1
  wait_for_log_line drydock "bad-signature|unknown-key|unauthorized|reject" 30 && ok=0
  docker rm -f "$bad_container" >/dev/null 2>&1 || true
  rm -f "$key_file"

  if [ "$ok" -eq 0 ]; then
    record_result "$name" PASS "throwaway agent config with an unregistered Ed25519 key had its hello rejected, matching the documented failure mode"
  else
    record_result "$name" FAIL "throwaway unknown-key probe never produced a rejection in drydock's logs within 30s"
  fi
}

assert_auth_handshake() {
  local name="auth-handshake"
  if ! wait_for_log_line drydock 'Handshake successful' 90; then
    record_result "$name" FAIL "drydock never logged 'Handshake successful' for the portwing agent within 90s"
    return 1
  fi
  record_result "$name" PASS "drydock logged 'Handshake successful' for the portwing agent"

  if [ "$MODE" = "standard" ]; then
    assert_standard_wrong_secret_probe
  else
    assert_edge_unknown_key_probe
  fi
}

# ---------------------------------------------------------------------------
# Assertion 3: inventory & inspect (passive -- see README "Verification
# strategy" for why this and the assertions below key on sockguard's own
# access log rather than guessing at Portwing/drydock's private API shapes)
# ---------------------------------------------------------------------------

assert_inventory_inspect() {
  local name="inventory-inspect"
  local list_ok=1 inspect_ok=1
  wait_for_access_log_route GET allow '^/containers/json$' 30 && list_ok=0
  wait_for_access_log_route GET allow '^/containers/[^/]+/json$' 30 && inspect_ok=0

  if [ "$list_ok" -eq 0 ] && [ "$inspect_ok" -eq 0 ]; then
    record_result "$name" PASS "Portwing's own list+inspect polling reached sockguard (allowed GET /containers/json and GET /containers/*/json observed)"
  else
    record_result "$name" FAIL "did not observe both an allowed GET /containers/json and GET /containers/*/json in sockguard's access log within 30s"
  fi
}

# ---------------------------------------------------------------------------
# Assertion 4: events -- create/remove a sentinel via the proxied socket
# ---------------------------------------------------------------------------

assert_events() {
  local name="events"
  local sentinel="tt-conf-sentinel-events-$$"
  local create_resp id
  create_resp="$(create_sentinel "$sentinel" "$OLD_BUSYBOX_REF")"
  id="$(jq -r '.Id // empty' <<<"$create_resp" 2>/dev/null)"
  if [ -z "$id" ]; then
    record_result "$name" FAIL "sentinel container create via the proxied socket failed: ${create_resp}"
    return 1
  fi
  SENTINEL_IDS+=("$id")
  probe_curl -X POST "http://localhost/containers/${id}/start" >/dev/null

  local events_ok=1
  wait_for_access_log_route GET allow '^/events$' 15 && events_ok=0

  probe_curl -X POST "http://localhost/containers/${id}/stop?t=5" >/dev/null
  probe_curl -X DELETE "http://localhost/containers/${id}?force=true" >/dev/null

  local removed_ok=1
  wait_for_access_log_route DELETE allow '^/containers/[^/]+$' 15 && removed_ok=0

  if [ "$events_ok" -eq 0 ] && [ "$removed_ok" -eq 0 ]; then
    record_result "$name" PASS "sentinel created/started/stopped/removed via the proxied socket; /events channel open and DELETE allowed"
  else
    record_result "$name" FAIL "events channel or the sentinel's DELETE was not observed allowed (events_ok=${events_ok} removed_ok=${removed_ok})"
  fi
}

# ---------------------------------------------------------------------------
# Assertion 5: logs -- fetch logs for a running container through the
# proxied socket (the sockguard-owned half of the log-streaming contract;
# see README for what this does and doesn't prove about drydock's own
# SSE/WS wrapping)
# ---------------------------------------------------------------------------

assert_logs() {
  local name="logs"
  local sentinel="tt-conf-sentinel-primary-$$"
  local create_resp
  create_resp="$(create_sentinel "$sentinel" "$NEW_BUSYBOX_REF")"
  PRIMARY_SENTINEL_ID="$(jq -r '.Id // empty' <<<"$create_resp" 2>/dev/null)"
  if [ -z "$PRIMARY_SENTINEL_ID" ]; then
    record_result "$name" FAIL "primary sentinel container create failed: ${create_resp}"
    # Not also recording "lifecycle" here -- assert_lifecycle already
    # records its own FAIL when PRIMARY_SENTINEL_ID is empty (it runs right
    # after this in the main sequence), so doing it here too would double
    # up the artifact's assertions array with the same name.
    return 1
  fi
  SENTINEL_IDS+=("$PRIMARY_SENTINEL_ID")
  probe_curl -X POST "http://localhost/containers/${PRIMARY_SENTINEL_ID}/start" >/dev/null
  sleep 2

  local logs
  logs="$(probe_curl "http://localhost/containers/${PRIMARY_SENTINEL_ID}/logs?stdout=1&stderr=1")"
  if grep -q 'tri-tool-conformance-log-marker' <<<"$logs"; then
    record_result "$name" PASS "GET /containers/{id}/logs returned the sentinel's stdout through the proxied socket"
  else
    record_result "$name" FAIL "expected log marker not found in the proxied /containers/{id}/logs response"
  fi
}

# ---------------------------------------------------------------------------
# Assertion 6: lifecycle -- stop/start/restart, verify state converges
# ---------------------------------------------------------------------------

assert_lifecycle() {
  local name="lifecycle"
  if [ -z "$PRIMARY_SENTINEL_ID" ]; then
    record_result "$name" FAIL "skipped -- primary sentinel was never created (see the logs assertion)"
    return 1
  fi

  probe_curl -X POST "http://localhost/containers/${PRIMARY_SENTINEL_ID}/stop?t=5" >/dev/null
  WANT_STATE="exited"
  if ! wait_until 20 2 sentinel_state_matches; then
    record_result "$name" FAIL "sentinel did not converge to 'exited' after stop"
    return 1
  fi

  probe_curl -X POST "http://localhost/containers/${PRIMARY_SENTINEL_ID}/start" >/dev/null
  WANT_STATE="running"
  if ! wait_until 20 2 sentinel_state_matches; then
    record_result "$name" FAIL "sentinel did not converge to 'running' after start"
    return 1
  fi

  probe_curl -X POST "http://localhost/containers/${PRIMARY_SENTINEL_ID}/restart?t=5" >/dev/null
  WANT_STATE="running"
  if ! wait_until 30 2 sentinel_state_matches; then
    record_result "$name" FAIL "sentinel did not converge to 'running' after restart"
    return 1
  fi

  record_result "$name" PASS "stop/start/restart all converged on the sentinel through the proxied socket"
}

# ---------------------------------------------------------------------------
# Assertion 7: configured exec (current-edge only)
# ---------------------------------------------------------------------------

assert_exec() {
  local name="exec-policy"
  if [ "$EXEC_ROW" -ne 1 ]; then
    record_result "$name" SKIP "exec has no transport outside Edge mode -- see examples/compose/tri-tool/README.md"
    return 0
  fi
  if [ -z "$PRIMARY_SENTINEL_ID" ]; then
    record_result "$name" FAIL "skipped -- primary sentinel was never created"
    return 1
  fi

  local exec_create exec_id exec_status
  exec_create="$(probe_curl -X POST -H 'Content-Type: application/json' \
    -d '{"Cmd":["echo","tri-tool-conformance-exec-ok"],"AttachStdout":true,"AttachStderr":true}' \
    "http://localhost/containers/${PRIMARY_SENTINEL_ID}/exec")"
  exec_id="$(jq -r '.Id // empty' <<<"$exec_create" 2>/dev/null)"
  if [ -z "$exec_id" ]; then
    record_result "${name}-allowed" FAIL "a non-privileged exec create was denied: ${exec_create}"
  else
    exec_status="$(probe_curl_status -X POST -H 'Content-Type: application/json' \
      -d '{"Detach":true}' "http://localhost/exec/${exec_id}/start")"
    if [ "$exec_status" = "200" ] || [ "$exec_status" = "201" ]; then
      record_result "${name}-allowed" PASS "a non-privileged exec create+start succeeded through Portwing's edge exec transport"
    else
      record_result "${name}-allowed" FAIL "exec start returned ${exec_status}, want 200/201"
    fi
  fi

  # allow_privileged: false in sockguard-with-exec.yaml denies this
  # regardless of what Portwing/drydock request -- see the compose bundle
  # README's "Usage: Edge Mode + exec" section.
  local denied_status denied_body
  denied_status="$(probe_curl_status -X POST -H 'Content-Type: application/json' \
    -d '{"Cmd":["id"],"Privileged":true,"AttachStdout":true}' \
    "http://localhost/containers/${PRIMARY_SENTINEL_ID}/exec")"
  denied_body="$(probe_curl -X POST -H 'Content-Type: application/json' \
    -d '{"Cmd":["id"],"Privileged":true,"AttachStdout":true}' \
    "http://localhost/containers/${PRIMARY_SENTINEL_ID}/exec")"
  if [ "$denied_status" = "403" ] && jq -e '.reason // empty | length > 0' <<<"$denied_body" >/dev/null 2>&1; then
    record_result "${name}-denied" PASS "a privileged exec create was denied 403 with a documented reason: $(jq -r '.reason' <<<"$denied_body")"
  else
    record_result "${name}-denied" FAIL "a privileged exec create returned status=${denied_status} body=${denied_body}, want 403 with a reason"
  fi
}

# ---------------------------------------------------------------------------
# Assertion 8: remote update trigger (current-* only; legacy-floor asserts
# the documented 501 instead)
# ---------------------------------------------------------------------------

assert_remote_update_trigger() {
  local name="remote-update-trigger"

  if [ "$REMOTE_UPDATE_SUPPORTED" -ne 1 ]; then
    # Portwing 0.8.1 doesn't implement the update-trigger endpoint yet --
    # examples/compose/tri-tool/README.md's "Compatibility boundary"
    # section documents POST /api/triggers/{type}/{name} (and .../batch)
    # returning 501 on this exact pin.
    local status
    status="$(curl --silent --show-error --max-time 10 --output /dev/null --write-out '%{http_code}' \
      -X POST -H 'Content-Type: application/json' -d '{}' \
      "http://127.0.0.1:3000/api/triggers/docker/update" 2>/dev/null)"
    if [ "$status" = "501" ]; then
      record_result "$name" PASS "legacy-floor trigger invocation returned the documented 501 not-implemented"
    else
      record_result "$name" FAIL "legacy-floor trigger invocation returned ${status}, want the documented 501"
    fi
    return 0
  fi

  # current-standard / current-edge: portwing 0.9.0 + drydock 1.6.0-rc.11
  # ship a controller-owned synthetic docker trigger named "update"
  # (transport:docker-api, execution:controller) that bridges through
  # Portwing to sockguard using only endpoints already in the presets.
  #
  # KNOWN GAP: the exact trigger-invocation HTTP contract (path, body
  # schema) is not pinned anywhere in this repo -- it lives in the
  # portwing/drydock repos, which this sandbox has no access to. This
  # request shape is a best-effort match to the compatibility text in
  # examples/compose/tri-tool/README.md and MUST be confirmed (and this
  # function adjusted if wrong) on the first live workflow_dispatch run --
  # see the harness README's "Known gaps" section.
  local sentinel="tt-conf-sentinel-update-$$"
  local create_resp id
  create_resp="$(create_sentinel "$sentinel" "$OLD_BUSYBOX_REF")"
  id="$(jq -r '.Id // empty' <<<"$create_resp" 2>/dev/null)"
  if [ -z "$id" ]; then
    record_result "$name" FAIL "update-trigger sentinel create failed: ${create_resp}"
    return 1
  fi
  SENTINEL_IDS+=("$id")
  probe_curl -X POST "http://localhost/containers/${id}/start" >/dev/null

  local trigger_status
  trigger_status="$(curl --silent --show-error --max-time 30 --output /tmp/trigger-response.json --write-out '%{http_code}' \
    -X POST -H 'Content-Type: application/json' \
    -d "$(jq -n --arg c "$sentinel" --arg img "${NEW_BUSYBOX_REF%%@*}" '{container:$c, image:$img}')" \
    "http://127.0.0.1:3000/api/triggers/docker/update" 2>/dev/null)"

  if [[ ! "$trigger_status" =~ ^2[0-9][0-9]$ ]]; then
    record_result "$name" FAIL "trigger invocation returned ${trigger_status} (body: $(head -c 500 /tmp/trigger-response.json 2>/dev/null)) -- confirm the real trigger contract on the first live dispatch, see harness README 'Known gaps'"
    return 1
  fi

  local recreated=1 waited=0 new_id=""
  while (( waited < 60 )); do
    new_id="$(docker inspect --format '{{.Id}}' "$sentinel" 2>/dev/null || true)"
    if [ -n "$new_id" ] && [ "$new_id" != "$id" ]; then
      recreated=0
      break
    fi
    sleep 3
    waited=$(( waited + 3 ))
  done

  if [ "$recreated" -eq 0 ]; then
    SENTINEL_IDS+=("$new_id")
    record_result "$name" PASS "the controller-owned update trigger recreated the sentinel on the new pin; all Docker API traffic flowed Portwing -> sockguard"
  else
    record_result "$name" FAIL "sentinel container was not recreated within 60s of firing the update trigger"
  fi
}

# ---------------------------------------------------------------------------
# Assertion 9: expected denials
# ---------------------------------------------------------------------------

assert_expected_denials() {
  local name="expected-denials"

  local build_status build_body
  build_status="$(probe_curl_status -X POST "http://localhost/build")"
  build_body="$(probe_curl -X POST "http://localhost/build")"
  if [ "$build_status" = "403" ] && jq -e '.reason // empty | length > 0' <<<"$build_body" >/dev/null 2>&1; then
    record_result "${name}-build" PASS "POST /build denied 403 with reason: $(jq -r '.reason' <<<"$build_body")"
  else
    record_result "${name}-build" FAIL "POST /build returned status=${build_status} body=${build_body}, want 403 with a reason"
  fi

  if [ "$EXEC_ROW" -ne 1 ]; then
    local exec_status
    exec_status="$(probe_curl_status -X POST -H 'Content-Type: application/json' \
      -d '{"Cmd":["id"]}' "http://localhost/containers/nonexistent/exec")"
    if [ "$exec_status" = "403" ]; then
      record_result "${name}-exec" PASS "POST /containers/*/exec denied 403 on the non-exec preset"
    else
      record_result "${name}-exec" FAIL "POST /containers/*/exec returned ${exec_status}, want 403"
    fi
  else
    record_result "${name}-exec" SKIP "current-edge runs the exec-enabled preset by design -- see the exec-policy assertion for its privileged-exec denial case"
  fi

  local export_status
  export_status="$(probe_curl_status "http://localhost/containers/${PRIMARY_SENTINEL_ID:-nonexistent}/export")"
  if [ "$export_status" = "403" ]; then
    record_result "${name}-export" PASS "GET /containers/{id}/export denied 403 (exfiltration-gated read)"
  else
    record_result "${name}-export" FAIL "GET /containers/{id}/export returned ${export_status}, want 403"
  fi
}

# ---------------------------------------------------------------------------
# Assertion 10: route-drift tripwire
# ---------------------------------------------------------------------------

assert_route_drift() {
  local name="route-drift-tripwire"
  local access_log observed status_line status detail
  access_log="$(mktemp)"
  sockguard_access_log > "$access_log"

  observed="$(jq -n -R -f "${SCRIPT_DIR}/normalize-routes.jq" "$access_log")"
  OBSERVED_ROUTES_JSON="$observed"

  status_line="$(route_drift_status "$observed")"
  status="${status_line%%|*}"
  detail="${status_line#*|}"
  record_result "$name" "$status" "$detail"
  rm -f "$access_log"
}

# ---------------------------------------------------------------------------
# Artifact
# ---------------------------------------------------------------------------

resolve_metadata() {
  # Image digests are already captured in assert_pristine_boot, from the
  # images `compose up` actually started this row's containers from -- NOT
  # re-pulled here. A `docker compose pull` this late would race an upstream
  # tag moving mid-run and could record a digest that never ran any of this
  # row's assertions.
  local version_resp
  version_resp="$(probe_curl http://localhost/version 2>/dev/null)"
  ENGINE_VERSION="$(jq -r '.Version // "unknown"' <<<"$version_resp" 2>/dev/null || echo unknown)"
  ENGINE_API_VERSION="$(jq -r '.ApiVersion // "unknown"' <<<"$version_resp" 2>/dev/null || echo unknown)"
}

write_artifact() {
  local outfile="${REPO_ROOT}/conformance-${ROW}.json"
  jq -n \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg row "$ROW" \
    --arg sockguard_ref "$SOCKGUARD_IMAGE_RESOLVED" \
    --arg sockguard_digest "$SOCKGUARD_DIGEST" \
    --arg portwing_ref "$PORTWING_IMAGE_RESOLVED" \
    --arg portwing_digest "$PORTWING_DIGEST" \
    --arg drydock_ref "$DRYDOCK_IMAGE_RESOLVED" \
    --arg drydock_digest "$DRYDOCK_DIGEST" \
    --arg engine_version "$ENGINE_VERSION" \
    --arg engine_api_version "$ENGINE_API_VERSION" \
    --arg preset "$PRESET_FILE" \
    --arg mode "$MODE" \
    --argjson assertions "$ASSERTIONS_JSON" \
    --argjson observed_routes "$OBSERVED_ROUTES_JSON" \
    '{
      timestamp: $timestamp,
      row: $row,
      images: {
        sockguard: {ref: $sockguard_ref, digest: $sockguard_digest},
        portwing: {ref: $portwing_ref, digest: $portwing_digest},
        drydock: {ref: $drydock_ref, digest: $drydock_digest}
      },
      docker_engine: {version: $engine_version, api_version: $engine_api_version},
      sockguard_preset: $preset,
      portwing_mode: $mode,
      observed_routes: $observed_routes,
      assertions: $assertions,
      overall: (if ([$assertions[] | select(.status=="FAIL")] | length) > 0 then "FAIL" else "PASS" end)
    }' > "$outfile"
  echo "Wrote ${outfile}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

PRISTINE_BOOT_OK=1
if assert_pristine_boot; then
  PRISTINE_BOOT_OK=0
  assert_auth_handshake
fi

if [ "$ROW_FAILED" -eq 0 ]; then
  assert_inventory_inspect
  assert_events
  assert_logs
  assert_lifecycle
  assert_exec
  assert_remote_update_trigger
  assert_expected_denials
else
  echo "Pristine boot or auth handshake failed -- skipping the remaining scenario assertions for this row." >&2

  # assert_auth_handshake was never even called when pristine boot itself is
  # what failed, so there's no "auth-handshake" result in the artifact yet
  # to account for it -- record it as skipped too. When pristine boot
  # succeeded and auth-handshake (or its per-mode negative probe) is what
  # failed instead, that assertion already recorded its own FAIL above; skip
  # it here would just duplicate the entry.
  if [ "$PRISTINE_BOOT_OK" -ne 0 ]; then
    record_result "auth-handshake" SKIP "row aborted -- pristine boot failed before auth handshake could be attempted"
  fi

  # Names below must match exactly what the success path records (see each
  # assert_* function) so a skipped row's artifact has the same assertion
  # names a passing row would, just with SKIP instead of PASS/FAIL/SKIP.
  for skipped in inventory-inspect events logs lifecycle; do
    record_result "$skipped" SKIP "row aborted after pristine-boot/auth-handshake failure"
  done

  if [ "$EXEC_ROW" -eq 1 ]; then
    record_result "exec-policy-allowed" SKIP "row aborted after pristine-boot/auth-handshake failure"
    record_result "exec-policy-denied" SKIP "row aborted after pristine-boot/auth-handshake failure"
  else
    record_result "exec-policy" SKIP "row aborted after pristine-boot/auth-handshake failure"
  fi

  record_result "remote-update-trigger" SKIP "row aborted after pristine-boot/auth-handshake failure"

  for skipped in expected-denials-build expected-denials-exec expected-denials-export; do
    record_result "$skipped" SKIP "row aborted after pristine-boot/auth-handshake failure"
  done
fi

# The route-drift tripwire always runs, even on a failed row -- whatever
# traffic did reach sockguard still needs to be checked against the
# manifest, and the artifact is written unconditionally either way.
assert_route_drift
resolve_metadata
write_artifact

echo "== #150 tri-tool conformance: row=${ROW} $( [ "$ROW_FAILED" -eq 0 ] && echo PASS || echo FAIL ) =="
exit "$ROW_FAILED"
