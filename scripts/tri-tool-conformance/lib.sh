#!/usr/bin/env bash
#
# scripts/tri-tool-conformance/lib.sh — shared helpers for run-matrix.sh (#150).
# Sourced, not executed directly.
#
# No `set -e` in here (or in run-matrix.sh): an assertion failing is
# expected, routine control flow, not a script bug, and the driver needs to
# keep running the remaining assertions after one fails so a single broken
# scenario doesn't hide unrelated failures. Every function below returns a
# status instead of exiting; run-matrix.sh's assertion functions are
# responsible for calling record_result with the outcome.

# ---------------------------------------------------------------------------
# Result recording — accumulates into ASSERTIONS_JSON (a jq-encoded array),
# printed and written into the row's artifact by run-matrix.sh at the end.
# ---------------------------------------------------------------------------

ASSERTIONS_JSON='[]'
ROW_FAILED=0

record_result() {
  local name="$1" status="$2" detail="${3:-}"
  ASSERTIONS_JSON="$(jq -c --arg n "$name" --arg s "$status" --arg d "$detail" \
    '. + [{"name":$n,"status":$s,"detail":$d}]' <<<"$ASSERTIONS_JSON")"
  case "$status" in
    PASS) echo "PASS: ${name}" ;;
    SKIP) echo "SKIP: ${name} -- ${detail}" ;;
    *)
      echo "FAIL: ${name} -- ${detail}" >&2
      # shellcheck disable=SC2034 # read by run-matrix.sh, which sources this file
      ROW_FAILED=1
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Polling helper — retries `check_fn` (a function name, called with no args)
# every `interval` seconds until it returns 0 or `timeout` seconds elapse.
# ---------------------------------------------------------------------------

wait_until() {
  local timeout="$1" interval="$2" check_fn="$3"
  local waited=0
  while (( waited < timeout )); do
    if "$check_fn"; then
      return 0
    fi
    sleep "$interval"
    waited=$(( waited + interval ))
  done
  return 1
}

# ---------------------------------------------------------------------------
# Route-drift tripwire decision logic (assertion 10) -- pure jq, no Docker
# dependency, so it can be exercised by --self-test as well as a live row.
# ---------------------------------------------------------------------------

# route_drift_status computes the route-drift tripwire's PASS/FAIL verdict
# for a given observed-routes JSON array against known-routes.json. Relies
# on SCRIPT_DIR (set by run-matrix.sh before this file is sourced) to find
# known-routes.json. Echoes "STATUS|detail" on stdout; used by
# assert_route_drift in run-matrix.sh and directly by --self-test, so the
# fail-closed-on-empty behavior is proven against the exact same code path
# a live run uses, not a reimplementation of it.
route_drift_status() {
  local observed="$1"
  local observed_count unknown

  observed_count="$(jq 'length' <<<"$observed")"
  if [ "$observed_count" -eq 0 ]; then
    # An empty observed set is NOT the same thing as "nothing unexpected was
    # observed" -- it usually means log capture or the normalizer broke, and
    # an empty-diff PASS would silently rubber-stamp that. Fail closed
    # instead: zero parseable access records is itself worth investigating.
    echo "FAIL|no access-log records captured -- log capture or shape broke"
    return
  fi

  unknown="$(jq -n -c --argjson observed "$observed" --slurpfile known "${SCRIPT_DIR}/known-routes.json" \
    '$observed - $known[0].routes')"
  if [ "$unknown" = "[]" ]; then
    echo "PASS|all ${observed_count} observed route shapes are in known-routes.json"
  else
    echo "FAIL|peer repository sent a route sockguard policy has not reviewed -- review policy, then update known-routes.json: ${unknown}"
  fi
}

# ---------------------------------------------------------------------------
# Compose / docker plumbing
# ---------------------------------------------------------------------------

# compose runs `docker compose` for the current row (project name + -f
# flags already applied) with whatever subcommand/args callers pass through:
# `compose up -d sockguard portwing drydock probe`. COMPOSE_FILES is an
# array set by run-matrix.sh per row.
compose() {
  local -a args=(compose -p "$PROJECT")
  local f
  for f in "${COMPOSE_FILES[@]}"; do
    args+=(-f "$f")
  done
  docker "${args[@]}" "$@"
}

# probe_curl runs curl inside the throwaway `probe` container added by
# docker-compose.conformance-overlay.yml, against sockguard's Unix socket.
probe_curl() {
  compose exec -T probe curl --silent --show-error --max-time 10 \
    --unix-socket /var/run/sockguard/sockguard.sock "$@"
}

# probe_curl_status is probe_curl but returns only the HTTP status code,
# for assertions that only care about the response code (denials).
probe_curl_status() {
  compose exec -T probe curl --silent --show-error --max-time 10 \
    --output /dev/null --write-out '%{http_code}' \
    --unix-socket /var/run/sockguard/sockguard.sock "$@"
}

# sockguard_access_log captures the FULL buffered stdout of the row's
# sockguard container (docker's log driver keeps the whole scrollback, so
# calling this repeatedly at different points in the run is safe and always
# returns everything logged so far, not just what's new since last call).
sockguard_access_log() {
  compose logs --no-color --no-log-prefix sockguard 2>/dev/null
}

# wait_for_access_log_route polls sockguard's access log for at least one
# line matching (method, decision, normalized_path regex) within timeout
# seconds. decision may be "allow", "deny", or "would_deny"; an empty
# decision field on an allow line is treated as "allow" per
# app/internal/logging/access.go.
#
# The filter below is deliberately tolerant of malformed/partial lines: a
# non-object JSON value or a line missing (or null) normalized_path must be
# skipped, not error. Under `set -o pipefail` (in effect for the whole of
# run-matrix.sh) a jq error on ANY line -- even one that arrives after a
# genuine match was already found and printed -- flips jq's own exit status
# non-zero, which flips the exit status of this entire pipeline non-zero too
# and reports the wait as failed regardless of what grep found. That poisons
# assertions 3 (inventory-inspect), 4 (events), and 10 (route-drift, via a
# similar pattern in normalize-routes.jq) on otherwise-passing traffic.
#
# For the same pipefail reason the last pipe stage must READ TO EOF, never
# exit early: `grep -q` quits on the first match, and if jq then emits a
# SECOND matching line it dies on SIGPIPE (141), failing the pipeline even
# though the route was observed. That failure mode is deterministic exactly
# when the traffic is healthy -- e.g. Portwing polling /containers/json
# every DD_POLL_INTERVAL seconds guarantees multiple matches -- which is
# how the v1.6.0 gate's inventory-inspect assertion failed on every
# standard row while the routes sat plainly in the log (round 6).
# `grep -c ... >/dev/null` keeps grep's found/not-found exit semantics but
# always consumes the full stream.
# shellcheck disable=SC2016 # single-quoted on purpose: $m/$d/$p are jq --arg variables, not shell
ACCESS_LOG_ROUTE_MATCH_JQ='
  (try fromjson catch empty)
  | select(type=="object")
  | select(.msg=="request" or .msg=="request_denied" or .msg=="request_would_deny")
  | select(.method==$m and ((.decision // "allow")==$d))
  | select((.normalized_path? // empty | strings | test($p)))
'
# access_log_stream_has_route is the wait's matcher: reads an access-log
# stream on stdin, exits 0 iff at least one line matches (method, decision,
# path regex). Kept as its own function so --self-test can drive it with a
# synthetic multi-match stream and pin the read-to-EOF requirement above.
access_log_stream_has_route() {
  local method="$1" decision="$2" path_regex="$3"
  jq -R \
    --arg m "$method" --arg d "$decision" --arg p "$path_regex" \
    "$ACCESS_LOG_ROUTE_MATCH_JQ" \
    2>/dev/null | grep -c . >/dev/null
}

wait_for_access_log_route() {
  local method="$1" decision="$2" path_regex="$3" timeout="${4:-30}"
  local waited=0
  while (( waited < timeout )); do
    if sockguard_access_log | access_log_stream_has_route "$method" "$decision" "$path_regex"; then
      return 0
    fi
    sleep 2
    waited=$(( waited + 2 ))
  done
  return 1
}

# wait_for_log_line polls `docker compose logs <service>` for a line
# matching an extended-regex pattern within timeout seconds. Same
# read-to-EOF rule as above: an early-exiting grep -Eq would SIGPIPE
# `docker compose logs` under pipefail whenever >64KB of log follows the
# first match.
wait_for_log_line() {
  local service="$1" pattern="$2" timeout="${3:-30}"
  local waited=0
  while (( waited < timeout )); do
    if compose logs --no-color --no-log-prefix "$service" 2>/dev/null | grep -Ec "$pattern" >/dev/null; then
      return 0
    fi
    sleep 2
    waited=$(( waited + 2 ))
  done
  return 1
}

# wait_for_container_log_line is wait_for_log_line's twin for a plain
# `docker run` container that isn't part of the compose project (the
# throwaway negative-auth-probe containers assert_auth_handshake starts
# directly on the compose network).
wait_for_container_log_line() {
  local container="$1" pattern="$2" timeout="${3:-30}"
  local waited=0
  while (( waited < timeout )); do
    if docker logs "$container" 2>&1 | grep -Eiq "$pattern"; then
      return 0
    fi
    sleep 2
    waited=$(( waited + 2 ))
  done
  return 1
}
