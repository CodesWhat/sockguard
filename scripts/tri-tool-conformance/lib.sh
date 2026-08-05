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
# Compose / docker plumbing
# ---------------------------------------------------------------------------

# compose_cmd echoes the base `docker compose` invocation for the current
# row (project name + -f flags already applied) so callers can append
# subcommands: `$(compose_cmd) up -d sockguard portwing drydock probe`.
# COMPOSE_FILES is an array set by run-matrix.sh per row.
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
wait_for_access_log_route() {
  local method="$1" decision="$2" path_regex="$3" timeout="${4:-30}"
  local waited=0
  while (( waited < timeout )); do
    if sockguard_access_log | jq -R \
        --arg m "$method" --arg d "$decision" --arg p "$path_regex" \
        '(try fromjson catch empty)
         | select(.msg=="request" or .msg=="request_denied" or .msg=="request_would_deny")
         | select(.method==$m and ((.decision // "allow")==$d) and (.normalized_path|test($p)))' \
        2>/dev/null | grep -q .; then
      return 0
    fi
    sleep 2
    waited=$(( waited + 2 ))
  done
  return 1
}

# wait_for_log_line polls `docker compose logs <service>` for a line
# matching an extended-regex pattern within timeout seconds.
wait_for_log_line() {
  local service="$1" pattern="$2" timeout="${3:-30}"
  local waited=0
  while (( waited < timeout )); do
    if compose logs --no-color --no-log-prefix "$service" 2>/dev/null | grep -Eq "$pattern"; then
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
