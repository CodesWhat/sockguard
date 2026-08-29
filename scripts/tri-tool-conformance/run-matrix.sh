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
# It needs jq and awk only -- no Docker, no network -- and is wired into `npm test`
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

# Every transient err/log/cid file lives under one private mktemp dir: a
# fixed /tmp path could be pre-created by a local user as a symlink before
# the shell redirection opens it.
SCRATCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tri-tool-conformance.XXXXXX")"
trap 'rm -rf "${SCRATCH_DIR}"' EXIT

# busybox pins for the events/logs/lifecycle sentinels and the assertion-8
# (remote update trigger) store-sync sentinel. Only NEW_BUSYBOX_REF matches
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

# Is `codeswhat/sockguard:<version>` actually pullable from Docker Hub?
#
# `docker manifest inspect` rather than the Hub REST API: Docker is already a
# hard dependency of every non-self-test row, it needs no token dance or tag
# pagination, and it resolves the same reference the compose bundle pulls --
# a bare `codeswhat/*` ref is Docker Hub, not GHCR, and the two registries
# diverge.
#
# Three-way result, because "the registry says no" and "we could not ask" are
# different facts and only the first one licenses walking back a version:
#   0 = published, 1 = registry answered and the tag is absent, 2 = query failed
sockguard_tag_is_published() {
  local ref="codeswhat/sockguard:$1" out rc=0
  # `|| rc=$?`, not `if ...; then return 0; fi; rc=$?` -- a failed `if` with no
  # `else` exits 0, so the latter reads every failure as rc 0.
  out="$(docker manifest inspect "$ref" 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    return 0
  fi
  case "$out" in
    *"manifest unknown"*|*"not found"*|*"no such manifest"*) return 1 ;;
  esac
  echo "FATAL: sockguard_tag_is_published: could not query the registry for ${ref} (docker manifest inspect exit ${rc}): ${out}" >&2
  return 2
}

# Resolves "the newest published stable sockguard release", walking local tag
# history newest-first and stopping at the first tag whose image is actually on
# Docker Hub. Tag filtering is the same awk-based prerelease filter as
# release-cut.yml's "Find latest release tag" step (v*-sorted, hyphenated
# prerelease tags dropped), read here at run time instead of computed once in a
# workflow step.
#
# The walk-back exists because a git tag and its published image are not
# simultaneous: `v1.7.1` is pushed minutes before release-from-tag finishes
# publishing `codeswhat/sockguard:1.7.1`, and a release whose publish job
# failed leaves a tag with no image behind indefinitely. Resolving to a tag
# in either window hands the row an unpullable reference. "Current" here means
# the newest sockguard a user can actually pull, not the newest one tagged.
#
# Every skip is announced on stderr -- a silently-skipped tag would hide a
# broken publish, which is the same class of quiet-wrong-version bug this
# function exists to fix (#289 item 2: current-* rows already float
# portwing/drydock to latest, but sockguard silently stayed pinned to the
# legacy-floor default). Likewise both failure modes exit FATAL rather than
# falling back to the audited floor: a checkout missing tag history (e.g. the
# default shallow depth-1 clone) and a registry we cannot reach must both fail
# loudly, not quietly reintroduce that bug by another route.
resolve_latest_sockguard_version() {
  local tags tag version probe_rc skipped=0
  tags="$(git -C "$REPO_ROOT" tag --list 'v*' --sort=-v:refname | awk '!/-/')"
  if [ -z "$tags" ]; then
    echo "FATAL: resolve_latest_sockguard_version: no stable v* tags found in ${REPO_ROOT} -- checkout is missing tag history (needs fetch-depth: 0)" >&2
    exit 1
  fi

  while IFS= read -r tag; do
    [ -n "$tag" ] || continue
    version="${tag#v}"

    # `|| probe_rc=$?` for the same reason as in sockguard_tag_is_published:
    # reading `$?` after a failed `if` would silently yield 0.
    probe_rc=0
    sockguard_tag_is_published "$version" || probe_rc=$?

    if [ "$probe_rc" -eq 0 ]; then
      if [ "$skipped" -gt 0 ]; then
        echo "resolve_latest_sockguard_version: resolved to ${tag} after skipping ${skipped} unpublished tag(s)." >&2
      fi
      echo "$version"
      return 0
    fi

    # rc 2 already printed its own FATAL. Exiting here rather than returning
    # propagates through the `$(...)` the caller reads -- see the call site.
    [ "$probe_rc" -eq 1 ] || exit 1

    echo "WARN: resolve_latest_sockguard_version: ${tag} is tagged in git but codeswhat/sockguard:${version} is not published on Docker Hub -- trying the next older tag. If a release just cut, its publish job may still be running; if not, that release's image push failed." >&2
    skipped=$((skipped + 1))
  done <<<"$tags"

  echo "FATAL: resolve_latest_sockguard_version: no stable v* tag in ${REPO_ROOT} has a published codeswhat/sockguard image on Docker Hub (checked ${skipped} tag(s)) -- refusing to fall back to the legacy floor." >&2
  exit 1
}

# ---------------------------------------------------------------------------
# --self-test: no Docker, no network. Proves the normalizer + diff logic
# that assertion 11 depends on actually work before trusting them in a live
# run, and gives lefthook/CI something to check on every push.
# ---------------------------------------------------------------------------

run_self_test() {
  echo "== run-matrix.sh --self-test: route normalizer + tripwire diff logic =="
  local fixture="${SCRIPT_DIR}/testdata/access-log-fixture.jsonl"
  local known="${SCRIPT_DIR}/known-routes.json"
  local failed=0

  if ! jq empty "$known" 2>"${SCRATCH_DIR}/known-routes-lint.err"; then
    echo "FAIL: known-routes.json is not valid JSON: $(cat "${SCRATCH_DIR}/known-routes-lint.err")" >&2
    return 1
  fi
  echo "PASS: known-routes.json parses as valid JSON"

  local observed
  observed="$(jq -n -R -f "${SCRIPT_DIR}/normalize-routes.jq" "$fixture")" || {
    echo "FAIL: normalize-routes.jq errored against the fixture" >&2
    return 1
  }

  # The fixture (testdata/access-log-fixture.jsonl) has 11 lines: 7 real
  # access-log lines (6 allowed + 1 denied that IS in known-routes.json),
  # 1 deliberately-unknown denied route (GET /containers/*/attach, which is
  # NOT in known-routes.json -- attach is never allowed by any preset and
  # was never added as an expected-denial-probe shape either), 1
  # access-log-shaped line with normalized_path missing entirely, 1
  # non-access-log line (msg=startup), 1 bare-string JSON value (valid JSON,
  # not an object), and 1 line that isn't JSON at all. The three malformed/
  # partial lines prove tolerance (see below); a correct normalizer still
  # yields exactly 6 unique {method,path} shapes from the 7 real lines. The
  # single- and multi-segment image references deliberately collapse to the
  # same /images/**/json policy shape.
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
    "$ACCESS_LOG_ROUTE_MATCH_JQ" "$fixture" 2>"${SCRATCH_DIR}/access-log-match.err")"
  match_status=$?
  if [ "$match_status" -ne 0 ]; then
    echo "FAIL: ACCESS_LOG_ROUTE_MATCH_JQ exited ${match_status} against the fixture's malformed lines: $(cat "${SCRATCH_DIR}/access-log-match.err")" >&2
    failed=1
  elif ! grep -q '"normalized_path": *"/containers/json"' <<<"$match_output"; then
    echo "FAIL: ACCESS_LOG_ROUTE_MATCH_JQ did not find the expected match past the fixture's malformed lines" >&2
    failed=1
  else
    echo "PASS: ACCESS_LOG_ROUTE_MATCH_JQ tolerates missing-normalized_path and bare-string-JSON lines without poisoning the exit status"
  fi

  # Round-6 regression pin: the full matcher pipeline (jq + grep tail) must
  # return success on a stream where the route matches many times. With an
  # early-exiting `grep -q` tail, grep quits on the first match and jq dies
  # on SIGPIPE (141) writing later ones, so under pipefail the wait reported
  # failure precisely when the traffic was healthiest (Portwing polling
  # every 5s -> guaranteed multi-match). The matched output must exceed the
  # 64KB pipe buffer for the SIGPIPE to be deterministic rather than a
  # scheduling race, hence 5000 matches (~450KB) -- verified to exit 141
  # with the old tail on every run, 0 with the read-to-EOF tail.
  local multi_stream multi_status
  multi_stream="$(awk 'BEGIN{
    m="{\"msg\":\"request\",\"method\":\"GET\",\"decision\":\"allow\",\"normalized_path\":\"/containers/json\"}";
    f="{\"msg\":\"request\",\"method\":\"GET\",\"decision\":\"allow\",\"normalized_path\":\"/events\"}";
    for(i=0;i<5000;i++){print m; print f; print f; print f}
  }')"
  access_log_stream_has_route "GET" "allow" '^/containers/json$' <<<"$multi_stream"
  multi_status=$?
  if [ "$multi_status" -ne 0 ]; then
    echo "FAIL: access_log_stream_has_route exited ${multi_status} on a multi-match stream (grep tail must read to EOF -- SIGPIPE regression)" >&2
    failed=1
  else
    echo "PASS: access_log_stream_has_route survives a multi-match stream under pipefail (read-to-EOF tail)"
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

  # resolve_latest_sockguard_version (defined above, alongside
  # sockguard_tag_is_published, so it's callable here) must walk tag history
  # correctly under every shape a registry probe can come back in, without
  # ever making a real network call. Shadow `docker` with a stub selected by
  # $stub_mode and unset it again once this section is done, so nothing
  # later in the script can silently talk to the fake instead of the real
  # docker binary.
  #
  # `git` is stubbed for the same reason `docker` is. Reading the real tag
  # list made this section pass locally and fail in CI, where the Node test
  # gate checks out at the default depth 1 and has no tags at all: every case
  # took the "no stable v* tags found" exit, and none-published still "passed"
  # -- non-zero for entirely the wrong reason. A fixed synthetic list also
  # lets the expectations below be exact constants instead of whatever the
  # newest release happens to be this week, and pins the prerelease filter
  # (v2.1.0-rc.1 must never win).
  local newest_stable="v2.0.0" second_newest_stable="v1.9.0"
  git() {
    if [ "${3:-}" = "tag" ]; then
      printf '%s\n' v2.1.0-rc.1 v2.0.0 v1.9.0 v1.8.0
      return 0
    fi
    command git "$@"
  }

  local stub_mode
  docker() {
    local ver="${3##*:}"
    case "$stub_mode" in
      all-published)
        return 0
        ;;
      newest-missing)
        if [ "v${ver}" = "$newest_stable" ]; then
          echo "no such manifest: docker.io/codeswhat/sockguard:${ver}" >&2
          return 1
        fi
        return 0
        ;;
      registry-down)
        echo 'Get "https://registry-1.docker.io/v2/": dial tcp: i/o timeout' >&2
        return 1
        ;;
      none-published)
        echo "no such manifest: docker.io/codeswhat/sockguard:${ver}" >&2
        return 1
        ;;
    esac
  }

  local resolver_err="${SCRATCH_DIR}/resolve-latest-sockguard-version.err"
  local resolver_out resolver_rc

  stub_mode="all-published"
  resolver_out="$(resolve_latest_sockguard_version 2>"$resolver_err")"
  resolver_rc=$?
  if [ "$resolver_rc" -eq 0 ] && [ "$resolver_out" = "${newest_stable#v}" ]; then
    echo "PASS: resolve_latest_sockguard_version resolves to the newest tag when the registry reports every tag published"
  else
    echo "FAIL: resolve_latest_sockguard_version(all-published) rc=${resolver_rc} out='${resolver_out}', want rc 0 out '${newest_stable#v}'" >&2
    failed=1
  fi

  stub_mode="newest-missing"
  resolver_out="$(resolve_latest_sockguard_version 2>"$resolver_err")"
  resolver_rc=$?
  if [ "$resolver_rc" -eq 0 ] && [ "$resolver_out" = "${second_newest_stable#v}" ] && grep -q "WARN" "$resolver_err"; then
    echo "PASS: resolve_latest_sockguard_version walks back to the next tag and warns on stderr when only the newest is unpublished"
  else
    echo "FAIL: resolve_latest_sockguard_version(newest-missing) rc=${resolver_rc} out='${resolver_out}', want rc 0 out '${second_newest_stable#v}' with WARN on stderr: $(cat "$resolver_err")" >&2
    failed=1
  fi

  stub_mode="registry-down"
  resolver_out="$(resolve_latest_sockguard_version 2>"$resolver_err")"
  resolver_rc=$?
  # No WARN: an unreachable registry must fail on the FIRST tag it checks,
  # not silently walk back through older tags the way an absent-manifest
  # response does -- a walk-back here would eventually hit the same FATAL
  # message anyway (exhausting every tag), so checking for FATAL text alone
  # would not catch a regression that let this case fall into the walk-back
  # path instead of exiting immediately.
  if [ "$resolver_rc" -ne 0 ] && [ -z "$resolver_out" ] && grep -q "FATAL" "$resolver_err" \
      && grep -q -F "could not query the registry" "$resolver_err" && ! grep -q "WARN" "$resolver_err"; then
    echo "PASS: resolve_latest_sockguard_version fails loudly (FATAL, could not query the registry) instead of walking back when the registry is unreachable"
  else
    echo "FAIL: resolve_latest_sockguard_version(registry-down) rc=${resolver_rc} out='${resolver_out}', want a non-zero rc, empty stdout, FATAL/could not query the registry on stderr, and no WARN (no walk-back): $(cat "$resolver_err")" >&2
    failed=1
  fi

  stub_mode="none-published"
  resolver_out="$(resolve_latest_sockguard_version 2>"$resolver_err")"
  resolver_rc=$?
  if [ "$resolver_rc" -ne 0 ] && [ -z "$resolver_out" ] && grep -q -F "no stable v* tag" "$resolver_err"; then
    echo "PASS: resolve_latest_sockguard_version fails when no stable v* tag has a published image"
  else
    echo "FAIL: resolve_latest_sockguard_version(none-published) rc=${resolver_rc} out='${resolver_out}', want a non-zero rc, empty stdout, and 'no stable v* tag' on stderr: $(cat "$resolver_err")" >&2
    failed=1
  fi

  unset -f docker
  unset -f git

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
    STORE_SYNC_TIMEOUT=120
    ;;
  current-edge)
    COMPOSE_FILES=("${BUNDLE_DIR}/docker-compose.edge-exec.yml" "${BUNDLE_DIR}/docker-compose.conformance-overlay.yml")
    MODE="edge"
    PRESET_FILE="sockguard-with-exec.yaml"
    PORTWING_VERSION="${PORTWING_VERSION_INPUT:-latest}"
    DRYDOCK_VERSION="${DRYDOCK_VERSION_INPUT:-latest}"
    EXEC_ROW=1
    # Edge mode ignores the overlay's DD_POLL_INTERVAL=5: Portwing's edge
    # client takes its refresh cadence from the pollInterval in drydock's
    # WebSocket welcome (portwing edge/client.go), and drydock hardcodes
    # that to 300s with no env override (drydock app/api/portwing-ws.ts,
    # `const pollInterval = 300`). A mid-run sentinel can therefore take a
    # full poll cycle to reach drydock's store on this row; 360s covers one
    # 300s cycle plus report/ingest slack.
    STORE_SYNC_TIMEOUT=360
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
    STORE_SYNC_TIMEOUT=120
    ;;
  *)
    echo "run-matrix.sh: unknown --row '${ROW}' (expected current-standard|current-edge|legacy-floor)" >&2
    exit 2
    ;;
esac

# An explicit --sockguard-image/sockguard_image always wins outright, for
# every row, unconditionally -- RELEASING.md's pre-GA gate depends on this
# to test a specific release-candidate ref rather than whatever a row would
# otherwise default to. Below that: legacy-floor keeps the deliberate
# audited-floor 1.5.1 pin (sockguard PR #155 -- see the legacy-floor case
# arm above), while current-standard/current-edge resolve the newest
# published stable release from tag history, the same way they already
# float portwing/drydock to `latest` (#289 item 2). Concrete rather than
# `latest`, unlike the other two tools, so a future failure names exactly
# what it tested instead of "latest" as of an unknown moment -- see the
# sockguard=/portwing=/drydock= log line below.
if [ -n "$SOCKGUARD_IMAGE_INPUT" ]; then
  SOCKGUARD_IMAGE_RESOLVED="$SOCKGUARD_IMAGE_INPUT"
elif [ "$ROW" = "legacy-floor" ]; then
  SOCKGUARD_IMAGE_RESOLVED="codeswhat/sockguard:1.5.1"
else
  # Not `$(...)` inlined directly into the assignment: resolve_latest_sockguard_version's
  # own `exit 1` only kills the command-substitution subshell, not this
  # script, so the failure must be caught explicitly here or a resolver
  # FATAL would silently fall through to an empty version string instead
  # of stopping the row.
  SOCKGUARD_VERSION_RESOLVED="$(resolve_latest_sockguard_version)" || exit 1
  SOCKGUARD_IMAGE_RESOLVED="codeswhat/sockguard:${SOCKGUARD_VERSION_RESOLVED}"
fi
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
IDENTITY_CONTAINERS=()
IDENTITY_EVIDENCE_JSON='{"status":"not-run"}'
CONFORMANCE_LOG_DIR="${REPO_ROOT}/conformance-${ROW}-logs"

echo "== #150 tri-tool conformance: row=${ROW} mode=${MODE} preset=${PRESET_FILE} project=${PROJECT} =="
echo "   sockguard=${SOCKGUARD_IMAGE_RESOLVED} portwing=${PORTWING_IMAGE_RESOLVED} drydock=${DRYDOCK_IMAGE_RESOLVED}"

# shellcheck disable=SC2317,SC2329 # invoked indirectly via `trap cleanup EXIT` below (SC2317 is the pre-0.10 code for SC2329)
cleanup() {
  local id container
  for id in "${SENTINEL_IDS[@]:-}"; do
    if [ -n "$id" ]; then docker rm -f "$id" >/dev/null 2>&1 || true; fi
  done
  for container in ${IDENTITY_CONTAINERS[@]+"${IDENTITY_CONTAINERS[@]}"}; do
    docker rm -f "$container" >/dev/null 2>&1 || true
  done
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  sudo rm -f -- "${BUNDLE_DIR}/portwing_token.txt" "${BUNDLE_DIR}/portwing_ed25519.pem" "${BUNDLE_DIR}/portwing_authorized_keys"
  rm -rf -- "$SCRATCH_DIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Fresh secrets every run (design doc assertion 1: "fresh secrets every run")
# ---------------------------------------------------------------------------

# A killed local run can leave these files owned by the container UID. Clear
# only the three fixed harness paths before recreating them so a retry cannot
# inherit credentials or fail its first redirect with EACCES.
sudo rm -f -- "${BUNDLE_DIR}/portwing_token.txt" "${BUNDLE_DIR}/portwing_ed25519.pem" "${BUNDLE_DIR}/portwing_authorized_keys"

if [ "$MODE" = "standard" ]; then
  openssl rand -hex 32 > "${BUNDLE_DIR}/portwing_token.txt"
  # BOTH sides of the handshake read this one file via the compose `secrets:`
  # bind: portwing as UID 65532 (docker-compose.yml's `user: "65532:65532"`)
  # and drydock as its runtime user `node` (UID/GID 1000 -- the entrypoint
  # su-execs before the app ever reads DD_AGENT_PORTWING_SECRET__FILE). So
  # owner 65532 gets the read bit and group 1000 gets the group-read bit:
  # 65532:1000 mode 0440. Anything tighter (65532:65532 0400) locks drydock
  # out with EACCES and surfaces as a bogus auth-handshake timeout -- exactly
  # what the first live run of this matrix hit. Every step here is checked
  # explicitly rather than just `&&`-chaining: a setup failure needs to read
  # as exactly that, not surface later as a misleading handshake failure.
  if ! sudo chown 65532:1000 "${BUNDLE_DIR}/portwing_token.txt"; then
    echo "FATAL: could not chown portwing_token.txt to 65532:1000 (portwing's UID, drydock's node GID) -- setup error, not a conformance failure" >&2
    exit 1
  fi
  if ! sudo chmod 0440 "${BUNDLE_DIR}/portwing_token.txt"; then
    echo "FATAL: could not chmod portwing_token.txt to 0440 -- setup error, not a conformance failure" >&2
    exit 1
  fi
else
  if ! docker run --rm "$PORTWING_IMAGE_RESOLVED" keygen -comment "tri-tool-conformance-${ROW}" \
      > "${BUNDLE_DIR}/portwing_ed25519.pem" 2>"${SCRATCH_DIR}/keygen.err"; then
    echo "FATAL: could not generate Portwing Ed25519 keypair from ${PORTWING_IMAGE_RESOLVED}: $(cat "${SCRATCH_DIR}/keygen.err")" >&2
    exit 1
  fi
  # Lock the private key down BEFORE deriving the public key: the shell
  # redirect above writes the pem with the runner's default umask (0644),
  # and portwing's own key loader refuses to load a group/world-readable
  # private key -- the first live run of this matrix died right here with
  # "unsafe permissions". 65532 is both the keygen container's user and the
  # compose-run portwing user, so one chown serves the derivation and the
  # actual row. Every chown/chmod checked explicitly (not `&&`-chained
  # without a check) so a setup failure here fails the row with a clear
  # setup-error message instead of surfacing later as a confusing
  # auth-handshake failure.
  if ! sudo chown 65532:65532 "${BUNDLE_DIR}/portwing_ed25519.pem"; then
    echo "FATAL: could not chown portwing_ed25519.pem to 65532:65532 (the UID portwing runs as) -- setup error, not a conformance failure" >&2
    exit 1
  fi
  if ! sudo chmod 0400 "${BUNDLE_DIR}/portwing_ed25519.pem"; then
    echo "FATAL: could not chmod portwing_ed25519.pem to 0400 -- setup error, not a conformance failure" >&2
    exit 1
  fi
  if ! docker run --rm -v "${BUNDLE_DIR}/portwing_ed25519.pem:/key.pem:ro" "$PORTWING_IMAGE_RESOLVED" \
      keygen -pub-from /key.pem -comment "tri-tool-conformance-${ROW}" \
      > "${BUNDLE_DIR}/portwing_authorized_keys" 2>"${SCRATCH_DIR}/keygen-pub.err"; then
    echo "FATAL: could not derive the authorized_keys line: $(cat "${SCRATCH_DIR}/keygen-pub.err")" >&2
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
  if ! docker pull "$busybox_ref" >"${SCRATCH_DIR}/busybox-pull.log" 2>&1; then
    echo "FATAL: could not pre-pull ${busybox_ref}: $(tail -c 2000 "${SCRATCH_DIR}/busybox-pull.log")" >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Helpers used by more than one assertion
# ---------------------------------------------------------------------------

# shellcheck disable=SC2317,SC2329 # invoked indirectly via `wait_until ... sockguard_ping_ok` (SC2317 is the pre-0.10 code for SC2329)
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
# shellcheck disable=SC2317,SC2329 # invoked indirectly via `wait_until ... sentinel_state_matches` (SC2317 is the pre-0.10 code for SC2329)
sentinel_state_matches() {
  [ "$(docker inspect --format '{{.State.Status}}' "$PRIMARY_SENTINEL_ID" 2>/dev/null)" = "$WANT_STATE" ]
}

# ---------------------------------------------------------------------------
# Assertion 1: pristine boot
# ---------------------------------------------------------------------------

assert_pristine_boot() {
  local name="pristine-boot"
  compose down -v --remove-orphans >/dev/null 2>&1 || true

  if ! compose up -d sockguard portwing drydock probe >"${SCRATCH_DIR}/compose-up.log" 2>&1; then
    record_result "$name" FAIL "docker compose up failed: $(tail -c 2000 "${SCRATCH_DIR}/compose-up.log")"
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
  # mktemp creates the file 0600 owned by the runner, but the throwaway
  # drydock reads it as its node user (UID 1000) -- without this it EACCESes
  # before ever sending a request and the probe times out instead of seeing
  # a 401 (the second live matrix run failed exactly here). The value is
  # deliberately-wrong garbage, so world-readable is fine.
  chmod 0644 "$wrong_secret_file"
  bad_container="tt-conf-badsecret-$$"

  if ! docker run -d --name "$bad_container" --network "$net" \
      -v "${wrong_secret_file}:/run/secrets/portwing_token:ro" \
      -e DD_LOCAL_WATCHER=false \
      -e DD_ANONYMOUS_AUTH_CONFIRM=true \
      -e DD_AGENT_PORTWING_HOST=portwing \
      -e DD_AGENT_PORTWING_PORT=4000 \
      -e DD_AGENT_PORTWING_SECRET__FILE=/run/secrets/portwing_token \
      -e DD_AGENT_ALLOW_INSECURE_SECRET=true \
      "$DRYDOCK_IMAGE_RESOLVED" >"${SCRATCH_DIR}/badsecret.cid" 2>"${SCRATCH_DIR}/badsecret.err"; then
    record_result "$name" FAIL "could not start the throwaway wrong-secret agent-config probe: $(cat "${SCRATCH_DIR}/badsecret.err")"
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

  if ! docker run --rm "$PORTWING_IMAGE_RESOLVED" keygen -comment "$agent_name" > "$key_file" 2>"${SCRATCH_DIR}/badkey-gen.err"; then
    record_result "$name" FAIL "could not generate the throwaway unregistered keypair: $(cat "${SCRATCH_DIR}/badkey-gen.err")"
    rm -f "$key_file"
    return 1
  fi
  # mktemp's 0600-owned-by-runner default locks out the throwaway portwing,
  # which reads the key as UID 65532 -- chown so the probe fails on the
  # unregistered KEY, not on an unreadable file. Mode stays 0600 (portwing's
  # loader refuses group/world-readable private keys).
  if ! sudo chown 65532:65532 "$key_file"; then
    record_result "$name" FAIL "could not chown the throwaway key to 65532:65532 -- setup error, not a conformance failure"
    rm -f "$key_file"
    return 1
  fi

  # ALLOW_INSECURE_EDGE_URL: the plaintext drydock URL over the private compose
  # network is by design; current portwing refuses it without this opt-in and
  # would fail to load config before ever reaching the unknown-key rejection
  # this probe exists to observe.
  if ! docker run -d --name "$bad_container" --network "$net" \
      -v "${vol}:/var/run/sockguard:ro" \
      -v "${key_file}:/run/secrets/portwing_key:ro" \
      -e DOCKER_SOCKET=/var/run/sockguard/sockguard.sock \
      -e AGENT_NAME="$agent_name" \
      -e DRYDOCK_URL=http://drydock:3000 \
      -e ALLOW_INSECURE_EDGE_URL=true \
      -e PRIVATE_KEY_FILE=/run/secrets/portwing_key \
      "$PORTWING_IMAGE_RESOLVED" >"${SCRATCH_DIR}/badkey.cid" 2>"${SCRATCH_DIR}/badkey-run.err"; then
    record_result "$name" FAIL "could not start the throwaway unknown-key agent-config probe: $(cat "${SCRATCH_DIR}/badkey-run.err")"
    sudo rm -f -- "$key_file"
    return 1
  fi

  # drydock rejects an unknown key by sending an error frame to the CLIENT
  # and closing the socket -- it logs nothing server-side (verified against
  # drydock's portwing-ws sendErrorAndClose). The rejection evidence lives
  # in the throwaway portwing's own logs: "controller rejected hello ...
  # (unknown-key)" (pinned against live portwing 0.9.2 / drydock latest).
  # Require BOTH terms on one line: a bare alternation would also match a
  # bad-signature rejection, which is a different failure (registered key
  # not matching the private key) than the unregistered-key case this probe
  # exists to pin.
  local ok=1
  wait_for_container_log_line "$bad_container" "rejected hello.*unknown-key" 30 && ok=0
  docker rm -f "$bad_container" >/dev/null 2>&1 || true
  # sudo: the key file was chowned to 65532 above, and /tmp's sticky bit
  # blocks the runner from unlinking a file it no longer owns.
  sudo rm -f -- "$key_file"

  if [ "$ok" -eq 0 ]; then
    record_result "$name" PASS "throwaway agent config with an unregistered Ed25519 key had its hello rejected (unknown-key), matching the documented failure mode"
  else
    record_result "$name" FAIL "throwaway unknown-key probe never logged a rejected hello within 30s"
  fi
}

assert_auth_handshake() {
  local name="auth-handshake"
  # The success log line is mode-specific: standard mode's HTTP poller logs
  # "Handshake successful. Received N containers." (AgentClient), while the
  # edge WS server logs "Edge agent connected: portwing-edge-<id> (...)"
  # (portwing-ws) and never emits the standard line. Both pinned against
  # live drydock during the second live matrix run's diagnosis.
  local expect='Handshake successful'
  if [ "$MODE" != "standard" ]; then
    expect='Edge agent connected'
  fi
  if ! wait_for_log_line drydock "$expect" 90; then
    record_result "$name" FAIL "drydock never logged '${expect}' for the portwing agent within 90s"
    # The row is about to abort -- without these dumps the job log has no
    # way to tell an auth failure from a crash-loop from a network problem
    # (the first live run of this matrix was undiagnosable from CI alone).
    echo "---- drydock logs (last 40 lines) ----"
    compose logs --tail 40 drydock 2>&1 || true
    echo "---- portwing logs (last 40 lines) ----"
    compose logs --tail 40 portwing 2>&1 || true
    echo "---- sockguard logs (last 20 lines) ----"
    compose logs --tail 20 sockguard 2>&1 || true
    return 1
  fi
  record_result "$name" PASS "drydock logged '${expect}' for the portwing agent"

  if [ "$MODE" = "standard" ]; then
    assert_standard_wrong_secret_probe
  else
    assert_edge_unknown_key_probe
  fi
}

# ---------------------------------------------------------------------------
# Tagged-artifact identity acceptance (current-standard only)
#
# This is a second, isolated Standard-mode Portwing + drydock pairing on the
# row's real compose network and sockguard socket. It runs the exact published
# Portwing and drydock images resolved for the row. The harness only provisions
# credentials and edits the operator-owned authorized_keys file; every
# authenticated request and retry comes from a real drydock controller.
# ---------------------------------------------------------------------------

IDENTITY_AGENT=""
IDENTITY_DIR=""
IDENTITY_AGENT_DIR=""
IDENTITY_CONTROLLER_DIR=""

# shellcheck disable=SC2317,SC2329 # invoked indirectly via wait_until
identity_agent_ready() {
  docker exec "$IDENTITY_AGENT" wget -q --spider http://127.0.0.1:4100/health >/dev/null 2>&1
}

identity_generate_key() {
  local label="$1" private_file="$2" public_file="$3" raw_file
  raw_file="${private_file}.raw"
  if ! (umask 077; docker run --rm "$PORTWING_IMAGE_RESOLVED" keygen -comment "$label" > "$raw_file" 2>"${raw_file}.err"); then
    rm -f -- "$raw_file" "${raw_file}.err" "$private_file" "$public_file"
    return 1
  fi
  if ! (umask 077; sed -n '/-----BEGIN PRIVATE KEY-----/,/-----END PRIVATE KEY-----/p' "$raw_file" > "$private_file") \
      || [ ! -s "$private_file" ]; then
    rm -f -- "$raw_file" "${raw_file}.err" "$private_file" "$public_file"
    return 1
  fi
  if ! sudo chown 65532:65532 "$private_file" || ! sudo chmod 0400 "$private_file"; then
    rm -f -- "$raw_file" "${raw_file}.err" "$private_file" "$public_file"
    return 1
  fi
  if ! docker run --rm -v "${private_file}:/key.pem:ro" "$PORTWING_IMAGE_RESOLVED" \
      keygen -pub-from /key.pem -comment "$label" > "$public_file" 2>"${public_file}.err"; then
    rm -f -- "$raw_file" "${raw_file}.err" "$private_file" "$public_file" "${public_file}.err"
    return 1
  fi
  rm -f -- "$raw_file" "${raw_file}.err" "${public_file}.err"
  # drydock drops to UID 1000 before it resolves SIGNINGKEY__FILE.
  if ! sudo chown 1000:1000 "$private_file" || ! sudo chmod 0400 "$private_file"; then
    return 1
  fi
  return 0
}

identity_key_id() {
  local public_file="$1" encoded
  encoded="$(awk 'NF >= 2 && $1 == "ed25519" { print $2; exit }' "$public_file")"
  if [ -z "$encoded" ]; then
    return 1
  fi
  printf '%s' "$encoded" \
    | openssl base64 -d -A \
    | openssl dgst -sha256 -binary \
    | od -An -tx1 \
    | tr -d ' \n' \
    | cut -c1-16
}

identity_enroll() {
  local secret="$1" public_file="$2" request response
  request="$(jq -n --arg secret "$secret" --arg public_key "$(awk 'NF >= 2 && $1 == "ed25519" { print $2; exit }' "$public_file")" \
    '{enrollment_token:$secret,public_key:$public_key}')"
  response="$(compose exec -T probe curl --silent --show-error --max-time 10 \
    -X POST -H 'Content-Type: application/json' -d "$request" \
    --write-out '\n%{http_code}' "http://${IDENTITY_AGENT}:4100/api/portwing/enroll" 2>/dev/null)" || return 1
  IDENTITY_ENROLL_STATUS="$(tail -n 1 <<<"$response")"
  IDENTITY_ENROLL_BODY="$(sed '$d' <<<"$response")"
}

identity_replace_registry() {
  local source_public_file="$1"
  rm -f -- "${IDENTITY_AGENT_DIR}/authorized_keys.next"
  cp "$source_public_file" "${IDENTITY_AGENT_DIR}/authorized_keys.next"
  sudo chown "65532:${IDENTITY_RUNNER_GID}" "${IDENTITY_AGENT_DIR}/authorized_keys.next" || return 1
  sudo chmod 0640 "${IDENTITY_AGENT_DIR}/authorized_keys.next" || return 1
  mv -f -- "${IDENTITY_AGENT_DIR}/authorized_keys.next" "${IDENTITY_AGENT_DIR}/authorized_keys"
}

identity_append_registry() {
  local public_file="$1"
  rm -f -- "${IDENTITY_AGENT_DIR}/authorized_keys.next"
  cp "${IDENTITY_AGENT_DIR}/authorized_keys" "${IDENTITY_AGENT_DIR}/authorized_keys.next"
  sed -n '1p' "$public_file" >> "${IDENTITY_AGENT_DIR}/authorized_keys.next"
  sudo chown "65532:${IDENTITY_RUNNER_GID}" "${IDENTITY_AGENT_DIR}/authorized_keys.next" || return 1
  sudo chmod 0640 "${IDENTITY_AGENT_DIR}/authorized_keys.next" || return 1
  mv -f -- "${IDENTITY_AGENT_DIR}/authorized_keys.next" "${IDENTITY_AGENT_DIR}/authorized_keys"
}

identity_start_controller() {
  local container="$1" key_id="$2" private_file="$3" offset_file="${4:-}"
  local -a args=(run -d --name "$container" --network "$IDENTITY_NETWORK"
    -v "${private_file}:/run/secrets/identity_key:ro"
    -e DD_LOCAL_WATCHER=false
    -e DD_ANONYMOUS_AUTH_CONFIRM=true
    -e DD_AGENT_IDENTITY_HOST="$IDENTITY_AGENT"
    -e DD_AGENT_IDENTITY_PORT=4100
    -e DD_AGENT_IDENTITY_AUTHMODE=ed25519
    -e DD_AGENT_IDENTITY_SIGNINGKEYID="$key_id"
    -e DD_AGENT_IDENTITY_SIGNINGKEY__FILE=/run/secrets/identity_key)
  if [ -n "$offset_file" ]; then
    args+=(-v "${SCRIPT_DIR}/controller-clock-offset.cjs:/opt/tri-tool/controller-clock-offset.cjs:ro")
    args+=(-v "${offset_file}:/run/tri-tool/clock-offset:ro")
    args+=(-e NODE_OPTIONS=--require=/opt/tri-tool/controller-clock-offset.cjs)
    args+=(-e TT_CLOCK_OFFSET_FILE=/run/tri-tool/clock-offset)
  fi
  args+=("$DRYDOCK_IMAGE_RESOLVED")
  if ! docker "${args[@]}" >"${SCRATCH_DIR}/${container}.cid" 2>"${SCRATCH_DIR}/${container}.err"; then
    return 1
  fi
  IDENTITY_CONTAINERS+=("$container")
}

identity_reason_count() {
  local reason="$1"
  docker logs "$IDENTITY_AGENT" 2>&1 | grep -Fic "\"reason\":\"${reason}\"" || true
}

assert_identity_acceptance() {
  local skip_detail="the five-operation identity gate runs once against the current published Standard-mode pair"
  if [ "$ROW" != "current-standard" ]; then
    record_result "identity-enrollment" SKIP "$skip_detail"
    record_result "identity-overlapping-key-rotation" SKIP "$skip_detail"
    record_result "identity-revocation" SKIP "$skip_detail"
    record_result "identity-sighup-reload" SKIP "$skip_detail"
    record_result "identity-clock-skew-recovery" SKIP "$skip_detail"
    return 0
  fi

  local old_private old_public new_private new_public rejected_public
  local old_key_id new_key_id enrollment_secret wrong_secret
  local old_controller new_controller skew_controller
  local old_handshakes new_handshakes reloads_before reloads_after
  local unknown_before unknown_after skew_before skew_after
  local old_restart_count new_restart_count skew_restart_count

  IDENTITY_DIR="${SCRATCH_DIR}/identity"
  IDENTITY_AGENT_DIR="${IDENTITY_DIR}/agent"
  IDENTITY_CONTROLLER_DIR="${IDENTITY_DIR}/controller"
  mkdir -p "$IDENTITY_AGENT_DIR" "$IDENTITY_CONTROLLER_DIR"
  old_private="${IDENTITY_CONTROLLER_DIR}/old.pem"
  old_public="${IDENTITY_CONTROLLER_DIR}/old.pub"
  new_private="${IDENTITY_CONTROLLER_DIR}/new.pem"
  new_public="${IDENTITY_CONTROLLER_DIR}/new.pub"
  rejected_public="$new_public"
  old_controller="${PROJECT}-identity-old"
  new_controller="${PROJECT}-identity-new"
  skew_controller="${PROJECT}-identity-skew"
  IDENTITY_AGENT="${PROJECT}-identity-agent"
  IDENTITY_CONTAINERS+=("$IDENTITY_AGENT")
  IDENTITY_NETWORK="$(docker network ls --filter "label=com.docker.compose.project=${PROJECT}" --format '{{.Name}}' | head -1)"
  IDENTITY_SOCKET_VOLUME="$(docker volume ls --filter "label=com.docker.compose.project=${PROJECT}" --format '{{.Name}}' | grep 'sockguard-socket$' | head -1)"

  if [ -z "$IDENTITY_NETWORK" ] || [ -z "$IDENTITY_SOCKET_VOLUME" ]; then
    record_result "identity-enrollment" FAIL "could not resolve the row's compose network or sockguard socket volume"
    skip_detail="identity setup failed before the published controller could enroll"
    for identity_name in identity-overlapping-key-rotation identity-revocation identity-sighup-reload identity-clock-skew-recovery; do
      record_result "$identity_name" SKIP "$skip_detail"
    done
    return 1
  fi

  if ! identity_generate_key "tri-tool-controller-old" "$old_private" "$old_public" \
      || ! identity_generate_key "tri-tool-controller-new" "$new_private" "$new_public"; then
    record_result "identity-enrollment" FAIL "published Portwing keygen could not prepare the controller credentials"
    skip_detail="identity key generation failed"
    for identity_name in identity-overlapping-key-rotation identity-revocation identity-sighup-reload identity-clock-skew-recovery; do
      record_result "$identity_name" SKIP "$skip_detail"
    done
    return 1
  fi

  old_key_id="$(identity_key_id "$old_public")"
  new_key_id="$(identity_key_id "$new_public")"
  IDENTITY_RUNNER_GID="$(id -g)"
  enrollment_secret="$(openssl rand -hex 32)"
  wrong_secret="$(openssl rand -hex 32)"
  : > "${IDENTITY_AGENT_DIR}/authorized_keys"
  printf '%s\n' "$enrollment_secret" > "${IDENTITY_AGENT_DIR}/enrollment_secret"
  sudo chown "65532:${IDENTITY_RUNNER_GID}" "${IDENTITY_AGENT_DIR}/authorized_keys"
  sudo chown 65532:65532 "${IDENTITY_AGENT_DIR}/enrollment_secret"
  sudo chmod 0640 "${IDENTITY_AGENT_DIR}/authorized_keys"
  sudo chmod 0400 "${IDENTITY_AGENT_DIR}/enrollment_secret"

  if ! docker run -d --name "$IDENTITY_AGENT" --network "$IDENTITY_NETWORK" \
      --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
      -v "${IDENTITY_SOCKET_VOLUME}:/var/run/sockguard:ro" \
      -v "${IDENTITY_AGENT_DIR}:/run/identity" \
      -e DOCKER_SOCKET=/var/run/sockguard/sockguard.sock \
      -e PORT=4100 \
      -e AGENT_NAME=tri-tool-identity-agent \
      -e AUTHORIZED_KEYS=/run/identity/authorized_keys \
      -e ENROLLMENT_TOKEN_FILE=/run/identity/enrollment_secret \
      "$PORTWING_IMAGE_RESOLVED" >"${SCRATCH_DIR}/identity-agent.cid" 2>"${SCRATCH_DIR}/identity-agent.err"; then
    record_result "identity-enrollment" FAIL "could not start the published Portwing identity agent: $(cat "${SCRATCH_DIR}/identity-agent.err")"
    skip_detail="identity agent startup failed"
    for identity_name in identity-overlapping-key-rotation identity-revocation identity-sighup-reload identity-clock-skew-recovery; do
      record_result "$identity_name" SKIP "$skip_detail"
    done
    return 1
  fi
  if ! wait_until 30 2 identity_agent_ready; then
    record_result "identity-enrollment" FAIL "published Portwing identity agent never became healthy"
    skip_detail="identity agent health check failed"
    for identity_name in identity-overlapping-key-rotation identity-revocation identity-sighup-reload identity-clock-skew-recovery; do
      record_result "$identity_name" SKIP "$skip_detail"
    done
    return 1
  fi

  # Negative control 1: a wrong enrollment credential returns 401 but does not
  # burn the single-use credential. The correct enrollment immediately after it
  # must succeed, and its key id must match the published keygen output.
  identity_enroll "$wrong_secret" "$rejected_public" || true
  local wrong_status="$IDENTITY_ENROLL_STATUS" wrong_body="$IDENTITY_ENROLL_BODY"
  identity_enroll "$enrollment_secret" "$old_public" || true
  local enrolled_status="$IDENTITY_ENROLL_STATUS" enrolled_body="$IDENTITY_ENROLL_BODY"
  local enrolled_key_id
  enrolled_key_id="$(jq -r '.key_id // empty' <<<"$enrolled_body" 2>/dev/null)"
  identity_enroll "$enrollment_secret" "$rejected_public" || true
  local reused_status="$IDENTITY_ENROLL_STATUS" reused_body="$IDENTITY_ENROLL_BODY"

  if [ "$wrong_status" != "401" ] || [ "$enrolled_status" != "200" ] \
      || [ "$enrolled_key_id" != "$old_key_id" ] || [ "$reused_status" != "401" ] \
      || ! grep -Eiq 'already used' <<<"$reused_body"; then
    record_result "identity-enrollment" FAIL "enrollment controls failed: wrong=${wrong_status} (${wrong_body}), correct=${enrolled_status} (${enrolled_body}), reuse=${reused_status} (${reused_body})"
    skip_detail="one-shot enrollment did not pass its positive and negative controls"
    for identity_name in identity-overlapping-key-rotation identity-revocation identity-sighup-reload identity-clock-skew-recovery; do
      record_result "$identity_name" SKIP "$skip_detail"
    done
    return 1
  fi
  if ! identity_start_controller "$old_controller" "$old_key_id" "$old_private" \
      || ! wait_for_container_log_count "$old_controller" 'Handshake successful' 1 90; then
    record_result "identity-enrollment" FAIL "the real published drydock controller did not authenticate with the freshly enrolled key"
    skip_detail="the enrolled controller never completed a signed handshake"
    for identity_name in identity-overlapping-key-rotation identity-revocation identity-sighup-reload identity-clock-skew-recovery; do
      record_result "$identity_name" SKIP "$skip_detail"
    done
    return 1
  fi
  record_result "identity-enrollment" PASS "wrong credential denied 401 without burning enrollment; the enrolled key authenticated a published drydock controller; reuse denied 401 as already used"

  # Add the replacement key, signal the live Portwing process, then prove both
  # old and new published controllers can complete fresh handshakes during the
  # overlap. Fresh handshake counts prevent pre-reload logs from passing.
  reloads_before="$(docker logs "$IDENTITY_AGENT" 2>&1 | grep -Ec 'SIGHUP: authorized_keys reloaded' || true)"
  old_handshakes="$(docker logs "$old_controller" 2>&1 | grep -Ec 'Handshake successful' || true)"
  if ! identity_append_registry "$new_public" \
      || ! docker kill --signal HUP "$IDENTITY_AGENT" >/dev/null \
      || ! wait_for_container_log_count "$IDENTITY_AGENT" 'SIGHUP: authorized_keys reloaded' "$((reloads_before + 1))" 30 \
      || ! identity_start_controller "$new_controller" "$new_key_id" "$new_private" \
      || ! wait_for_container_log_count "$new_controller" 'Handshake successful' 1 90 \
      || ! docker restart "$old_controller" >/dev/null \
      || ! wait_for_container_log_count "$old_controller" 'Handshake successful' "$((old_handshakes + 1))" 90; then
    record_result "identity-overlapping-key-rotation" FAIL "both controller keys did not authenticate after the additive SIGHUP reload"
  else
    record_result "identity-overlapping-key-rotation" PASS "old and new published drydock controllers each completed a fresh signed handshake after the additive reload"
  fi

  # Revoke the old key with a second atomic file replacement + SIGHUP. The old
  # controller must fail with the same `unknown-key` reason Portwing returns in
  # X-Portwing-Reason, while a fresh new-key handshake must still succeed.
  reloads_before="$(docker logs "$IDENTITY_AGENT" 2>&1 | grep -Ec 'SIGHUP: authorized_keys reloaded' || true)"
  unknown_before="$(identity_reason_count unknown-key)"
  new_handshakes="$(docker logs "$new_controller" 2>&1 | grep -Ec 'Handshake successful' || true)"
  if ! identity_replace_registry "$new_public" \
      || ! docker kill --signal HUP "$IDENTITY_AGENT" >/dev/null \
      || ! wait_for_container_log_count "$IDENTITY_AGENT" 'SIGHUP: authorized_keys reloaded' "$((reloads_before + 1))" 30 \
      || ! docker restart "$old_controller" >/dev/null \
      || ! wait_for_container_log_count "$IDENTITY_AGENT" '"reason":"unknown-key"' "$((unknown_before + 1))" 60 \
      || ! docker restart "$new_controller" >/dev/null \
      || ! wait_for_container_log_count "$new_controller" 'Handshake successful' "$((new_handshakes + 1))" 90; then
    record_result "identity-revocation" FAIL "the revoked controller was not rejected as unknown-key while the retained controller stayed healthy"
  else
    record_result "identity-revocation" PASS "old-key controller rejected with X-Portwing-Reason=unknown-key; retained new-key controller completed a fresh handshake"
  fi

  reloads_after="$(docker logs "$IDENTITY_AGENT" 2>&1 | grep -Ec 'SIGHUP: authorized_keys reloaded' || true)"
  old_restart_count="$(docker inspect --format '{{.RestartCount}}' "$IDENTITY_AGENT" 2>/dev/null || echo unknown)"
  if [ "$reloads_after" -ge 2 ] && [ "$old_restart_count" = "0" ]; then
    record_result "identity-sighup-reload" PASS "two key-registry reloads completed in the original Portwing process (restart count 0)"
  else
    record_result "identity-sighup-reload" FAIL "reload count=${reloads_after}, Portwing restart count=${old_restart_count}; want at least two reloads without restart"
  fi

  # Fault injection stays inside the real published drydock controller: the
  # preload changes only Date.now(), which v1.6.0's signer uses for
  # X-Portwing-Timestamp. The same live process must first be rejected with
  # X-Portwing-Reason=timestamp-skew, then recover after the offset file returns
  # to zero. No handcrafted signed request bypasses the controller.
  printf '%s\n' -120 > "${IDENTITY_CONTROLLER_DIR}/clock-offset"
  chmod 0444 "${IDENTITY_CONTROLLER_DIR}/clock-offset"
  skew_before="$(identity_reason_count timestamp-skew)"
  if ! identity_start_controller "$skew_controller" "$new_key_id" "$new_private" "${IDENTITY_CONTROLLER_DIR}/clock-offset" \
      || ! wait_for_container_log_count "$IDENTITY_AGENT" '"reason":"timestamp-skew"' "$((skew_before + 1))" 60; then
    record_result "identity-clock-skew-recovery" FAIL "the clock-faulted published controller was not rejected with timestamp-skew"
  else
    chmod 0644 "${IDENTITY_CONTROLLER_DIR}/clock-offset"
    printf '%s\n' 0 > "${IDENTITY_CONTROLLER_DIR}/clock-offset"
    if wait_for_container_log_count "$skew_controller" 'Handshake successful' 1 120; then
      skew_restart_count="$(docker inspect --format '{{.RestartCount}}' "$skew_controller" 2>/dev/null || echo unknown)"
      if [ "$skew_restart_count" = "0" ]; then
        record_result "identity-clock-skew-recovery" PASS "same published controller rejected with X-Portwing-Reason=timestamp-skew, then completed a handshake after its clock recovered (restart count 0)"
      else
        record_result "identity-clock-skew-recovery" FAIL "controller recovered only after restart count changed to ${skew_restart_count}"
      fi
    else
      record_result "identity-clock-skew-recovery" FAIL "same controller stayed unauthenticated for 120s after its injected clock offset returned to zero"
    fi
  fi

  unknown_after="$(identity_reason_count unknown-key)"
  skew_after="$(identity_reason_count timestamp-skew)"
  new_restart_count="$(docker inspect --format '{{.RestartCount}}' "$new_controller" 2>/dev/null || echo unknown)"
  IDENTITY_EVIDENCE_JSON="$(jq -n \
    --arg old_key_id "$old_key_id" --arg new_key_id "$new_key_id" \
    --argjson reloads "$reloads_after" --argjson unknown_key_rejections "$unknown_after" \
    --argjson timestamp_skew_rejections "$skew_after" --arg retained_controller_restarts "$new_restart_count" \
    '{status:"exercised",old_key_id:$old_key_id,new_key_id:$new_key_id,sighup_reloads:$reloads,unknown_key_rejections:$unknown_key_rejections,timestamp_skew_rejections:$timestamp_skew_rejections,retained_controller_restarts:$retained_controller_restarts}')"
}

# ---------------------------------------------------------------------------
# Assertion 4: inventory & inspect (passive -- see README "Verification
# strategy" for why this and the assertions below key on sockguard's own
# access log rather than guessing at Portwing/drydock's private API shapes)
# ---------------------------------------------------------------------------

assert_inventory_inspect() {
  # 120s window. Historical note: the 2026-08-09 gate runs appeared to show
  # this traffic landing outside a 30s window; round 6 proved the routes
  # were in the log all along and the WAIT was broken (grep -q SIGPIPE
  # under pipefail whenever the route matched more than once -- see the
  # ACCESS_LOG_ROUTE_MATCH_JQ comment in lib.sh). 120s stays as headroom
  # for genuinely slow first polls; the scan is cumulative so a healthy
  # row still passes on its first iteration.
  local name="inventory-inspect"
  local list_ok=1 inspect_ok=1
  wait_for_access_log_route GET allow '^/containers/json$' 120 && list_ok=0
  wait_for_access_log_route GET allow '^/containers/[^/]+/json$' 120 && inspect_ok=0

  if [ "$list_ok" -eq 0 ] && [ "$inspect_ok" -eq 0 ]; then
    record_result "$name" PASS "Portwing's own list+inspect polling reached sockguard (allowed GET /containers/json and GET /containers/*/json observed)"
  else
    record_result "$name" FAIL "did not observe both an allowed GET /containers/json and GET /containers/*/json in sockguard's access log within 120s"
  fi
}

# ---------------------------------------------------------------------------
# Assertion 5: events -- create/remove a sentinel via the proxied socket
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

  # Probe GET /events directly rather than waiting for it in the access log:
  # sockguard only writes an access-log line when a request completes, and
  # the events stream outlives the row, so the old wait could never succeed
  # (#211, verified against both the 1.5.1 and 1.6.0-rc.1 images). curl's
  # --write-out still prints the received status when --max-time cuts the
  # stream, so a 200 here proves the preset admits the channel.
  local events_ok=1 events_status
  events_status="$(probe_curl_status "http://localhost/events" || true)"
  [ "$events_status" = "200" ] && events_ok=0

  probe_curl -X POST "http://localhost/containers/${id}/stop?t=5" >/dev/null
  probe_curl -X DELETE "http://localhost/containers/${id}?force=true" >/dev/null

  local removed_ok=1
  wait_for_access_log_route DELETE allow '^/containers/[^/]+$' 15 && removed_ok=0

  if [ "$events_ok" -eq 0 ] && [ "$removed_ok" -eq 0 ]; then
    record_result "$name" PASS "sentinel created/started/stopped/removed via the proxied socket; /events stream opened with a 200 and DELETE allowed"
  else
    record_result "$name" FAIL "events stream open or the sentinel's DELETE was not observed allowed (events_status=${events_status:-none} removed_ok=${removed_ok})"
  fi
}

# ---------------------------------------------------------------------------
# Assertion 6: logs -- fetch logs for a running container through the
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
# Assertion 7: lifecycle -- stop/start/restart, verify state converges
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
# Assertion 8: configured exec (current-edge only)
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
# Assertion 9: remote update trigger -- store sync through sockguard plus the
# documented unconfigured-trigger refusal, identical on every row
# ---------------------------------------------------------------------------

assert_remote_update_trigger() {
  local name="remote-update-trigger"

  # Contract pinned from live runs (#211) plus a local repro against the
  # published pair (2026-08-09). Two facts bound what this assertion can
  # honestly claim, on EVERY row:
  #
  #   1. GET /api/v1/containers returns a paginated envelope {data: [...]}
  #      on both drydock latest and the 1.5.2 legacy pin (v1.5.2
  #      app/api/container/crud-context.ts ContainerListResponse) -- the
  #      earlier bare-array read made this poll return empty forever. The
  #      unversioned /api/containers alias used before
  #      (CodesWhat/drydock#802) 410s as of drydock v1.6.0
  #      (app/api/index.ts sendUnversionedApiTombstone) --
  #      it was NEVER a drydock sync regression, just this harness polling
  #      a removed alias and silently discarding the resulting jq error.
  #   2. The audited tri-tool bundle configures NO docker update trigger in
  #      drydock, so a correctly-shaped POST /api/v1/triggers/docker/update
  #      with drydock's own store {id} is refused on every drydock version.
  #      1.5.2 refuses it 404 "trigger not found"; 1.6.x gets one step
  #      further and refuses it 400 "No update available for this
  #      container", which still means it accepted the request shape.
  #      There is no topology in this bundle where updates flow: drydock's
  #      watch-now delegates registry checks to the Portwing agent, whose
  #      watcher endpoint answers 501 "registry checking is performed by
  #      the Drydock controller" (portwing
  #      internal/adapter/drydock/routes.go), so updateAvailable can never
  #      flip either. A malformed body is a different 400, "Invalid trigger
  #      request body" -- reading the body rather than the bare status is
  #      what keeps that distinction, and what proves the request shape is
  #      right.
  #
  # So the end-to-end proof this row CAN give: the sentinel created through
  # sockguard's proxied socket reaches drydock's store via Portwing's
  # sockguard-mediated inventory sync (presence), and a correctly-shaped
  # trigger invocation reaches drydock's trigger API and is refused, as
  # unconfigured (404 "trigger not found") or as having nothing to update
  # (400 "no update available") -- the documented boundary for the audited
  # bundle. Both accepted refusals are matched on the response BODY, not on
  # the status alone: a wrong trigger URL also answers 404, so a bare-status
  # check would let this assertion pass while testing nothing, which is the
  # exact shape of the bug that hid in the store poll above. A 2xx means an
  # UNCONFIGURED trigger executed (alarming, fail); anything else, including
  # any other 400, is a fail that prints the status and body.
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

  # Resolve the sentinel's drydock-side container document from the
  # paginated store envelope. Presence proves the sockguard-mediated sync
  # path end to end; ?limit=500 keeps the sentinel on page one even on a
  # busy daemon.
  # STORE_SYNC_TIMEOUT is per-row: 120s where the overlay's DD_POLL_INTERVAL=5
  # applies (standard mode), 360s on current-edge where drydock's welcome
  # pins the poll cycle at 300s (see the row-configuration comment).
  # Wall-clock deadline, not iteration counting: each iteration can spend up
  # to 10s inside curl --max-time on top of the 5s sleep, so counting
  # iterations would let a stalled store consume ~3x the advertised window.
  local doc="" dd_id="" dd_agent="" remaining
  local containers_body="${SCRATCH_DIR}/containers-response.json"
  local containers_status containers_jq_err
  local deadline=$(( SECONDS + STORE_SYNC_TIMEOUT ))
  while (( SECONDS < deadline )); do
    if ! containers_status="$(curl --silent --max-time 10 --output "$containers_body" \
        --write-out '%{http_code}' "http://127.0.0.1:3000/api/v1/containers?limit=500" 2>"${SCRATCH_DIR}/containers-curl-err.log")"; then
      # curl itself failed to get a response at all (connection refused,
      # timeout, etc) -- transient, keep polling like before rather than
      # failing on the first hiccup.
      remaining=$(( deadline - SECONDS ))
      (( remaining <= 0 )) && break
      sleep $(( remaining < 5 ? remaining : 5 ))
      continue
    fi
    case "$containers_status" in
      2??)
        ;;
      *)
        # drydock answered, just not with success -- this is drydock (or
        # the harness's URL for it) misbehaving, not "sentinel not synced
        # yet". Fail loudly now instead of retrying an error into a
        # timeout that looks identical to a real sync failure.
        #
        # No 5xx-is-transient carve-out on purpose: assert_auth_handshake
        # has already waited up to 90s for drydock to log the portwing
        # agent authenticating, and that's the same express app serving
        # this route, so warm-up is over by the time this runs. Retrying a
        # 5xx here would re-hide exactly the class of error this branch
        # exists to surface.
        record_result "$name" FAIL "harness error, not a conformance failure -- GET /api/v1/containers returned ${containers_status}: $(head -c 300 "$containers_body" 2>/dev/null)"
        return 1
        ;;
    esac
    # /api/v1/containers answers 2xx with the {data: [...]} envelope (drydock
    # app/api/container/crud-context.ts ContainerListResponse), so assert that
    # shape rather than tolerating anything else. `.data[]?` on its own would
    # swallow a missing, null, or scalar `.data` and hand back an empty result
    # with exit 0 -- a 2xx error envelope would then decay into the same
    # "sentinel never appeared" timeout this whole branch exists to stop. An
    # empty `.data` array is NOT that case: it's the normal not-synced-yet
    # state and still polls to the deadline.
    if ! doc="$(jq -c --arg n "$sentinel" \
        'if (.data | type) != "array" then
           error("expected a data array, got \(.data | type)")
         else
           [.data[] | select((.name // "") == $n or (.name // "") == ("/" + $n))] | first // empty
         end' \
        "$containers_body" 2>"${SCRATCH_DIR}/containers-jq-err.log")"; then
      containers_jq_err="$(cat "${SCRATCH_DIR}/containers-jq-err.log" 2>/dev/null)"
      record_result "$name" FAIL "harness bug, not a conformance failure -- jq could not read the /api/v1/containers response (${containers_jq_err}): $(head -c 300 "$containers_body" 2>/dev/null)"
      return 1
    fi
    if [ -n "$doc" ]; then
      break
    fi
    remaining=$(( deadline - SECONDS ))
    (( remaining <= 0 )) && break
    sleep $(( remaining < 5 ? remaining : 5 ))
  done
  if [ -z "$doc" ]; then
    record_result "$name" FAIL "sentinel never appeared in drydock's /api/v1/containers store within ${STORE_SYNC_TIMEOUT}s"
    return 1
  fi
  dd_id="$(jq -r '.id // empty' <<<"$doc")"
  dd_agent="$(jq -r '.agent // empty' <<<"$doc")"
  if [ -z "$dd_id" ]; then
    record_result "$name" FAIL "drydock container document for the sentinel has no id: $(head -c 300 <<<"$doc")"
    return 1
  fi

  local trigger_url="http://127.0.0.1:3000/api/v1/triggers/docker/update"
  if [ -n "$dd_agent" ]; then
    trigger_url="${trigger_url}/${dd_agent}"
  fi

  local trigger_status
  trigger_status="$(curl --silent --show-error --max-time 30 --output "${SCRATCH_DIR}/trigger-response.json" --write-out '%{http_code}' \
    -X POST -H 'Content-Type: application/json' \
    -d "$(jq -c '{id: .id} + (if .agent then {agent: .agent} else {} end)' <<<"$doc")" \
    "$trigger_url" 2>/dev/null)"

  case "$trigger_status" in
    404)
      # Body-checked for the same reason the 400 arm below is: a bare status
      # is not evidence. A wrong trigger URL -- exactly the bug that hid here
      # for a month -- also answers 404, so accepting any 404 would let this
      # assertion pass while testing nothing.
      #
      # The pattern is `trigger <something> not found`, not the literal
      # "trigger not found" the README used to claim. drydock 1.5.2 actually
      # answers {"error":"Remote update trigger portwing.docker.update not
      # found"} (run 32323163685), and the middle is the agent-qualified
      # trigger name, so it varies with the row. Requiring the word "trigger"
      # before "not found" is what keeps a bare {"error":"Not Found"} from
      # an unrouted request out.
      if jq -e '(.error // "") | test("trigger .*not found"; "i")' \
          "${SCRATCH_DIR}/trigger-response.json" >/dev/null 2>&1; then
        record_result "$name" PASS "sentinel synced into drydock's store through sockguard-mediated Portwing polling; a correctly-shaped trigger invocation was refused as unconfigured (404: $(jq -r '.error' "${SCRATCH_DIR}/trigger-response.json" 2>/dev/null)) -- the audited bundle's documented boundary"
      else
        record_result "$name" FAIL "trigger invocation returned 404 but not drydock's unconfigured-trigger refusal -- most likely a wrong trigger URL rather than a conformance failure; body: $(head -c 300 "${SCRATCH_DIR}/trigger-response.json" 2>/dev/null)"
      fi
      ;;
    2*)
      record_result "$name" FAIL "an update trigger the audited bundle never configures ACCEPTED the invocation (${trigger_status}) -- the documented boundary no longer holds; body: $(head -c 300 "${SCRATCH_DIR}/trigger-response.json" 2>/dev/null)"
      ;;
    400)
      # drydock 1.6.x refuses the same invocation 400 "No update available for
      # this container" where 1.5.2 refused it 404 "trigger not found". Both
      # are the audited bundle's documented boundary reached by different
      # routes: 1.6.x gets far enough to evaluate the container and find
      # nothing to update, which means it accepted the request shape. Matching
      # on the body rather than on the drydock version keeps this assertion
      # version-agnostic, and keeps a bare 400 -- drydock's "Invalid trigger
      # request body" -- a shape regression, which is the thing this arm was
      # written to catch.
      if jq -e '(.error // "") | test("no update available"; "i")' \
          "${SCRATCH_DIR}/trigger-response.json" >/dev/null 2>&1; then
        record_result "$name" PASS "sentinel synced into drydock's store through sockguard-mediated Portwing polling; a correctly-shaped trigger invocation was refused with no update available (400) -- the audited bundle's documented boundary"
      else
        record_result "$name" FAIL "trigger invocation was refused 400 -- the request shape regressed (want 404 'trigger not found' or 400 'no update available'); body: $(head -c 300 "${SCRATCH_DIR}/trigger-response.json" 2>/dev/null)"
      fi
      ;;
    *)
      # 501 used to sit in the accepting arm alongside 404, unvalidated. No
      # row has ever returned it: the 2026-08-20 run recorded 404 on
      # legacy-floor (drydock 1.5.2) and 400 on both current-* rows (1.6.x).
      # The 501 in the bundle README is Portwing's own trigger endpoint, a
      # different service from the drydock:3000 API this posts to. Failing
      # here prints the status and body, so a real 501 becomes a pinnable
      # fact rather than a silent pass on a status nobody has observed.
      record_result "$name" FAIL "trigger invocation returned ${trigger_status} (body: $(head -c 300 "${SCRATCH_DIR}/trigger-response.json" 2>/dev/null)), want 404 'trigger not found' or 400 'no update available'"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Assertion 10: expected denials
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
# Assertion 11: route-drift tripwire
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

capture_conformance_logs() {
  local container
  if [ -d "$CONFORMANCE_LOG_DIR" ]; then
    find "$CONFORMANCE_LOG_DIR" -type f -delete
  fi
  mkdir -p "$CONFORMANCE_LOG_DIR"
  compose logs --no-color > "${CONFORMANCE_LOG_DIR}/compose.log" 2>&1 || true
  for container in ${IDENTITY_CONTAINERS[@]+"${IDENTITY_CONTAINERS[@]}"}; do
    docker logs "$container" > "${CONFORMANCE_LOG_DIR}/${container}.log" 2>&1 || true
  done
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
    --argjson identity "$IDENTITY_EVIDENCE_JSON" \
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
      identity: $identity,
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
  assert_identity_acceptance
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

  for skipped in identity-enrollment identity-overlapping-key-rotation identity-revocation identity-sighup-reload identity-clock-skew-recovery; do
    record_result "$skipped" SKIP "row aborted after pristine-boot/auth-handshake failure"
  done

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
capture_conformance_logs
resolve_metadata
write_artifact

echo "== #150 tri-tool conformance: row=${ROW} $( [ "$ROW_FAILED" -eq 0 ] && echo PASS || echo FAIL ) =="
exit "$ROW_FAILED"
