#!/usr/bin/env bash
# Run Sockguard fuzzers locally in isolated copies of the repository.
#
# The script intentionally avoids running fuzz in the working tree. Go writes
# minimized failures under testdata/fuzz/<Fuzzer>/, so each fuzzer gets a clean
# copy and any failures are collected into an artifact directory.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FUZZTIME="2m"
TEST_TIMEOUT=""
SUITE="ci"
JOBS="0"
GO_PARALLEL=""
GO_BIN=""
USE_DOCKER="0"
DOCKER_IMAGE="golang:1.26.2"
PLATFORM=""
ARTIFACT_ROOT=""
KEEP_WORK="0"
DRY_RUN="0"

# shellcheck source=scripts/fuzz-duration.sh
source "$REPO_ROOT/scripts/fuzz-duration.sh"

usage() {
  cat <<'EOF'
Usage: scripts/local-fuzz.sh [options]

Options:
  --suite NAME       Fuzzer suite: ci, proxy, filter, config, response, all, ultra (default: ci)
  --fuzztime DURATION
                     Per-fuzzer budget passed to go test -fuzztime (default: 2m)
  --timeout DURATION Go test watchdog. Defaults to fuzztime + 10m.
  --jobs N           Number of fuzzers to run in parallel (default: min(fuzzers, 4))
  --parallel N       Workers per go test fuzz process (default: Go test default)
  --docker           Run each fuzzer inside a golang Docker image
  --platform VALUE   Docker platform, for example linux/amd64
  --image VALUE      Docker image to use with --docker (default: golang:1.26.2)
  --artifacts DIR    Directory for logs and failing corpora (default: .fuzz-artifacts/<timestamp>)
  --keep-work        Keep temporary isolated repository copies
  --dry-run          Print planned commands without copying or running fuzzers
  -h, --help         Show this help

Examples:
  scripts/local-fuzz.sh --suite proxy --fuzztime 5m
  scripts/local-fuzz.sh --docker --platform linux/amd64 --suite ci --fuzztime 15m
  scripts/local-fuzz.sh --suite ultra --fuzztime 1h --timeout 1h15m --jobs 1
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

find_go() {
  local candidate
  if candidate="$(command -v go 2>/dev/null)"; then
    printf '%s\n' "$candidate"
    return 0
  fi
  for candidate in /opt/homebrew/bin/go /usr/local/go/bin/go /usr/local/bin/go; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite)
      [[ $# -ge 2 ]] || die "--suite requires a value"
      SUITE="$2"
      shift 2
      ;;
    --fuzztime)
      [[ $# -ge 2 ]] || die "--fuzztime requires a value"
      FUZZTIME="$2"
      shift 2
      ;;
    --timeout)
      [[ $# -ge 2 ]] || die "--timeout requires a value"
      TEST_TIMEOUT="$2"
      shift 2
      ;;
    --jobs)
      [[ $# -ge 2 ]] || die "--jobs requires a value"
      JOBS="$2"
      shift 2
      ;;
    --parallel)
      [[ $# -ge 2 ]] || die "--parallel requires a value"
      GO_PARALLEL="$2"
      shift 2
      ;;
    --docker)
      USE_DOCKER="1"
      shift
      ;;
    --platform)
      [[ $# -ge 2 ]] || die "--platform requires a value"
      PLATFORM="$2"
      shift 2
      ;;
    --image)
      [[ $# -ge 2 ]] || die "--image requires a value"
      DOCKER_IMAGE="$2"
      shift 2
      ;;
    --artifacts)
      [[ $# -ge 2 ]] || die "--artifacts requires a value"
      ARTIFACT_ROOT="$2"
      shift 2
      ;;
    --keep-work)
      KEEP_WORK="1"
      shift
      ;;
    --dry-run)
      DRY_RUN="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option $1"
      ;;
  esac
done

case "$JOBS" in
  ''|*[!0-9]*) die "--jobs must be a positive integer" ;;
esac

if [[ -n "$GO_PARALLEL" ]]; then
  case "$GO_PARALLEL" in
    ''|*[!0-9]*) die "--parallel must be a positive integer" ;;
  esac
  if [[ "$GO_PARALLEL" -lt 1 ]]; then
    die "--parallel must be a positive integer"
  fi
fi

if ! fuzz_duration_to_seconds "$FUZZTIME" >/dev/null; then
  die "--fuzztime must use h/m/s components, for example 60s, 15m, or 1h30m"
fi
if [[ -z "$TEST_TIMEOUT" ]]; then
  TEST_TIMEOUT="$(fuzz_timeout_for_budget "$FUZZTIME")" || die "failed to derive --timeout from --fuzztime"
elif ! fuzz_duration_to_seconds "$TEST_TIMEOUT" >/dev/null; then
  die "--timeout must use h/m/s components, for example 10m, 1h15m, or 2h"
fi

declare -a ENTRIES=()

add_entry() {
  ENTRIES+=("$1|$2")
}

add_ci_entries() {
  add_entry "FuzzPathMatch" "./internal/filter/"
  add_entry "FuzzGlobToRegex" "./internal/filter/"
  add_entry "FuzzNormalizePath" "./internal/filter/"
  add_entry "FuzzCompileRule" "./internal/filter/"
  add_entry "FuzzLoadYAML" "./internal/config/"
  add_entry "FuzzProxyHeadersAndBody" "./internal/proxy/"
  add_entry "FuzzHijackHeadersAndBody" "./internal/proxy/"
  add_entry "FuzzHijackBidirectionalStream" "./internal/proxy/"
}

add_proxy_entries() {
  add_entry "FuzzProxyHeadersAndBody" "./internal/proxy/"
  add_entry "FuzzHijackHeadersAndBody" "./internal/proxy/"
  add_entry "FuzzHijackBidirectionalStream" "./internal/proxy/"
}

add_filter_entries() {
  add_entry "FuzzPathMatch" "./internal/filter/"
  add_entry "FuzzGlobToRegex" "./internal/filter/"
  add_entry "FuzzNormalizePath" "./internal/filter/"
  add_entry "FuzzCompileRule" "./internal/filter/"
  add_entry "FuzzBuild" "./internal/filter/"
  add_entry "FuzzContainerCreate" "./internal/filter/"
  add_entry "FuzzExec" "./internal/filter/"
  add_entry "FuzzImagePull" "./internal/filter/"
  add_entry "FuzzVolume" "./internal/filter/"
  add_entry "FuzzSecret" "./internal/filter/"
  add_entry "FuzzConfigWrite" "./internal/filter/"
  add_entry "FuzzService" "./internal/filter/"
  add_entry "FuzzSwarm" "./internal/filter/"
  add_entry "FuzzPlugin" "./internal/filter/"
}

case "$SUITE" in
  ci)
    add_ci_entries
    ;;
  proxy)
    add_proxy_entries
    ;;
  filter)
    add_filter_entries
    ;;
  config)
    add_entry "FuzzLoadYAML" "./internal/config/"
    ;;
  response)
    add_entry "FuzzFilterModifyResponse" "./internal/responsefilter/"
    ;;
  all|ultra)
    add_filter_entries
    add_entry "FuzzLoadYAML" "./internal/config/"
    add_proxy_entries
    add_entry "FuzzFilterModifyResponse" "./internal/responsefilter/"
    ;;
  *)
    die "unknown suite \"$SUITE\""
    ;;
esac

if [[ "$JOBS" -eq 0 ]]; then
  JOBS="${#ENTRIES[@]}"
  if [[ "$JOBS" -gt 4 ]]; then
    JOBS="4"
  fi
fi

if [[ "$JOBS" -lt 1 ]]; then
  die "--jobs must be a positive integer"
fi

native_command_text() {
  local fuzzer="$1"
  local pkg="$2"
  printf "go test -run='^$' -fuzz='^%s$' -fuzztime=%s -timeout=%s" "$fuzzer" "$FUZZTIME" "$TEST_TIMEOUT"
  if [[ -n "$GO_PARALLEL" ]]; then
    printf " -parallel=%s" "$GO_PARALLEL"
  fi
  printf " %s" "$pkg"
}

docker_command_text() {
  local fuzzer="$1"
  local pkg="$2"
  local repo_path="${3:-<isolated-repo>}"
  local platform_args=()
  if [[ -n "$PLATFORM" ]]; then
    platform_args=(--platform "$PLATFORM")
  fi
  printf "docker run --rm"
  if [[ "${#platform_args[@]}" -gt 0 ]]; then
    printf " %s %s" "${platform_args[0]}" "${platform_args[1]}"
  fi
  printf " -v '%s:/src' -w /src/app -e GOTOOLCHAIN=local %s sh -lc " \
    "$repo_path" \
    "$DOCKER_IMAGE"
  printf "\"/usr/local/go/bin/go test -run='^$' -fuzz='^%s$' -fuzztime='%s' -timeout='%s'" \
    "$fuzzer" \
    "$FUZZTIME" \
    "$TEST_TIMEOUT"
  if [[ -n "$GO_PARALLEL" ]]; then
    printf " -parallel='%s'" "$GO_PARALLEL"
  fi
  printf " '%s'\"" "$pkg"
}

if [[ "$DRY_RUN" = "1" ]]; then
  echo "suite: $SUITE"
  echo "fuzztime: $FUZZTIME"
  echo "timeout: $TEST_TIMEOUT"
  echo "jobs: $JOBS"
  if [[ -n "$GO_PARALLEL" ]]; then
    echo "parallel: $GO_PARALLEL"
  fi
  echo "runner: $([[ "$USE_DOCKER" = "1" ]] && echo docker || echo native)"
  echo
  for entry in "${ENTRIES[@]}"; do
    fuzzer="${entry%%|*}"
    pkg="${entry#*|}"
    echo "[$fuzzer] $pkg"
    if [[ "$USE_DOCKER" = "1" ]]; then
      docker_command_text "$fuzzer" "$pkg"
    else
      native_command_text "$fuzzer" "$pkg"
    fi
    echo
  done
  exit 0
fi

if [[ "$USE_DOCKER" = "1" ]]; then
  command -v docker >/dev/null 2>&1 || die "docker is required for --docker"
else
  GO_BIN="$(find_go)" || die "go is required for native fuzzing"
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$ARTIFACT_ROOT" ]]; then
  ARTIFACT_ROOT="$REPO_ROOT/.fuzz-artifacts/$timestamp"
fi
ARTIFACT_ROOT="$(mkdir -p "$ARTIFACT_ROOT" && cd "$ARTIFACT_ROOT" && pwd)"

if [[ "$USE_DOCKER" = "1" ]]; then
  mkdir -p "$REPO_ROOT/.fuzz-artifacts/.work"
  WORK_ROOT="$(mktemp -d "$REPO_ROOT/.fuzz-artifacts/.work/$timestamp.XXXXXX")"
else
  WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/sockguard-local-fuzz.XXXXXX")"
fi
cleanup_work_root() {
  if [[ -d "$WORK_ROOT" ]]; then
    chmod -R u+w "$WORK_ROOT" 2>/dev/null || true
    rm -rf "$WORK_ROOT"
  fi
}

if [[ "$KEEP_WORK" != "1" ]]; then
  trap cleanup_work_root EXIT
fi

copy_repo() {
  local dest="$1"
  mkdir -p "$dest"
  (
    cd "$REPO_ROOT"
    COPYFILE_DISABLE=1 tar \
      --exclude='.git' \
      --exclude='.fuzz-artifacts' \
      --exclude='node_modules' \
      --exclude='website/.next' \
      --exclude='website/out' \
      --exclude='docs/.next' \
      --exclude='docs/out' \
      -cf - .
  ) | (
    cd "$dest"
    tar -xf -
  )
}

run_native_fuzzer() {
  local repo="$1"
  local fuzzer="$2"
  local pkg="$3"
  (
    cd "$repo/app"
    mkdir -p "$repo/.gocache" "$repo/.gomodcache" "$repo/.gotmp"
    env \
      GOCACHE="$repo/.gocache" \
      GOMODCACHE="$repo/.gomodcache" \
      GOTMPDIR="$repo/.gotmp" \
      GOFLAGS="-mod=readonly" \
      "$GO_BIN" test \
        -run='^$' \
        -fuzz="^${fuzzer}$" \
        -fuzztime="$FUZZTIME" \
        -timeout="$TEST_TIMEOUT" \
        ${GO_PARALLEL:+-parallel="$GO_PARALLEL"} \
        "$pkg"
  )
}

run_docker_fuzzer() {
  local repo="$1"
  local fuzzer="$2"
  local pkg="$3"
  docker run --rm ${PLATFORM:+--platform "$PLATFORM"} \
    -v "$repo:/src" \
    -w /src/app \
    -e GOTOOLCHAIN=local \
    "$DOCKER_IMAGE" \
    sh -lc "mkdir -p /tmp/sockguard-fuzz-cache && /usr/local/go/bin/go test -run='^$' -fuzz='^${fuzzer}$' -fuzztime='${FUZZTIME}' -timeout='${TEST_TIMEOUT}' ${GO_PARALLEL:+-parallel='${GO_PARALLEL}'} '${pkg}'"
}

replay_native_input() {
  local repo="$1"
  local fuzzer="$2"
  local pkg="$3"
  local input="$4"
  (
    cd "$repo/app"
    env GOFLAGS="-mod=readonly" "$GO_BIN" test -run="^${fuzzer}/$(basename "$input")$" "$pkg" -count=1 -v
  )
}

replay_docker_input() {
  local repo="$1"
  local fuzzer="$2"
  local pkg="$3"
  local input="$4"
  if [[ -n "$PLATFORM" ]]; then
    docker run --rm --platform "$PLATFORM" \
      -v "$repo:/src" \
      -w /src/app \
      -e GOTOOLCHAIN=local \
      "$DOCKER_IMAGE" \
      sh -lc "/usr/local/go/bin/go test -run='^${fuzzer}/$(basename "$input")$' '${pkg}' -count=1 -v"
  else
    docker run --rm \
      -v "$repo:/src" \
      -w /src/app \
      -e GOTOOLCHAIN=local \
      "$DOCKER_IMAGE" \
      sh -lc "/usr/local/go/bin/go test -run='^${fuzzer}/$(basename "$input")$' '${pkg}' -count=1 -v"
  fi
}

collect_and_replay() {
  local repo="$1"
  local fuzzer="$2"
  local pkg="$3"
  local out_dir="$4"
  local corpus_root="$out_dir/corpus"
  mkdir -p "$corpus_root"

  local found=0
  while IFS= read -r input; do
    found=1
    local rel="${input#"$repo/app/"}"
    local dest="$corpus_root/$rel"
    mkdir -p "$(dirname "$dest")"
    cp "$input" "$dest"

    local replay_log
    replay_log="$out_dir/replay-$(basename "$input").log"
    if [[ "$USE_DOCKER" = "1" ]]; then
      if replay_docker_input "$repo" "$fuzzer" "$pkg" "$input" >"$replay_log" 2>&1; then
        echo "replay $(basename "$input"): PASS" >>"$out_dir/summary.txt"
      else
        echo "replay $(basename "$input"): FAIL" >>"$out_dir/summary.txt"
      fi
    else
      if replay_native_input "$repo" "$fuzzer" "$pkg" "$input" >"$replay_log" 2>&1; then
        echo "replay $(basename "$input"): PASS" >>"$out_dir/summary.txt"
      else
        echo "replay $(basename "$input"): FAIL" >>"$out_dir/summary.txt"
      fi
    fi
  done < <(find "$repo/app/internal" -path "*/testdata/fuzz/$fuzzer/*" -type f 2>/dev/null | sort)

  if [[ "$found" -eq 0 ]]; then
    echo "no corpus files found for $fuzzer" >>"$out_dir/summary.txt"
  fi
}

run_one() {
  local entry="$1"
  local index="$2"
  local fuzzer="${entry%%|*}"
  local pkg="${entry#*|}"
  local safe_name
  safe_name="$(printf '%s' "$fuzzer" | tr -c 'A-Za-z0-9_.-' '_')"
  local work="$WORK_ROOT/$index-$safe_name"
  local repo="$work/repo"
  local out_dir="$ARTIFACT_ROOT/$safe_name"
  mkdir -p "$out_dir"

  {
    echo "fuzzer: $fuzzer"
    echo "package: $pkg"
    echo "fuzztime: $FUZZTIME"
    echo "timeout: $TEST_TIMEOUT"
    echo "runner: $([[ "$USE_DOCKER" = "1" ]] && echo docker || echo native)"
    if [[ -n "$GO_PARALLEL" ]]; then
      echo "parallel: $GO_PARALLEL"
    fi
    if [[ "$USE_DOCKER" = "1" && -n "$PLATFORM" ]]; then
      echo "platform: $PLATFORM"
    fi
    echo
  } >"$out_dir/summary.txt"

  copy_repo "$repo"

  local command_log="$out_dir/command.txt"
  if [[ "$USE_DOCKER" = "1" ]]; then
    docker_command_text "$fuzzer" "$pkg" "$repo" >"$command_log"
  else
    native_command_text "$fuzzer" "$pkg" >"$command_log"
  fi

  local fuzz_log="$out_dir/fuzz.log"
  echo "[$fuzzer] start"
  if [[ "$USE_DOCKER" = "1" ]]; then
    if run_docker_fuzzer "$repo" "$fuzzer" "$pkg" >"$fuzz_log" 2>&1; then
      echo "result: PASS" >>"$out_dir/summary.txt"
      echo "[$fuzzer] PASS"
      return 0
    fi
  else
    if run_native_fuzzer "$repo" "$fuzzer" "$pkg" >"$fuzz_log" 2>&1; then
      echo "result: PASS" >>"$out_dir/summary.txt"
      echo "[$fuzzer] PASS"
      return 0
    fi
  fi

  echo "result: FAIL" >>"$out_dir/summary.txt"
  collect_and_replay "$repo" "$fuzzer" "$pkg" "$out_dir"
  echo "[$fuzzer] FAIL (see $out_dir)"
  return 1
}

echo "Artifacts: $ARTIFACT_ROOT"
echo "Work root:  $WORK_ROOT"
echo "Suite:      $SUITE (${#ENTRIES[@]} fuzzers)"
echo "Fuzztime:   $FUZZTIME"
echo "Timeout:    $TEST_TIMEOUT"
echo "Jobs:       $JOBS"
if [[ -n "$GO_PARALLEL" ]]; then
  echo "Parallel:   $GO_PARALLEL"
fi
echo "Runner:     $([[ "$USE_DOCKER" = "1" ]] && echo docker || echo native)"
echo

declare -a PIDS=()
declare -a PID_NAMES=()

for i in "${!ENTRIES[@]}"; do
  while [[ "$(jobs -pr | wc -l | tr -d ' ')" -ge "$JOBS" ]]; do
    sleep 0.2
  done
  run_one "${ENTRIES[$i]}" "$i" &
  PIDS+=("$!")
  PID_NAMES+=("${ENTRIES[$i]%%|*}")
done

failed=0
for i in "${!PIDS[@]}"; do
  if ! wait "${PIDS[$i]}"; then
    echo "failure: ${PID_NAMES[$i]}" >&2
    failed=1
  fi
done

{
  echo "# Sockguard local fuzz summary"
  echo
  echo "- Suite: $SUITE"
  echo "- Fuzztime: $FUZZTIME"
  echo "- Timeout: $TEST_TIMEOUT"
  echo "- Runner: $([[ "$USE_DOCKER" = "1" ]] && echo docker || echo native)"
  echo "- Jobs: $JOBS"
  if [[ -n "$GO_PARALLEL" ]]; then
    echo "- Parallel: $GO_PARALLEL"
  fi
  echo
  for dir in "$ARTIFACT_ROOT"/*; do
    [[ -d "$dir" ]] || continue
    echo "## $(basename "$dir")"
    sed 's/^/- /' "$dir/summary.txt"
    echo
  done
} >"$ARTIFACT_ROOT/summary.md"

echo
echo "Summary: $ARTIFACT_ROOT/summary.md"

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi
