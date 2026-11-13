#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "::error::$1" >&2
  exit 1
}

coverage_repository="${GITHUB_REPOSITORY:?}"
coverage_run="${GITHUB_RUN_ID:?}"
coverage_attempt="${GITHUB_RUN_ATTEMPT:?}"
coverage_sha="${COVERAGE_EXPECTED_SHA:?}"
[[ $coverage_repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail "Invalid repository"
[[ $coverage_run =~ ^[1-9][0-9]*$ ]] || fail "Invalid run ID"
[[ $coverage_attempt =~ ^[1-9][0-9]*$ ]] || fail "Invalid run attempt"
[[ $coverage_sha =~ ^[a-f0-9]{40}$ ]] || fail "Invalid expected head"

coverage_metadata="$(gh api "repos/${coverage_repository}/actions/runs/${coverage_run}")"
if ! jq -e --arg run "$coverage_run" --arg sha "$coverage_sha" \
  '(.id | tostring) == $run and .head_sha == $sha' <<<"$coverage_metadata" >/dev/null; then
  fail "Run identity does not match the intended coverage commit"
fi

# A selected-job rerun can reuse Build & Test from an earlier attempt. Its
# immutable artifact still belongs to that producer attempt, not this job's.
coverage_pages="$(gh api --paginate --slurp \
  "repos/${coverage_repository}/actions/runs/${coverage_run}/artifacts?per_page=100")"
coverage_selection="$(jq -r \
  --arg run "$coverage_run" --arg sha "$coverage_sha" \
  --arg prefix "go-test-${coverage_run}-" --argjson current "$coverage_attempt" '
	[.[] | .artifacts[]
	 | select(.expired == false)
	 | select((.workflow_run.id | tostring) == $run and .workflow_run.head_sha == $sha)
	 | select(.id | type == "number" and . > 0 and floor == .)
	 | (.name | capture("^" + $prefix + "(?<attempt>[1-9][0-9]*)$")?) as $producer
	 | . + {producer_attempt: ($producer.attempt | tonumber)}
	 | select(.producer_attempt <= $current)]
	| sort_by(.producer_attempt, .id) | last // empty
	| [.id, .name, .producer_attempt] | @tsv
	' <<<"$coverage_pages")"
[[ -n $coverage_selection ]] || fail "No usable Go coverage artifact for the intended run and head"
IFS=$'\t' read -r coverage_id coverage_name coverage_producer <<<"$coverage_selection"
[[ $coverage_id =~ ^[1-9][0-9]*$ ]] || fail "Invalid resolved artifact ID"

{
  printf 'artifact_id=%s\n' "$coverage_id"
  printf 'artifact_name=%s\n' "$coverage_name"
  printf 'producer_attempt=%s\n' "$coverage_producer"
} >>"${GITHUB_OUTPUT:?}"
printf 'Go coverage: %s, producer attempt %s, head %s\n' \
  "$coverage_name" "$coverage_producer" "$coverage_sha"
if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
  printf 'Go coverage artifact: %s (ID %s), producer attempt %s, head %s.\n' \
    "$coverage_name" "$coverage_id" "$coverage_producer" "$coverage_sha" >>"$GITHUB_STEP_SUMMARY"
fi
