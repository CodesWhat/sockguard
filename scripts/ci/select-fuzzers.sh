#!/usr/bin/env bash
set -euo pipefail
# Print the fuzzers-json value for a pull request: only the fuzzers whose
# package directory holds a file the PR changed.
#
#   select-fuzzers.sh <base-ref> <fuzzer-list.json>
#
# Every uncertain path fails OPEN and prints the full list: an unreadable
# base ref, a failed diff, an empty diff, or a change to something that
# affects every fuzzer (the Go module files, the CI caller, the list itself,
# this script, or the fuzz runner). Output is one compact JSON line.

base_ref="${1:?usage: select-fuzzers.sh <base-ref> <fuzzer-list.json>}"
list_path="${2:?usage: select-fuzzers.sh <base-ref> <fuzzer-list.json>}"

full_list() {
  jq -c . "${list_path}"
}

fail_open() {
  echo "::warning::select-fuzzers: $1, running every fuzzer" >&2
  full_list
  exit 0
}

# Validate the list up front; without it there is nothing to select from.
jq -e 'type == "array"' "${list_path}" >/dev/null || {
  echo "::error::select-fuzzers: ${list_path} is not a readable JSON array" >&2
  exit 1
}

changed=""
if ! changed="$(git diff --name-only "${base_ref}...HEAD" 2>/dev/null)"; then
  fail_open "git diff against ${base_ref} failed"
fi
[ -n "${changed}" ] || fail_open "empty diff against ${base_ref}"

while IFS= read -r file; do
  case "${file}" in
    go.mod | go.sum | .github/workflows/ci-verify.yml | .github/ci-fuzzers.json | scripts/ci/select-fuzzers.sh | scripts/ci/go-fuzz.sh)
      echo "select-fuzzers: ${file} affects every fuzzer" >&2
      full_list
      exit 0
      ;;
  esac
done <<<"${changed}"

selected=""
while IFS= read -r pkg; do
  dir="app/${pkg#./}"
  dir="${dir%/}/"
  if printf '%s\n' "${changed}" | awk -v d="${dir}" 'index($0, d) == 1 { found = 1 } END { exit !found }'; then
    selected+="${pkg}"$'\n'
  fi
done < <(jq -r '.[].pkg' "${list_path}" | sort -u)

pkgs="$(printf '%s' "${selected}" | jq -Rn '[inputs | select(length > 0)]')"
jq -c --argjson pkgs "${pkgs}" '[.[] | select(.pkg as $p | $pkgs | index($p))]' "${list_path}"
