#!/usr/bin/env bash
set -euo pipefail

module_directory="${MODULE_DIRECTORY:-app}"
fuzzer="${FUZZER:-}"
package="${PKG:-}"

if [ -z "${fuzzer}" ]; then
  echo "FUZZER is required" >&2
  exit 2
fi
if [ -z "${package}" ]; then
  echo "PKG is required" >&2
  exit 2
fi

repository_root="$(pwd -P)"
artifact_directory="${repository_root}/artifacts/go-fuzz/${fuzzer}"
rm -rf "${artifact_directory}"
mkdir -p "${artifact_directory}"
cd "${module_directory}"

run_fuzz() {
  # No pipefail in the caller shell — return go test's status, not tee's,
  # so a crasher can't false-pass the attempt.
  go test -run='^$' \
    -fuzz="^${fuzzer}\$" \
    -fuzztime=60s \
    -timeout=5m \
    "${package}" 2>&1 | tee "${attempt_log}"
  return "${PIPESTATUS[0]}"
}

new_crashers() {
  git ls-files --others --exclude-standard -- '**/testdata/fuzz/**'
}

for attempt in 1 2; do
  attempt_log="${artifact_directory}/fuzz-attempt-${attempt}.log"
  status=0
  run_fuzz || status=$?
  if [ "${status}" -eq 0 ]; then
    exit 0
  fi
  if [ "${attempt}" -eq 2 ]; then
    exit "${status}"
  fi
  # Known coordinator-shutdown flake (#198): the run fails exactly at the
  # fuzztime boundary with a bare 'context deadline exceeded' and no
  # crasher written. Retry once on that exact signature only.
  if grep -q "context deadline exceeded" "${attempt_log}" && [ -z "$(new_crashers)" ]; then
    echo "::warning::${fuzzer}: deadline-exceeded at fuzztime expiry with no crasher written — retrying once (#198)" >&2
  else
    exit "${status}"
  fi
done
