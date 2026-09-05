#!/usr/bin/env bash
set -euo pipefail

module_directory="${MODULE_DIRECTORY:-app}"

repository_root="$(pwd -P)"
artifact_directory="${repository_root}/artifacts/go-test"
rm -rf "${artifact_directory}"
mkdir -p "${artifact_directory}"
cd "${module_directory}"

go list ./... | grep -v '/internal/testcert$' | xargs go test -race \
  -coverprofile="${artifact_directory}/coverage.txt" -covermode=atomic

# Drop non-production packages — those in NO binary's import closure:
# internal/differential (proxy-vs-daemon test harness), internal/testcert
# (test certs), internal/testhelp (test helpers). Their *tests* still run as
# regression checks; only their own statements are excluded so the gate
# reflects shipping code. internal/buildkitproto is also excluded: it is
# entirely protoc-generated marshal/decode code ("Code generated ... DO NOT
# EDIT") whose integrity is pinned by its provenance golden test, not
# statement coverage — counting its thousands of generated statements would
# let the gate be drowned out by codegen instead of measuring hand-written
# shipping logic (the hand-written internal/buildkitproxy package stays
# counted).
grep -vE 'github.com/codeswhat/sockguard/app/internal/(differential|testcert|testhelp|buildkitproto)/' \
  "${artifact_directory}/coverage.txt" > "${artifact_directory}/coverage.prod.txt"

# Vendor-free floor on PRODUCTION code: fails the job when the weighted
# statement total of shipping packages drops below COVERAGE_MIN. Kept a
# touch under the real total so ordinary churn does not trip it; ratchet up
# as coverage climbs.
COVERAGE_MIN="${COVERAGE_MIN:-96}"
total=$(go tool cover -func="${artifact_directory}/coverage.prod.txt" | awk '/^total:/ {print $3}' | tr -d '%')
echo "Production statement coverage: ${total}% (floor ${COVERAGE_MIN}%)"
awk -v t="${total}" -v m="${COVERAGE_MIN}" 'BEGIN { exit (t+0 >= m+0) ? 0 : 1 }' || {
  echo "::error::production coverage ${total}% is below the ${COVERAGE_MIN}% floor" >&2
  exit 1
}
