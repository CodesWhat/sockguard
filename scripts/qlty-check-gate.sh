#!/usr/bin/env bash
set -euo pipefail

mode="${1:-changed}"

case "${mode}" in
changed | all) ;;
*)
  echo "Usage: $0 [changed|all]" >&2
  exit 1
  ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

# Hard-fail rather than skip when the CLI is missing: this is a blocking gate,
# the same posture scripts/ci/shellcheck.sh takes. In CI the reusable go-ci.yml
# qlty job installs the CLI with qltysh/qlty-action/install before running this,
# so the check only ever fires locally.
if ! command -v qlty >/dev/null 2>&1; then
  echo "qlty is required; install it (e.g. 'curl https://qlty.sh | bash') and re-run" >&2
  exit 1
fi

# scripts/ci/go-test.sh stages coverage.txt and coverage.prod.txt under
# artifacts/go-test/. That directory is gitignored, but some qlty plugins still
# walk it before exclude filters apply. Drop the transient output to keep the
# gate stable.
rm -rf artifacts/go-test

cmd=(qlty check --no-progress)

if [ "${mode}" = "all" ]; then
  cmd+=(--all)
elif git rev-parse --verify --quiet refs/remotes/origin/main >/dev/null; then
  cmd+=(--upstream origin/main)
fi

echo "Running Qlty gate: ${cmd[*]}"
"${cmd[@]}" </dev/null
