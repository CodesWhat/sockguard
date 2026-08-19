#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

if ! command -v shellcheck >/dev/null 2>&1; then
  echo "shellcheck is required; install it (e.g. 'brew install shellcheck') and re-run" >&2
  exit 1
fi

echo "shellcheck version: $(shellcheck --version | awk '/^version:/ { print $2 }')"

# Build the file list with a plain array (not mapfile/readarray) — the
# macOS-shipped /bin/bash that lefthook resolves via `env bash` is 3.2 and
# has neither builtin.
scripts=()
while IFS= read -r -d '' script; do
  scripts+=("${script}")
done < <(git ls-files -z '*.sh')

if [ "${#scripts[@]}" -eq 0 ]; then
  echo "::error::no tracked *.sh files found — shellcheck gate has nothing to check" >&2
  exit 1
fi

shellcheck "${scripts[@]}"
