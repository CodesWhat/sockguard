#!/usr/bin/env bash
set -euo pipefail

# The reusable CodesWhat/.github go-ci.yml qlty job passes the caller's
# module-directory input through as MODULE_DIRECTORY. Sockguard's Go module
# lives in app/, but the Qlty gate is whole-repository (.qlty/qlty.toml sits at
# the root and covers the Go module, the TypeScript workspaces, the shell
# scripts and the workflows alike), so the module directory is only ever
# asserted here. Fail loudly if the caller ever points somewhere else, rather
# than silently checking a tree the input no longer describes.
module_directory="${MODULE_DIRECTORY:-app}"
if [ "${module_directory}" != "app" ]; then
  echo "::error::Sockguard Qlty checks require MODULE_DIRECTORY=app (got '${module_directory}')" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

./scripts/qlty-check-gate.sh all
