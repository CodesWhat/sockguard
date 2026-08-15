#!/usr/bin/env bash
set -euo pipefail

module_directory="${MODULE_DIRECTORY:-app}"
cd "${module_directory}"

# Pinned to the same version the branch-CI GoReleaser Action previously ran
# (env.GORELEASER_VERSION), so the snapshot build/config-parse behavior is
# unchanged by the reusable-workflow migration.
go run github.com/goreleaser/goreleaser/v2@v2.15.3 release --snapshot --clean --skip=publish

cask="dist/homebrew/Casks/sockguard.rb"
test -f "${cask}"
grep -Fq 'cask "sockguard" do' "${cask}"
grep -Fq 'binary "sockguard"' "${cask}"
grep -Fq 'system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{staged_path}/sockguard"]' "${cask}"
