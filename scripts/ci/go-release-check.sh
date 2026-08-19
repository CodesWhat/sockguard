#!/usr/bin/env bash
set -euo pipefail

module_directory="${MODULE_DIRECTORY:-app}"
cd "${module_directory}"

# Pinned to the same version the branch-CI GoReleaser Action previously ran
# (env.GORELEASER_VERSION), so the snapshot build/config-parse behavior is
# unchanged by the reusable-workflow migration.
#
# SBOM cataloging (the sboms: block) shells out to syft, which real releases
# get via a dedicated install step in release-from-tag.yml. Neither this
# snapshot's own purpose (cask-template rendering) nor the CI config-check
# gate needs a real SBOM document, so skip that step when syft isn't on
# PATH rather than failing the snapshot on a missing tool it doesn't need.
# When syft is present (e.g. a dev machine with it installed) the snapshot
# exercises the real sbom step for extra local coverage.
skip="publish"
if ! command -v syft >/dev/null 2>&1; then
  skip="${skip},sbom"
fi

go run github.com/goreleaser/goreleaser/v2@v2.15.3 release --snapshot --clean --skip="${skip}"

cask="dist/homebrew/Casks/sockguard.rb"
test -f "${cask}"
grep -Fq 'cask "sockguard" do' "${cask}"
grep -Fq 'binary "sockguard"' "${cask}"
grep -Fq 'system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{staged_path}/sockguard"]' "${cask}"
