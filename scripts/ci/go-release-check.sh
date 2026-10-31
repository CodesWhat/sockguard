#!/usr/bin/env bash
set -euo pipefail

module_directory="${MODULE_DIRECTORY:-app}"
cd "${module_directory}"

# Keep the snapshot engine in lockstep with GORELEASER_VERSION in the tagged
# publisher. The release contract test checks that both pins agree.
#
# SBOM cataloging (the sboms: block) shells out to syft, which real releases
# get via a dedicated install step in release-from-tag.yml. Neither this
# snapshot's own purpose (cask-template rendering) nor the CI config-check
# gate needs a real SBOM document, so skip that step when syft isn't on
# PATH rather than failing the snapshot on a missing tool it doesn't need.
# When syft is present (e.g. a dev machine with it installed) the snapshot
# exercises the real sbom step for extra local coverage.
#
# Signing is skipped unconditionally, unlike sbom. The signs: blocks use
# keyless cosign, which needs an ambient OIDC identity that only exists in
# release-from-tag.yml's tagged run -- a dev machine with cosign installed
# still can't produce one non-interactively, so gating on `command -v cosign`
# the way sbom gates on syft would fail exactly where cosign IS present.
# Signatures aren't part of what this dry-run checks (cask rendering, config
# parse, build, archive) anyway.
skip="publish,sign"
if ! command -v syft >/dev/null 2>&1; then
  skip="${skip},sbom"
fi

go run github.com/goreleaser/goreleaser/v2@v2.18.0 release --snapshot --clean --skip="${skip}"

cask="dist/homebrew/Casks/sockguard.rb"
test -f "${cask}"
grep -Fq 'cask "sockguard" do' "${cask}"
grep -Fq 'binary "sockguard"' "${cask}"
grep -Fq 'postflight_steps do' "${cask}"
grep -Fq 'run "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "sockguard"], chdir: "."' "${cask}"
if grep -Eq '^[[:space:]]*postflight do' "${cask}"; then
  echo "Generated cask uses deprecated postflight syntax" >&2
  exit 1
fi
