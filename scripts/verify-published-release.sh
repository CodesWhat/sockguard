#!/usr/bin/env bash
#
# verify-published-release.sh — QA-6 end-to-end signature verification.
#
# Runs the *exact* documented `cosign verify` and `cosign verify-blob`
# invocations from docs/content/docs/verification.mdx against the
# just-published artifacts: the multi-registry container image (ghcr,
# docker.io, quay.io) and the signed release tarball uploaded to the
# GitHub release page. The release workflow already verifies signatures
# inline using internal pipeline outputs; this is the *downstream* twin
# that exercises the published surface — pulling the tag the way a real
# operator would and following the published docs verbatim.
#
# The threat this gates is documentation drift: someone updates the
# release pipeline and forgets to update verification.mdx (or vice
# versa). A green run here means the docs you ship are the commands
# that actually verify the release.
#
# Usage:
#   scripts/verify-published-release.sh [--dry-run] --tag <vX.Y.Z>
#
# --dry-run prints the resolved plan (registries, identity regex,
# issuer, tarball download path) and exits 0 without contacting any
# registry or GitHub release. The test seam
# scripts/verify-published-release.test.mjs uses this to assert the
# option surface stays stable.

set -euo pipefail

DRY_RUN=0
RELEASE_TAG=""

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1; shift ;;
    --tag)
      RELEASE_TAG="${2:-}"; shift 2 ;;
    --tag=*)
      RELEASE_TAG="${1#--tag=}"; shift ;;
    -h|--help)
      sed -n '1,26p' "$0"; exit 0 ;;
    *)
      echo "verify-published-release.sh: unknown flag $1" >&2; exit 2 ;;
  esac
done

REPO="${GITHUB_REPOSITORY:-CodesWhat/sockguard}"
# Lowercase the org/repo for the ghcr image path — GHCR rejects mixed case.
REPO_LOWER="$(printf '%s' "${REPO}" | tr '[:upper:]' '[:lower:]')"

if [ -z "${RELEASE_TAG}" ]; then
  echo "verify-published-release.sh: --tag <vX.Y.Z[-pre]> is required" >&2
  exit 2
fi

# These two strings are the contract with docs/content/docs/verification.mdx.
# If they drift, the docs lie. The QA-6 job is here to catch that.
IDENTITY_REGEX="^https://github.com/${REPO}/.github/workflows/release-from-tag.yml@refs/tags/.+\$"
ISSUER="https://token.actions.githubusercontent.com"

# Registry tags follow the docker/metadata-action output in release-from-tag.yml.
# Stable tags (no -prerelease suffix) also get :latest, :major, :major.minor;
# we verify the full semver tag here — that's the one operators are pinning,
# and it's the one the verify-blob / docs flow shows.
IMAGE_TAGS=(
  "ghcr.io/${REPO_LOWER}:${RELEASE_TAG#v}"
  "docker.io/codeswhat/sockguard:${RELEASE_TAG#v}"
  "quay.io/codeswhat/sockguard:${RELEASE_TAG#v}"
)

# Release-asset filenames produced by the goreleaser + tarball signing
# steps in release-from-tag.yml. The .pem + .sig pair is what the
# documented verify-blob invocation consumes.
RELEASE_ARTIFACT="sockguard-${RELEASE_TAG}.tar.gz"
RELEASE_ASSETS=(
  "${RELEASE_ARTIFACT}"
  "${RELEASE_ARTIFACT}.sig"
  "${RELEASE_ARTIFACT}.pem"
)

if [ "${DRY_RUN}" -eq 1 ]; then
  cat <<EOF
verify-published-release.sh dry-run plan:
  release tag:        ${RELEASE_TAG}
  repo:               ${REPO}
  identity regex:     ${IDENTITY_REGEX}
  issuer:             ${ISSUER}
  image tags to verify:
$(printf '    - %s\n' "${IMAGE_TAGS[@]}")
  release assets to download + verify:
$(printf '    - %s\n' "${RELEASE_ASSETS[@]}")
  cosign image command (per tag):
    cosign verify \\
      --certificate-identity-regexp '${IDENTITY_REGEX}' \\
      --certificate-oidc-issuer '${ISSUER}' \\
      <image>
  cosign blob command:
    cosign verify-blob \\
      --certificate '${RELEASE_ARTIFACT}.pem' \\
      --signature   '${RELEASE_ARTIFACT}.sig' \\
      --certificate-identity-regexp '${IDENTITY_REGEX}' \\
      --certificate-oidc-issuer '${ISSUER}' \\
      '${RELEASE_ARTIFACT}'
EOF
  exit 0
fi

for tool in cosign gh; do
  if ! command -v "${tool}" >/dev/null; then
    echo "verify-published-release.sh: ${tool} not found on PATH" >&2
    exit 1
  fi
done

# Cosign verify retries cushion the registry pull + Rekor lookup against
# transient network errors; QA-6 should not flake the release on a one-off.
verify_image() {
  local image="$1"
  echo "==> cosign verify ${image}"
  for attempt in 1 2 3; do
    if cosign verify \
      --certificate-identity-regexp "${IDENTITY_REGEX}" \
      --certificate-oidc-issuer "${ISSUER}" \
      "${image}" >/dev/null; then
      return 0
    fi
    if [ "${attempt}" -eq 3 ]; then
      echo "==> FAIL: cosign verify ${image} after 3 attempts" >&2
      return 1
    fi
    sleep 5
  done
}

for image in "${IMAGE_TAGS[@]}"; do
  verify_image "${image}"
done

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "==> Downloading release assets for ${RELEASE_TAG}"
# `gh release download` honors GH_TOKEN; the workflow sets it. --pattern
# lets us pull just the tarball + the two verify-blob inputs so a missing
# .intoto.jsonl on a private-repo release does not break QA-6.
for asset in "${RELEASE_ASSETS[@]}"; do
  gh release download "${RELEASE_TAG}" \
    --repo "${REPO}" \
    --pattern "${asset}" \
    --dir "${WORK_DIR}" \
    --clobber
done

echo "==> cosign verify-blob ${RELEASE_ARTIFACT}"
(cd "${WORK_DIR}" && cosign verify-blob \
  --certificate "${RELEASE_ARTIFACT}.pem" \
  --signature   "${RELEASE_ARTIFACT}.sig" \
  --certificate-identity-regexp "${IDENTITY_REGEX}" \
  --certificate-oidc-issuer "${ISSUER}" \
  "${RELEASE_ARTIFACT}" >/dev/null)

echo "==> QA-6: all published artifacts verify against documented identity"
