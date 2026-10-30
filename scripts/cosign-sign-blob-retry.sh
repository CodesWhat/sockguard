#!/usr/bin/env bash
# Runs `cosign sign-blob "$@"` up to three times. GoReleaser calls this once
# per artifact, in parallel, and a Rekor 409 on a resent upload or a transient
# Sigstore failure should cost one retry, not the release. Each cosign run signs
# with a fresh ephemeral key and certificate, so a retry can't hit the entry an
# earlier attempt may already have stored.
set -euo pipefail

bundle=""
for arg in "$@"; do
  case "${arg}" in
    --bundle=*) bundle="${arg#--bundle=}" ;;
  esac
done

for attempt in 1 2 3; do
  if cosign sign-blob "$@"; then
    exit 0
  fi
  if [ "${attempt}" -eq 3 ]; then
    echo "::error::cosign sign-blob failed after 3 attempts"
    exit 1
  fi
  delay=$((attempt * 30))
  echo "::warning::cosign sign-blob attempt ${attempt} failed, retrying in ${delay}s"
  if [ -n "${bundle}" ] && [ -e "${bundle}" ]; then
    rm -f -- "${bundle}"
  fi
  sleep "${delay}"
done
