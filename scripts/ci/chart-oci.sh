#!/usr/bin/env bash
#
# chart-oci.sh -- push a packaged Helm chart to an OCI registry and read it
# back, shared by release-from-tag.yml's publish-chart job and the
# chart-publish-rehearsal workflow so the rehearsal exercises release code.
#
# Usage:
#   chart-oci.sh push             push CHART_PACKAGE, or adopt the version that
#                                 is already published; prints ref/digest/exists
#   chart-oci.sh verify-contents  pull the published version back, check it is
#                                 the digest the registry reported, and run
#                                 assert-chart-release.mjs on the pulled chart
#
# Environment:
#   CHART_REGISTRY     registry namespace, e.g. ghcr.io/codeswhat/charts
#   CHART_VERSION      chart version (the tag without its leading v)
#   CHART_NAME         chart name (default sockguard)
#   CHART_PLAIN_HTTP   1 for an http registry (the rehearsal's service container)
#   CHART_PACKAGE      push: path of the packaged .tgz
#   CHART_DIGEST       verify-contents: digest `push` reported
#   RELEASE_TAG        verify-contents: the release tag, e.g. v3.0.0
#   IMAGE_DIGEST       verify-contents: the image digest the chart must pin
#
# Outputs go to $GITHUB_OUTPUT when it is set, and to stdout either way.

set -euo pipefail

CHART_NAME="${CHART_NAME:-sockguard}"
: "${CHART_REGISTRY:?CHART_REGISTRY is required}"
: "${CHART_VERSION:?CHART_VERSION is required}"
CHART_REF="${CHART_REGISTRY}/${CHART_NAME}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSERT_SCRIPT="${SCRIPT_DIR}/../assert-chart-release.mjs"

plain=()
if [ "${CHART_PLAIN_HTTP:-}" = "1" ]; then
  plain=(--plain-http)
fi

emit() {
  echo "$1"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "$1" >> "${GITHUB_OUTPUT}"
  fi
}

# helm push and helm pull both print a `Digest: sha256:...` line. awk reads to
# EOF so the pipeline never dies on SIGPIPE.
parse_digest() {
  awk '$1 == "Digest:" { d = $2 } END { print d }' "$1"
}

# Prints present, absent, or fails. Only a definite not-found is "absent":
# an auth, rate-limit or network error must not read as "nothing published"
# and fall through to a push.
version_state() {
  local out
  if out="$(helm show chart "oci://${CHART_REF}" --version "${CHART_VERSION}" ${plain[@]+"${plain[@]}"} 2>&1)"; then
    echo present
    return 0
  fi
  if printf '%s' "${out}" | grep -Eiq 'not found|manifest unknown|name unknown|404'; then
    echo absent
    return 0
  fi
  echo "::error::Could not tell whether ${CHART_REF}:${CHART_VERSION} exists; refusing to push on an unclear answer." >&2
  printf '%s\n' "${out}" >&2
  return 1
}

# Pulls the published version into $1 and prints its registry digest.
pull_version() {
  local dest="$1" log
  log="$(mktemp)"
  helm pull "oci://${CHART_REF}" --version "${CHART_VERSION}" --destination "${dest}" \
    ${plain[@]+"${plain[@]}"} > "${log}" 2>&1 || { cat "${log}" >&2; return 1; }
  parse_digest "${log}"
}

valid_digest() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]
}

cmd_push() {
  : "${CHART_PACKAGE:?CHART_PACKAGE is required}"
  local state digest exists=false attempt push_log pull_dir

  state="$(version_state)"
  pull_dir="$(mktemp -d)"

  if [ "${state}" = "present" ]; then
    echo "${CHART_REF}:${CHART_VERSION} is already published; adopting it instead of pushing."
    exists=true
    digest="$(pull_version "${pull_dir}")"
  else
    push_log="$(mktemp)"
    digest=""
    for attempt in 1 2 3 4 5; do
      if helm push "${CHART_PACKAGE}" "oci://${CHART_REGISTRY}" ${plain[@]+"${plain[@]}"} > "${push_log}" 2>&1; then
        cat "${push_log}"
        digest="$(parse_digest "${push_log}")"
        break
      fi
      cat "${push_log}" >&2
      # A push that errored may still have landed. Look before pushing again
      # so a retry can never overwrite a version.
      state="$(version_state)"
      if [ "${state}" = "present" ]; then
        echo "::warning::helm push reported an error but ${CHART_VERSION} is now published; adopting it."
        exists=true
        digest="$(pull_version "${pull_dir}")"
        break
      fi
      if [ "${attempt}" -eq 5 ]; then
        echo "::error::helm push failed after 5 attempts." >&2
        return 1
      fi
      sleep "${CHART_RETRY_DELAY:-5}"
    done
  fi

  if ! valid_digest "${digest}"; then
    echo "::error::Did not get a chart digest (got ${digest:-nothing}); helm push/pull output had no Digest line." >&2
    return 1
  fi

  emit "ref=${CHART_REF}"
  emit "digest=${digest}"
  emit "exists=${exists}"
  echo "${CHART_REF}:${CHART_VERSION} is ${digest} (already published: ${exists})."
}

cmd_verify_contents() {
  : "${CHART_DIGEST:?CHART_DIGEST is required}"
  : "${RELEASE_TAG:?RELEASE_TAG is required}"
  : "${IMAGE_DIGEST:?IMAGE_DIGEST is required}"
  local pull_dir digest package

  pull_dir="$(mktemp -d)"
  digest="$(pull_version "${pull_dir}")"
  if [ "${digest}" != "${CHART_DIGEST}" ]; then
    echo "::error::${CHART_REF}:${CHART_VERSION} resolves to ${digest} but ${CHART_DIGEST} was reported." >&2
    return 1
  fi

  package="${pull_dir}/${CHART_NAME}-${CHART_VERSION}.tgz"
  if [ ! -f "${package}" ]; then
    echo "::error::helm pull did not produce ${package}." >&2
    return 1
  fi

  helm show chart "${package}" > "${pull_dir}/Chart.yaml"
  helm show values "${package}" > "${pull_dir}/values.yaml"
  node "${ASSERT_SCRIPT}" \
    --tag "${RELEASE_TAG}" \
    --digest "${IMAGE_DIGEST}" \
    --chart "${pull_dir}/Chart.yaml" \
    --values "${pull_dir}/values.yaml"
}

case "${1:-}" in
  push) cmd_push ;;
  verify-contents) cmd_verify_contents ;;
  *)
    echo "usage: chart-oci.sh push|verify-contents" >&2
    exit 2 ;;
esac
