#!/usr/bin/env bash
# Resolve the branch a workflow is allowed to commit to.
#
# `main` is the released version and only advances through a promotion PR:
# its ruleset answers a direct push with "Changes must be made through a pull
# request", which is how run 34041041301 died in the mutation badge job's
# "Commit badge JSON" step. `dev/*` takes direct pushes — Renovate, the
# `-s ours` reconcile merges and starchart.yml all push there.
#
# renovate.json's baseBranchPatterns is the only place the active development
# branch is written down, and release-cut.yml's "Assert Renovate targets
# release branch" step already fails a cut when it disagrees with the release
# line, so it is the one durable source of truth for the branch the next
# promotion comes from. Both committing workflows read it through this script
# rather than each carrying its own copy of the parse.
#
# Usage: active-dev-branch.sh [path/to/renovate.json]
# Prints the branch on stdout. Fails closed, with the reason on stderr, on
# anything that is not exactly one `dev/vX.Y` or `maintenance/X.Y.x` entry, and
# on a value that names the default branch (DEFAULT_BRANCH, default "main").
set -euo pipefail

config="${1:-renovate.json}"
default_branch="${DEFAULT_BRANCH:-main}"

if [ ! -f "${config}" ]; then
  echo "::error::${config} not found; cannot resolve the active development branch" >&2
  exit 1
fi

# Same expression release-cut.yml asserts with, including the join: a
# multi-entry array collapses to a comma-joined string that fails the shape
# check below rather than silently resolving to its first element.
branch="$(jq -r '.baseBranchPatterns // .baseBranches // [] | join(",")' "${config}")"

if [ -z "${branch}" ]; then
  echo "::error::${config} declares no baseBranchPatterns; cannot resolve the active development branch" >&2
  exit 1
fi

if ! [[ "${branch}" =~ ^(dev/v[0-9]+\.[0-9]+|maintenance/[0-9]+\.[0-9]+\.x)$ ]]; then
  echo "::error::${config} baseBranchPatterns resolves to '${branch}', which is not a single dev/vX.Y or maintenance/X.Y.x branch" >&2
  exit 1
fi

if [ "${branch}" = "${default_branch}" ]; then
  echo "::error::refusing to target the default branch '${default_branch}'; it only advances through a promotion PR" >&2
  exit 1
fi

printf '%s\n' "${branch}"
