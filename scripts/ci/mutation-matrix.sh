#!/usr/bin/env bash
# Emit the Gremlins mutation-testing matrix as JSON for
# .github/workflows/quality-mutation-monthly.yml.
#
# Every package under app/internal, at any depth, that has both product
# code (a non-test .go file) and a test file is a matrix leg. Packages with no tests have
# no covered lines, so Gremlins would report 0 mutants and only pad the
# report count. Test-fixture packages are excluded by name below: they
# exist to support other packages' tests, so mutating them is noise.
#
# Deriving the matrix here instead of hardcoding it in the workflow means
# a new package is mutation-tested the month it lands, and the badge's
# expected-report count can never drift from the matrix.
#
# Package paths are repo-root relative (./app/internal/<pkg>): the Go module
# root is the repo root, and `gremlins unleash` resolves the module from the
# current directory rather than walking up for go.mod, so the workflow runs
# it from the root.
#
# Output (single line), shaped for `strategy.matrix: ${{ fromJSON(...) }}`.
# Only the `include` key: GitHub reads any other top-level key as a
# matrix dimension, and a scalar there makes the job fail to expand.
#   {"include":[{"name":"admin","package":"./app/internal/admin"},...]}
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}/app"

fixture_packages="testcert testhelp"

names=()
# Recursive: a package can sit at any depth under internal/ (buildkitproto
# has ten generated sub-packages today). testdata trees are never packages.
# `find -print0 | sort -z` keeps the order deterministic across filesystems;
# the read loop avoids mapfile, which macOS's bash 3.2 lacks.
while IFS= read -r -d '' dir; do
  rel="${dir#internal/}"
  case "${rel}" in
    */testdata|*/testdata/*|testdata|testdata/*) continue ;;
  esac
  # Matrix name: the path with / turned into -, so admin stays admin and
  # buildkitproto/pb becomes buildkitproto-pb. The badge job strips the
  # artifact prefix and run id and never re-derives the path from it.
  name="${rel//\//-}"

  case " ${fixture_packages} " in
    *" ${rel} "*) continue ;;
  esac

  has_src=0
  has_test=0
  for f in "${dir}"/*.go; do
    [ -e "${f}" ] || continue
    case "${f}" in
      *_test.go) has_test=1 ;;
      *) has_src=1 ;;
    esac
  done
  if [ "${has_src}" -eq 1 ] && [ "${has_test}" -eq 1 ]; then
    names+=("${name}:${rel}")
  fi
done < <(find internal -mindepth 1 -type d -print0 | sort -z)

if [ "${#names[@]}" -eq 0 ]; then
  echo "::error::mutation matrix is empty -- no package under app/internal has both source and tests" >&2
  exit 1
fi

include=""
for entry_spec in "${names[@]}"; do
  name="${entry_spec%%:*}"
  rel="${entry_spec#*:}"
  entry=$(printf '{"name":"%s","package":"./app/internal/%s"}' "${name}" "${rel}")
  if [ -n "${include}" ]; then
    include="${include},${entry}"
  else
    include="${entry}"
  fi
done

printf '{"include":[%s]}\n' "${include}"
