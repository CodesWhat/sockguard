#!/usr/bin/env bash
# Emit the Gremlins mutation-testing matrix as JSON for
# .github/workflows/quality-mutation-monthly.yml.
#
# Every package under app/internal that has both product code (a non-test
# .go file) and a test file is a matrix leg. Packages with no tests have
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
for dir in internal/*/; do
  name="${dir#internal/}"
  name="${name%/}"

  case " ${fixture_packages} " in
    *" ${name} "*) continue ;;
  esac

  has_src=0
  has_test=0
  for f in "${dir}"*.go; do
    [ -e "${f}" ] || continue
    case "${f}" in
      *_test.go) has_test=1 ;;
      *) has_src=1 ;;
    esac
  done
  if [ "${has_src}" -eq 1 ] && [ "${has_test}" -eq 1 ]; then
    names+=("${name}")
  fi
done

if [ "${#names[@]}" -eq 0 ]; then
  echo "::error::mutation matrix is empty -- no package under app/internal has both source and tests" >&2
  exit 1
fi

include=""
for name in "${names[@]}"; do
  entry=$(printf '{"name":"%s","package":"./app/internal/%s"}' "${name}" "${name}")
  if [ -n "${include}" ]; then
    include="${include},${entry}"
  else
    include="${entry}"
  fi
done

printf '{"include":[%s]}\n' "${include}"
