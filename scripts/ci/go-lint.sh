#!/usr/bin/env bash
set -euo pipefail

module_directory="${MODULE_DIRECTORY:-app}"
cd "${module_directory}"

unformatted="$(gofmt -l .)"
if [ -n "${unformatted}" ]; then
  echo "::error::gofmt found unformatted files — run 'gofmt -w .' in app/ and commit:" >&2
  echo "${unformatted}" >&2
  exit 1
fi

# Pin the linter so Go Lint is deterministic. Leaving it unpinned lets
# golangci-lint float to a newer staticcheck that has regressed SA5011:
# it false-positives "possible nil pointer dereference" on
# `if x == nil { t.Fatal(...) }` guards (t.Fatal ends the test via
# Goexit, so the deref below is unreachable). v2.13.2 is the first line with
# go1.27 support (golangci-lint#6642) and reports 0 issues on this tree.
GOLANGCI_LINT_CACHE="$(mktemp -d "${TMPDIR:-/tmp}/sockguard-golangci-lint.XXXXXX")"
export GOLANGCI_LINT_CACHE
trap 'rm -rf "${GOLANGCI_LINT_CACHE}"' EXIT

go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2 run
