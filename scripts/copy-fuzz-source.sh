#!/usr/bin/env bash

set -euo pipefail

source_root="${1:?source repository path is required}"
destination="${2:?destination path is required}"

mkdir -p "$destination"

(
  while IFS= read -r name; do
    unset "$name"
  done < <(git rev-parse --local-env-vars)
  cd "$source_root"
  git ls-files -z --cached --others --exclude-standard |
    while IFS= read -r -d '' path; do
      if [[ -f "$path" || -L "$path" ]]; then
        printf '%s\0' "$path"
      fi
    done |
    COPYFILE_DISABLE=1 tar --null -T - -cf -
) | (
  cd "$destination"
  tar -xf -
)
