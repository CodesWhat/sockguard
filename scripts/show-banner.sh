#!/usr/bin/env bash
# Prints the real sockguard startup banner in truecolor — exactly what
# `sockguard serve` renders on a 24-bit terminal — so you can eyeball the
# colored dog art straight from the Go source. Usage:
#
#   bash scripts/show-banner.sh
#
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo/app"
# COLORTERM=truecolor → 24-bit colored dog art (not the monochrome fallback);
# FORCE_COLOR=1 → emit color even if stdout isn't detected as a TTY.
COLORTERM=truecolor FORCE_COLOR=1 go run ./cmd/bannerpreview/main.go
