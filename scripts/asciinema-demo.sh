#!/usr/bin/env bash
# scripts/asciinema-demo.sh
#
# Records a ~15-second walkthrough of the sockguard CLI for the
# marketing site. Runs `sockguard version`, `sockguard validate`, and
# `sockguard serve` against a throwaway config so visitors see the
# mascot banner, the compiled rule table, and a real startup log line
# — not a synthetic rule tester.
#
# Usage (from the repo root):
#
#   # 1. Build sockguard from the current checkout
#   go -C app build -o /tmp/sockguard ./cmd/sockguard/
#   export SOCKGUARD_BIN=/tmp/sockguard
#
#   # 2. Install asciinema:
#   #    macOS:  brew install asciinema
#   #    Linux:  pipx install asciinema
#
#   # 3. Record the cast file:
#   asciinema rec \
#     --cols 100 --rows 30 \
#     --title "Sockguard CLI Tour" \
#     --command "./scripts/asciinema-demo.sh" \
#     website/public/sockguard-demo.cast
#
#   # 4. Preview locally:
#   asciinema play website/public/sockguard-demo.cast
#
# Re-record after any CLI output changes (font, banner, help text,
# rule-table format) so the cast matches the shipping binary.
#
# The script exits 0 even if a command prints a warning, so a stray
# deprecation notice never ruins a take; it is fatal only if the
# sockguard binary is missing or the serve process cannot be killed.

set -euo pipefail

SOCKGUARD_BIN="${SOCKGUARD_BIN:-sockguard}"

if ! command -v "$SOCKGUARD_BIN" >/dev/null 2>&1; then
  echo "error: sockguard binary not found (set SOCKGUARD_BIN to override)" >&2
  exit 1
fi

# Stage the demo under /tmp/ rather than $TMPDIR so the paths the
# validate + serve banners print stay short on macOS (where the
# default temp root is /var/folders/xx/xxxxxxxxx/T/... and dominates
# the screen). Random suffix so concurrent runs don't collide.
STAGE="$(mktemp -d /tmp/sockguard-demo.XXXXXX)"
CONFIG="$STAGE/sockguard.yaml"
SOCKET="$STAGE/sockguard.sock"
trap 'rm -rf "$STAGE"' EXIT

cat > "$CONFIG" <<EOF
listen:
  socket: $SOCKET

upstream:
  socket: /var/run/docker.sock

log:
  level: info
  format: text
  access_log: true

rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: GET, path: "/version" }
    action: allow
  - match: { method: GET, path: "/containers/json" }
    action: allow
  - match: { method: GET, path: "/containers/*/json" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
    reason: no matching allow rule
EOF

# ANSI-coloured fake prompt. Single quotes so the \033 stays literal
# until printf %b interprets it; the $ is already literal inside single
# quotes, no escaping needed.
PROMPT='\033[36m$\033[0m '

# Print a fake prompt, then the given command one character at a time
# so the recording looks like a human driver and not a batch replay.
# 25 ms per char lands at a readable cadence without dragging the
# take past ~15 s total.
typeline() {
  local text="$1"
  printf '%b' "$PROMPT"
  local i=0
  while (( i < ${#text} )); do
    printf '%s' "${text:i:1}"
    sleep 0.025
    i=$(( i + 1 ))
  done
  printf '\n'
  sleep 0.3
}

pause() {
  sleep "${1:-1}"
}

clear

# ────────────── sockguard version ──────────────
typeline "sockguard version"
"$SOCKGUARD_BIN" version || true
pause 1.2

# ────────────── sockguard validate ──────────────
typeline "sockguard validate --config ./sockguard.yaml"
"$SOCKGUARD_BIN" validate --config "$CONFIG" || true
pause 1.8

# ────────────── sockguard serve ──────────────
# Starts the proxy. Prints the mascot banner + the startup log line,
# then we SIGINT it so the recording doesn't hang on a long-lived
# process. 2.5 s is empirically enough time on a dev laptop for the
# banner to flush and the first `sockguard started` log entry to
# appear.
typeline "sockguard serve --config ./sockguard.yaml"
"$SOCKGUARD_BIN" serve --config "$CONFIG" &
SERVE_PID=$!
sleep 2.5
kill -INT "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true
pause 0.8
