#!/usr/bin/env bash
# scripts/asciinema-demo.sh
#
# Records a ~30-second walkthrough of the sockguard CLI for the
# marketing site. Six beats, each on its own frame:
#
#   1. sockguard version              — tool identification
#   2. sockguard validate             — compiled rule table
#   3. sockguard match (allow)        — GET /containers/json → rule #3
#   4. sockguard match (deny+reason)  — POST /containers/*/exec → rule #5
#   5. sockguard match (default-deny) — DELETE /images/* → rule #6
#   6. sockguard serve                — mascot banner + startup log
#
# Each beat is introduced by a dim comment line so viewers know what
# question the next command is answering, then the command types out
# character-by-character in bold so the user "drives" the demo. The
# screen clears between beats so the mascot banner on beat 6 lands in
# its own frame and nothing important gets pushed off the top.
#
# Usage (from the repo root):
#
#   # Build with real version/commit/date so the `sockguard version`
#   # block isn't a sea of "unknown" in the recording.
#   VERSION=$(git describe --tags --always)
#   COMMIT=$(git rev-parse HEAD)
#   BUILT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
#   LDFLAGS="-X github.com/codeswhat/sockguard/internal/version.Version=$VERSION \
#     -X github.com/codeswhat/sockguard/internal/version.Commit=$COMMIT \
#     -X github.com/codeswhat/sockguard/internal/version.BuildDate=$BUILT"
#   go -C app build -ldflags="$LDFLAGS" -o /tmp/sockguard ./cmd/sockguard/
#
#   # Record the cast.
#   SOCKGUARD_BIN=/tmp/sockguard asciinema rec \
#     --cols 100 --rows 32 --overwrite \
#     --title "Sockguard CLI Tour" \
#     --command ./scripts/asciinema-demo.sh \
#     website/public/sockguard-demo.cast
#
# Preview locally:
#
#   asciinema play website/public/sockguard-demo.cast
#   open website/public/asciinema-preview.html   # embeds asciinema-player

set -euo pipefail

SOCKGUARD_BIN="${SOCKGUARD_BIN:-sockguard}"

if ! command -v "$SOCKGUARD_BIN" >/dev/null 2>&1; then
  echo "error: sockguard binary not found (set SOCKGUARD_BIN to override)" >&2
  exit 1
fi

# Force colors on: sockguard disables color when stdout is not a TTY,
# but asciinema records through a PTY and the recorded cast should
# preserve ANSI escapes so the player can render them.
export FORCE_COLOR=1

# Pacing knobs — tweak these to retime the recording without touching
# the beat structure. TYPE_DELAY is per character, BEAT_PAUSE is how
# long we linger on the output of each command before moving on.
TYPE_DELAY="${TYPE_DELAY:-0.035}"
BEAT_PAUSE="${BEAT_PAUSE:-2.0}"
INTRO_PAUSE="${INTRO_PAUSE:-1.2}"

# Stage the demo under /tmp/ so `validate` and `serve` banners print a
# short path (macOS $TMPDIR is /var/folders/xx/.../T/ which dominates
# the screen). Random suffix keeps concurrent runs isolated.
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
  - match: { method: POST, path: "/containers/*/exec" }
    action: deny
    reason: exec disabled
  - match: { method: "*", path: "/**" }
    action: deny
    reason: no matching allow rule
EOF

# ──────────────────────────────────────────────────────────────────
# Styling helpers. All ANSI, no external deps, work through asciinema.
# ──────────────────────────────────────────────────────────────────
RESET=$'\033[0m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
GREEN=$'\033[32m'
CYAN=$'\033[36m'
YELLOW=$'\033[33m'
MAGENTA=$'\033[35m'

PROMPT="${GREEN}\$${RESET} "

# typeline prints the prompt, then types the command one char at a
# time. The command is printed bold so the viewer's eye locks onto
# the "active" line and ignores the surrounding output.
typeline() {
  local text="$1"
  printf '%s' "$PROMPT"
  printf '%s' "$BOLD"
  local i=0
  while (( i < ${#text} )); do
    printf '%s' "${text:i:1}"
    sleep "$TYPE_DELAY"
    i=$(( i + 1 ))
  done
  printf '%s\n' "$RESET"
  sleep 0.3
}

# comment prints a dim yellow "# ..." narration line. Used between
# beats so viewers know which question the next command answers.
comment() {
  printf '%s# %s%s\n' "$DIM$YELLOW" "$1" "$RESET"
  sleep "$INTRO_PAUSE"
}

# banner_title prints a big bold heading so the opening and closing
# frames have a little visual anchor.
banner_title() {
  printf '\n  %s%s%s\n' "$BOLD$MAGENTA" "$1" "$RESET"
  printf '  %s%s%s\n\n' "$DIM" "$2" "$RESET"
}

pause() {
  sleep "${1:-$BEAT_PAUSE}"
}

# run_demo types a short "pretty" version of the command, then
# actually invokes it with the full --config path (which stays
# out of the displayed command so the screen stays readable).
run_demo() {
  local fake="$1"
  shift
  typeline "$fake"
  "$SOCKGUARD_BIN" "$@" || true
}

# ═══════════════════ 0. Title frame ═══════════════════
clear
banner_title "sockguard" "a default-deny Docker socket proxy"
sleep 1.5

# ═══════════════════ 1. version ═══════════════════
clear
comment "What version are we running?"
run_demo "sockguard version" version
pause

# ═══════════════════ 2. validate ═══════════════════
clear
comment "Show me the rules this config compiles to."
run_demo "sockguard validate --config ./sockguard.yaml" \
  validate --config "$CONFIG"
pause

# ═══════════════════ 3. match — allowed ═══════════════════
clear
comment "Would sockguard let Traefik list containers?"
run_demo "sockguard match -X GET --path /v1.45/containers/json" \
  match --config "$CONFIG" --method GET --path /v1.45/containers/json
pause

# ═══════════════════ 4. match — explicit deny ═══════════════════
clear
comment "What if Portainer tries to exec into a container?"
run_demo "sockguard match -X POST --path /containers/abc/exec" \
  match --config "$CONFIG" --method POST --path /containers/abc/exec
pause

# ═══════════════════ 5. match — default deny ═══════════════════
clear
comment "And deleting an image? Nothing explicit — default deny."
run_demo "sockguard match -X DELETE --path /images/sha256:abc" \
  match --config "$CONFIG" --method DELETE --path /images/sha256:abc
pause

# ═══════════════════ 6. serve ═══════════════════
clear
comment "Time to actually run it."
typeline "sockguard serve --config ./sockguard.yaml"
"$SOCKGUARD_BIN" serve --config "$CONFIG" &
SERVE_PID=$!
# Longer window here: banner + info block + a few log lines need
# time to flush before we SIGINT. 3.5 s is empirically enough on a
# dev laptop with the Chainguard-free local build.
sleep 3.5
kill -INT "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true
sleep 1.5

# ═══════════════════ Outro ═══════════════════
printf '\n  %s%s%s\n' "$DIM$CYAN" "→ getsockguard.com" "$RESET"
sleep 2.0
