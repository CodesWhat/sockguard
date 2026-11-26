#!/usr/bin/env bash
# Smoke test for the rootless Quadlet kit (examples/quadlet/).
#
# Installs the units into the invoking user's Quadlet directory, starts
# sockguard in front of the user's podman.socket, then checks startup, one
# allowed call and denied calls through the filtered socket.
#
# Env:
#   SOCKGUARD_IMAGE   image to run instead of the one named in the unit
#                     (CI passes a locally built localhost/sockguard:quadlet-smoke)
#   KEEP=1            leave the units and volume in place on exit
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
kit="$root/examples/quadlet"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/containers/systemd"
conf_dir="${XDG_CONFIG_HOME:-$HOME/.config}/sockguard"

fail() {
  echo "FAIL: $*" >&2
  dump
  exit 1
}
dump() {
  systemctl --user status sockguard.service --no-pager 2>&1 | tail -20 || true
  journalctl --user -u sockguard.service --no-pager -n 50 2>&1 || true
  podman logs sockguard 2>&1 | tail -30 || true
}

cleanup() {
  [ "${KEEP:-0}" = 1 ] && return
  systemctl --user stop sockguard.service 2>/dev/null || true
  rm -f "$unit_dir/sockguard.container" "$unit_dir/sockguard.volume"
  rm -rf "$conf_dir"
  systemctl --user daemon-reload 2>/dev/null || true
  podman volume rm -f sockguard-socket >/dev/null 2>&1 || true
}
trap cleanup EXIT

for bin in podman curl systemctl; do
  command -v "$bin" >/dev/null || fail "$bin not found"
done
[ "$(id -u)" != 0 ] || fail "run as a regular user, this kit is rootless"

mkdir -p "$unit_dir" "$conf_dir"
cp "$kit/sockguard.volume" "$unit_dir/"
cp "$kit/sockguard.container" "$unit_dir/"
cp "$kit/sockguard.yaml" "$conf_dir/"
if [ -n "${SOCKGUARD_IMAGE:-}" ]; then
  sed -i "s|^Image=.*|Image=${SOCKGUARD_IMAGE}|" "$unit_dir/sockguard.container"
fi

# Surface Quadlet syntax errors with their own message instead of a missing unit.
for q in /usr/lib/podman/quadlet /usr/libexec/podman/quadlet; do
  if [ -x "$q" ]; then
    "$q" -dryrun -user >/dev/null || fail "quadlet rejected the units"
    break
  fi
done

# The Traefik consumer example isn't installed by this test (it would pull
# images), but its units must still parse alongside the kit's.
for q in /usr/lib/podman/quadlet /usr/libexec/podman/quadlet; do
  if [ -x "$q" ]; then
    trial="$(mktemp -d)"
    cp "$kit"/*.container "$kit"/*.volume "$kit"/traefik/*.container "$kit"/traefik/*.network "$trial/"
    QUADLET_UNIT_DIRS="$trial" "$q" -dryrun -user >/dev/null || {
      rm -rf "$trial"
      fail "quadlet rejected the traefik example units"
    }
    rm -rf "$trial"
    break
  fi
done

systemctl --user daemon-reload
systemctl --user start podman.socket
systemctl --user start sockguard.service || fail "sockguard.service did not start"

volume_dir="$(podman volume inspect sockguard-socket --format '{{.Mountpoint}}')"
sock="$volume_dir/sockguard.sock"
for _ in $(seq 1 30); do
  [ -S "$sock" ] && break
  sleep 1
done
[ -S "$sock" ] || fail "no sockguard socket at $sock"
systemctl --user is-active --quiet sockguard.service || fail "sockguard.service is not active"
echo "ok: startup"

code() { # code METHOD PATH
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 --unix-socket "$sock" -X "$1" "http://localhost$2"
}
expect() { # expect WANT METHOD PATH
  local got
  got="$(code "$2" "$3")"
  [ "$got" = "$1" ] || fail "$2 $3: want $1, got $got"
  echo "ok: $2 $3 -> $got"
}

expect 200 GET /_ping
expect 200 GET /version
expect 200 GET /containers/json
expect 200 GET /health
expect 403 POST /containers/create
expect 403 DELETE /containers/does-not-exist
expect 403 GET /images/json

# The same denial must hold on the native libpod surface.
expect 200 GET /libpod/containers/json
expect 403 POST /libpod/containers/create

echo "quadlet smoke: all checks passed"
