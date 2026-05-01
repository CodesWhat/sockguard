#!/usr/bin/env bash
# Helpers for turning a Go-style fuzz budget into a surrounding test timeout.
#
# Supported duration syntax is the subset used by Sockguard fuzz workflows:
# one or more integer h/m/s components, for example 60s, 15m, 1h, or 1h30m.

fuzz_duration_to_seconds() {
  local rest="${1:-}"
  local total=0

  if [[ -z "$rest" ]]; then
    return 1
  fi

  while [[ -n "$rest" ]]; do
    if [[ "$rest" =~ ^([0-9]+)(h|m|s)(.*)$ ]]; then
      local value="${BASH_REMATCH[1]}"
      local unit="${BASH_REMATCH[2]}"
      rest="${BASH_REMATCH[3]}"

      case "$unit" in
        h) total=$((total + (10#$value * 3600))) ;;
        m) total=$((total + (10#$value * 60))) ;;
        s) total=$((total + 10#$value)) ;;
      esac
    else
      return 1
    fi
  done

  printf '%d\n' "$total"
}

fuzz_seconds_to_go_duration() {
  local seconds="$1"
  local hours minutes remainder out

  case "$seconds" in
    ''|*[!0-9]*) return 1 ;;
  esac
  if [[ "$seconds" -lt 1 ]]; then
    return 1
  fi

  hours=$((seconds / 3600))
  remainder=$((seconds % 3600))
  minutes=$((remainder / 60))
  remainder=$((remainder % 60))
  out=""

  if [[ "$hours" -gt 0 ]]; then
    out+="${hours}h"
  fi
  if [[ "$minutes" -gt 0 ]]; then
    out+="${minutes}m"
  fi
  if [[ "$remainder" -gt 0 || -z "$out" ]]; then
    out+="${remainder}s"
  fi

  printf '%s\n' "$out"
}

fuzz_timeout_for_budget() {
  local budget="$1"
  local cushion_seconds="${2:-600}"
  local budget_seconds

  budget_seconds="$(fuzz_duration_to_seconds "$budget")" || return 1
  fuzz_seconds_to_go_duration "$((budget_seconds + cushion_seconds))"
}
