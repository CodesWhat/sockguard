#!/usr/bin/env bash
# Extracts the latest documented Docker Engine API minor version from the
# HTML of https://docs.docker.com/reference/api/engine/version-history/,
# fed on stdin. Prints "1.NN" on stdout and exits 0, or prints an
# ::error::-style diagnostic on stderr and exits 1.
#
# Why this is a script and not an inline grep pipeline: the page lists a
# "v1.NN API changes" heading for every documented minor, but a bare
# "v1.NN" token appears elsewhere on the page too — the inlined SVG icons'
# `<path d="...">` coordinate data contains literals like "v1.875", which
# outsort every real version. That is what made the workflow report Engine
# API "1.875" on 2026-09-01 and demand a ceiling bump Docker never shipped.
# Matching only the exact "v1.NN API changes" wording fixes that, but it
# creates a new failure mode: if Docker rewords or recases only the newest
# heading (e.g. "v1.56 API updates" or "V1.56 API changes") while older
# headings still match, a narrow grep would silently keep reporting the
# previous version and the ceiling check would never fire. This script
# fails closed instead: it separately tracks every heading that merely
# looks like a version (any casing of "v", any wording) and the subset in
# the exact recognized form, and refuses to report a version when the two
# don't agree on the newest one.
set -euo pipefail

HTML="$(cat)"

# Isolate every <h2>...</h2> heading block onto its own line so a
# line-oriented grep sees one heading per line even though the source page
# is a handful of very long lines. GNU sed interprets "\n" in a replacement
# string as a newline; BSD sed requires a literal backslash-newline in the
# script text instead and errors out on "\n". Both accept a real
# backslash-then-newline, so build the replacement from that (POSIX
# portable) form rather than either sed's "\n" shorthand.
NL=$'\\\n'
BLOCKS="$(printf '%s' "${HTML}" | sed -e "s/<h2/${NL}<h2/g" -e "s/<\/h2>/<\/h2>${NL}/g")"

heading_minors=()
heading_texts=()
recognized_minors=()

while IFS= read -r line; do
  [[ "${line}" == '<h2'* ]] || continue

  text="$(printf '%s' "${line}" | sed -E 's/<[^>]+>//g' | tr -s '[:space:]' ' ')"
  text="$(printf '%s' "${text}" | sed -E 's/^ +//; s/ +$//')"

  # HEADING_VERSIONS: any heading containing a v1.NN-shaped token, whatever
  # its casing or the rest of the wording. This is the "what does the page
  # actually say the newest minor is" signal.
  if [[ "${text}" =~ [vV]1\.([0-9]+) ]]; then
    heading_minors+=("${BASH_REMATCH[1]}")
    heading_texts+=("${text}")
  fi

  # RECOGNIZED: only headings in the exact wording this script knows how to
  # trust. Deliberately case-sensitive on the leading "v" and the literal
  # "API changes" suffix — this is the narrow match, not the permissive one.
  if [[ "${text}" =~ ^v1\.([0-9]+)\ API\ changes$ ]]; then
    recognized_minors+=("${BASH_REMATCH[1]}")
  fi
done <<< "${BLOCKS}"

if [ "${#heading_minors[@]}" -eq 0 ]; then
  echo "::error::no version heading found; page layout may have changed" >&2
  exit 1
fi

heading_max=-1
heading_max_text=""
for i in "${!heading_minors[@]}"; do
  minor="${heading_minors[${i}]}"
  if (( 10#${minor} > heading_max )); then
    heading_max=$((10#${minor}))
    heading_max_text="${heading_texts[${i}]}"
  fi
done

recognized_max=-1
for minor in "${recognized_minors[@]}"; do
  if (( 10#${minor} > recognized_max )); then
    recognized_max=$((10#${minor}))
  fi
done

if [ "${#recognized_minors[@]}" -eq 0 ] || [ "${recognized_max}" -ne "${heading_max}" ]; then
  echo "::error::newest Engine API heading is not in the recognized 'v1.NN API changes' form (found: '${heading_max_text}') — update the extractor or confirm this is a real new version before trusting it" >&2
  exit 1
fi

# Sanity ceiling. Docker's Engine API minor has been in the double digits
# for a decade; a three-digit minor means the scrape matched page markup
# again rather than a real version. Fail loudly here instead of laundering
# it into a bogus "new API version" alert downstream.
if [ "${heading_max}" -ge 100 ]; then
  echo "::error::extracted implausible Engine API version '1.${heading_max}' — the scrape is matching page markup, not a version heading" >&2
  exit 1
fi

printf '1.%s\n' "${heading_max}"
