#!/usr/bin/env bash
# Vercel "Ignored Build Step" for the website project (see ignoreCommand in
# website/vercel.json). Exit 0 skips the build, exit 1 runs it. Production
# always builds. A preview builds unless the pushed range leaves every file
# the site build reads untouched. Anything uncertain builds.
set -u

# Everything the website and docs builds read, relative to the repo top level:
#   website, docs   the two Next.js apps (website/prebuild exports docs)
#   package.json, package-lock.json, turbo.json   workspaces and installs
#   biome.json      root lint config
#   scripts/analytics-*.mjs   both builds run these --check steps first
#   .vercelignore   decides which files are uploaded to the build
#   .gitignore      Tailwind's automatic source detection skips ignored paths
SITE_INPUTS=(
  website
  docs
  package.json
  package-lock.json
  turbo.json
  biome.json
  scripts/analytics-routes.mjs
  scripts/analytics-runtime.mjs
  .vercelignore
  .gitignore
)

if [ "${VERCEL_ENV:-}" = "production" ]; then
  echo "vercel-ignore-build: production deploy, building"
  exit 1
fi

prev="${VERCEL_GIT_PREVIOUS_SHA:-}"
if [ -z "$prev" ]; then
  echo "vercel-ignore-build: no previous deployment SHA, building"
  exit 1
fi

if ! top="$(git rev-parse --show-toplevel 2>/dev/null)" || [ -z "$top" ]; then
  echo "vercel-ignore-build: not inside a git checkout, building"
  exit 1
fi
cd "$top" || exit 1

if ! git cat-file -e "${prev}^{commit}" 2>/dev/null; then
  git fetch --quiet --depth=50 origin "$prev" >/dev/null 2>&1 || true
  if ! git cat-file -e "${prev}^{commit}" 2>/dev/null; then
    echo "vercel-ignore-build: previous SHA ${prev} unavailable, building"
    exit 1
  fi
fi

git diff --quiet "$prev" "${VERCEL_GIT_COMMIT_SHA:-HEAD}" -- "${SITE_INPUTS[@]}"
rc=$?
case "$rc" in
  0)
    echo "vercel-ignore-build: no site inputs changed since ${prev}, skipping"
    exit 0
    ;;
  1)
    echo "vercel-ignore-build: site inputs changed since ${prev}, building"
    exit 1
    ;;
  *)
    echo "vercel-ignore-build: git diff failed (${rc}), building"
    exit 1
    ;;
esac
