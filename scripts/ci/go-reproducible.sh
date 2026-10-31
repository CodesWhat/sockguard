#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
source_ref="${1:-HEAD}"
source_commit="$(git -C "${repo_root}" rev-parse --verify --end-of-options "${source_ref}^{commit}")"
release_version="${2:-}"
if [ -z "${release_version}" ]; then
  release_version="$(git -C "${repo_root}" describe --tags --exact-match "${source_commit}" 2>/dev/null || echo v0.0.0-repro)"
  release_version="${release_version#v}"
fi
if [[ ! "${release_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.+-]+)?$ ]]; then
  echo "Version must be a semantic version without a leading v" >&2
  exit 2
fi
build_date="$(TZ=UTC git -C "${repo_root}" show -s --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ "${source_commit}")"
build_os="${GOOS:-linux}"
build_arch="${GOARCH:-amd64}"
case "${build_os}/${build_arch}" in
  linux/amd64 | linux/arm64 | darwin/amd64 | darwin/arm64) ;;
  *)
    echo "Unsupported release target: ${build_os}/${build_arch}" >&2
    exit 2
    ;;
esac

scratch_dir="$(mktemp -d "${TMPDIR:-/tmp}/sockguard-repro.XXXXXX")"
cleanup() { rm -rf "${scratch_dir}"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for build_copy in first second; do
  mkdir -p "${scratch_dir}/${build_copy}"
  git -C "${repo_root}" archive "${source_commit}" | tar -x -C "${scratch_dir}/${build_copy}"
done
required_toolchain="$(sed -n 's/^toolchain //p' "${scratch_dir}/first/go.mod")"
if [[ ! "${required_toolchain}" =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Source must pin an exact Go toolchain in go.mod" >&2
  exit 2
fi
printf 'Source: %s\nVersion: %s\nBuild date: %s\nTarget: %s/%s\nToolchain: %s\n' \
  "${source_commit}" "${release_version}" "${build_date}" "${build_os}" "${build_arch}" "${required_toolchain}"
version_package="github.com/codeswhat/sockguard/v2/app/internal/version"
linker_flags="-s -w -X ${version_package}.Version=${release_version} -X ${version_package}.Commit=${source_commit} -X ${version_package}.BuildDate=${build_date}"
for build_copy in first second; do
  (
    cd "${scratch_dir}/${build_copy}/app"
    env CGO_ENABLED=0 GOOS="${build_os}" GOARCH="${build_arch}" GOAMD64=v1 GOARM64=v8.0 \
      GOTOOLCHAIN="${required_toolchain}" GOENV=off GOWORK=off GOFLAGS= GOEXPERIMENT= \
      GOCACHE="${scratch_dir}/cache-${build_copy}" \
      go build -mod=readonly -trimpath -buildvcs=false -ldflags="${linker_flags}" \
      -o "${scratch_dir}/${build_copy}/sockguard" ./cmd/sockguard/
  )
done
cmp "${scratch_dir}/first/sockguard" "${scratch_dir}/second/sockguard"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${scratch_dir}/first/sockguard"
else
  shasum -a 256 "${scratch_dir}/first/sockguard"
fi
echo 'Reproducible: separate source directories and independent clean build caches produced identical bytes.'
