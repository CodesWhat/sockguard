# Releasing sockguard

## Before tagging

1. **Clean tree on `main`**

   ```
   git status            # must be clean
   git log --oneline -3  # confirm HEAD is what you intend to tag
   ```

2. **Go checks**

   ```
   cd app
   go test ./...
   golangci-lint run
   ```

3. **Vulnerability scan** — zero reachable vulnerabilities required before tagging

   ```
   # Install once: go install golang.org/x/vuln/cmd/govulncheck@latest
   cd app && govulncheck ./...
   ```

4. **Update CHANGELOG.md**

   - Rename `## [Unreleased]` → `## [v<version>] - <YYYY-MM-DD>`
   - Add a fresh empty `## [Unreleased]` block above it
   - The release workflow (`release-cut.yml`) validates that a non-empty CHANGELOG entry exists for the tag before pushing it; the build will fail if this step is skipped

5. **No source version bump needed** — sockguard does not hardcode its version in source. The binary's `sockguard version` output is injected at build time via goreleaser ldflags:

   ```
   -X github.com/codeswhat/sockguard/internal/version.Version={{.Version}}
   -X github.com/codeswhat/sockguard/internal/version.Commit={{.Commit}}
   -X github.com/codeswhat/sockguard/internal/version.BuildDate={{.Date}}
   ```

   The only file that needs a manual bump is `chart/sockguard/Chart.yaml` (see [Helm chart](#helm-chart) below).

6. **Lefthook pre-push** — runs automatically on `git push`. Sequence: goreleaser snapshot → go-lint → go-test → go-fuzz smoke → lockfile-dedupe → knip → biome → ts-test → build → zizmor. The push is blocked if any step fails.

---

## Cutting the tag

**Preferred path: use the `release-cut` workflow.**

Go to **Actions → Release: Cut** → **Run workflow** on `main`. The workflow:

- Polls until `ci-verify.yml` has a successful run on HEAD
- Computes the next semver from conventional-commit history
- Validates the CHANGELOG entry is non-empty for the computed tag
- Creates and pushes a signed annotated tag using the repo bot identity

This automatically triggers `release-from-tag.yml`.

**Manual path** (if you need to override the computed version):

```
git tag -s v<version> -m "v<version>"
git push origin v<version>
```

Signed tags require your GPG key. The `release-from-tag.yml` workflow fires on any `v*` tag push.

---

## After tagging

`release-from-tag.yml` runs these jobs in order:

1. **verify-ci** — confirms `ci-verify.yml` passed on the tag SHA; fails the release otherwise
2. **changelog** — extracts the CHANGELOG entry for the tag into release notes
3. **goreleaser** — builds `linux/amd64` + `linux/arm64` binaries, archives, and checksums; attaches them to the GitHub release
4. **release** — builds and pushes the multi-arch Docker image, then:
   - Signs the image with cosign (keyless, via GitHub OIDC)
   - Verifies the cosign signature in the same job
   - Signs the release tarball with cosign (blob signing)
   - Attests SLSA build provenance (public repo only; activates automatically when the repo is public)

**Verify the release:**

- GitHub Actions: `release-from-tag.yml` run is green
- GHCR image exists: `ghcr.io/codeswhat/sockguard:<version>`
- Docker Hub mirror updated: `docker.io/codeswhat/sockguard:<version>`
- Quay.io mirror updated: `quay.io/codeswhat/sockguard:<version>`
- Cosign verify — see `docs/content/docs/verification.mdx` for the canonical invocation

---

## Helm chart

The chart is in `chart/sockguard/`. It is not auto-published by any current workflow — bump and publish manually:

1. Edit `chart/sockguard/Chart.yaml`:
   - `version:` — chart semver (increment independently of the app version)
   - `appVersion:` — set to the new release tag (e.g. `"v1.0.0"`)
2. Commit the change in the same PR or as a follow-up patch commit on `main` before tagging.

There is no chart-release workflow at this time. If you publish to a Helm repository, do so after the Docker images are live.

---

## If something goes wrong

Do not delete the bad release or the tag — that breaks `go install` version pinning and any existing image digests. Instead:

1. Revert the merge commit that introduced the bug: `git revert <merge-sha>`
2. Tag a patch release following the normal process
3. Edit the bad release on GitHub: prepend a warning to the release notes and link to the patched version (e.g. _"⚠️ This release contains a known issue — upgrade to v<patch>."_)
