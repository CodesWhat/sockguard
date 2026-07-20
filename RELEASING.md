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

5. **Sync release metadata** — sockguard does not hardcode its binary version in source. The binary's `sockguard version` output is injected at build time via goreleaser ldflags:

   ```
   -X github.com/codeswhat/sockguard/internal/version.Version={{.Version}}
   -X github.com/codeswhat/sockguard/internal/version.Commit={{.Commit}}
   -X github.com/codeswhat/sockguard/internal/version.BuildDate={{.Date}}
   ```

   The release-facing files still need explicit updates in the same PR:

   - `website/src/lib/site-config.ts` — current stable version shown by the site
   - `website/src/lib/site-content.ts` and `README.md` — roadmap/current-release copy
   - `chart/sockguard/Chart.yaml` — chart version plus the default application image tag (see [Helm chart](#helm-chart) below)

6. **Lefthook pre-push** — runs automatically on `git push`. Sequence: clean-tree → goreleaser snapshot → go-lint → go-test → go-fuzz smoke → lockfile-dedupe → knip → biome → ts-test → build → zizmor. The push is blocked if any step fails.

---

## Cutting the tag

**Preferred path: use the `release-cut` workflow.**

Go to **Actions → Release: Cut** → **Run workflow** on `main`. The workflow:

- Polls until `ci-verify.yml` has a successful run on HEAD
- Computes the next **stable** semver from conventional-commit history — **or**, if you supply the optional `release_tag` input (e.g. `v1.4.0-rc.1`), cuts that exact tag instead. This is how prereleases / rc's are cut: the auto-computer only emits stable versions.
- Validates the CHANGELOG entry is non-empty for the tag
- Creates and pushes an annotated tag using the repo bot identity

This automatically triggers `release-from-tag.yml`.

> Tags are **not** GPG-signed — the bot pushes a plain annotated tag (`git tag -a`). Release provenance comes from cosign keyless signing of the image plus SLSA attestation in `release-from-tag.yml`, not from a git-tag signature.

**Manual path** (fallback if you can't use the workflow):

```
git tag -a v<version> -m "v<version>"
git push origin v<version>
```

Swap `-a` for `-s` if you want to GPG-sign locally, but signing is optional and not enforced anywhere. The `release-from-tag.yml` workflow fires on any `v*` tag push and gates the release on a green `ci-verify` run for the tag SHA.

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
5. **verify-published** — QA-6 end-to-end gate: pulls each published image tag (ghcr, docker.io, quay.io) and the release tarball + signature assets, then runs the *exact* `cosign verify` / `cosign verify-blob` commands published in `docs/content/docs/verification.mdx`. Catches drift between the operator-facing docs and the actual pipeline.

**Verify the release:**

- GitHub Actions: `release-from-tag.yml` run is green
- GHCR image exists: `ghcr.io/codeswhat/sockguard:<version>`
- Docker Hub mirror updated: `docker.io/codeswhat/sockguard:<version>`
- Quay.io mirror updated: `quay.io/codeswhat/sockguard:<version>`
- Cosign verify — see `docs/content/docs/verification.mdx` for the canonical invocation

### Stable patch plus active release-candidate line

When a fix applies to the current stable release while a later release candidate is active, use two tracks instead of tagging the RC branch first:

1. Land and tag the stable patch from `main`; wait for `release-from-tag.yml` and its published-artifact verification to pass.
2. Merge the stable tag commit forward into the active development branch. Resolve CHANGELOG, site version, roadmap, and chart metadata deliberately — do not drop the stable release history during conflict resolution.
3. Add an exact prerelease CHANGELOG heading, run the full gates again, and cut the next RC with the explicit `release_tag` workflow input.
4. Keep the next minor milestone marked as prerelease/next until its soak completes. A security fix resets the promotion clock; it is not a reason to relabel the RC as stable early.

---

## Helm chart

The chart is in `chart/sockguard/`. It is not auto-published by any current workflow — bump and publish manually:

1. Edit `chart/sockguard/Chart.yaml`:
   - `version:` — chart semver (increment independently of the app version)
   - `appVersion:` — set to the container image tag **without** the git tag's leading `v` (e.g. `"1.4.3"` or `"1.5.0-rc.2"`); the DaemonSet uses this value verbatim when `image.tag` is empty
2. Commit the change in the same PR or as a follow-up patch commit on `main` before tagging.

There is no chart-release workflow at this time. If you publish to a Helm repository, do so after the Docker images are live.

---

## If something goes wrong

Do not delete the bad release or the tag — that breaks `go install` version pinning and any existing image digests. Instead:

1. Revert the merge commit that introduced the bug: `git revert <merge-sha>`
2. Tag a patch release following the normal process
3. Edit the bad release on GitHub: prepend a warning to the release notes and link to the patched version (e.g. _"⚠️ This release contains a known issue — upgrade to v<patch>."_)
