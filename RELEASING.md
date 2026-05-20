# Releasing sockguard

## v1.0.0 release gate (one-time)

> Applies only to the `v1.0.0` tag. Remove this section once v1.0.0 ships.
>
> v1.0.0 is **criteria-gated, not date-gated** — there is no fixed soak duration, and "soak until it feels ready" is not a criterion. The v1.0 contract — YAML schema, CLI flags, env vars, admin endpoints, and Prometheus metric names — is frozen as of `v1.0.0-rc.2` (tagged 2026-05-16). Every box below must hold before the `v1.0.0` tag is cut; the generic [Before tagging](#before-tagging) steps then still apply on top.

- [ ] An rc (`rc.2` or later) has run **≥ 2–4 weeks across ≥ 2 real deployments** carrying production-shaped traffic.
- [ ] **Zero policy-bypass findings** from the proxy-vs-daemon differential harness and the negative / red-team test suite.
- [ ] **Zero panics and zero goroutine/RSS growth** over a 24 h+ memory-and-goroutine soak. The scheduled `quality-soak-weekly` workflow runs the 4 h github-hosted soak via `scripts/soak.sh`; a 24 h target run is the same script with `--duration 24h` on a self-hosted runner.
- [ ] **No change was forced to the locked surface during the soak.** Any forced schema / CLI / env var / admin-endpoint / metric-name change re-cuts an rc and resets the soak clock — that is the point of freezing the surface.
- [ ] `govulncheck` is clean, Grype + OpenSSF Scorecard are green, and the published image verifies with the documented `cosign verify` invocation.
- [ ] CHANGELOG `[Unreleased]` is rolled into a `[1.0.0]` entry and `chart/sockguard/Chart.yaml` is bumped (also covered by the generic checklist below).

If any box fails, fix it, cut a fresh rc, and restart the soak clock — a reset here is the gate working as designed, not a failure.

---

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

6. **Lefthook pre-push** — runs automatically on `git push`. Sequence: clean-tree → goreleaser snapshot → go-lint → go-test → go-fuzz smoke → lockfile-dedupe → knip → biome → ts-test → build → zizmor. The push is blocked if any step fails.

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
5. **verify-published** — QA-6 end-to-end gate: pulls each published image tag (ghcr, docker.io, quay.io) and the release tarball + signature assets, then runs the *exact* `cosign verify` / `cosign verify-blob` commands published in `docs/content/docs/verification.mdx`. Catches drift between the operator-facing docs and the actual pipeline.

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
