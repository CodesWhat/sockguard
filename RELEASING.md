# Releasing sockguard

## Maintenance releases

After v3 ships, 2.4.x receives security fixes until v3.1 ships. Keep its release changes on `maintenance/2.4.x`, with reviewed PRs and exact-SHA branch CI. The release cutter and publisher verify that the matching line is older than the first supported line in the default branch's `SECURITY.md` and is still marked supported there. A retired or mismatched line fails before publication. Protect the maintenance branch with the normal review and required-check rules before its first cut. Update its own release metadata and Renovate target for each patch, and supply an explicit `release_tag` to the cutter.

Maintenance releases publish their versioned assets, Go module, chart digest and full and minor image tags. They advance the floating major image tag only when the default branch's `SECURITY.md` records no newer minor line in that major, including retired lines. This lets a 2.4 patch update `:2` after v3 ships without allowing a 2.4 patch to roll `:2` back from a recorded 2.5 line. Maintenance releases do not replace Docker `latest`, GitHub's latest release or the global Homebrew cask. Homebrew publication and its smoke test apply to current stable releases only; maintenance users pin the versioned binary or image. The chart pin still runs after successful maintenance artifact verification, with Homebrew intentionally skipped. It opens a chart-pin PR instead of pushing to the protected maintenance branch. The existing release credential creates that PR so normal CI is triggered; review and merge it with the usual approvals. A rerun reuses an identical pin branch and open PR, and refuses to overwrite a different tree. Prereleases never move latest channels.

## Before tagging

1. **Clean tree on the release source branch**

   Use the active `dev/vX.Y` branch, or a `maintenance/X.Y.x` branch, for a prerelease. Use `main` for the current stable line. An older supported line uses its exact `maintenance/X.Y.x` branch head.

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

4. **Pre-GA tri-tool conformance gate** (minor/major GA promotions only — e.g. cutting v1.6.0 stable off an already-soaked `-rc.N`; skip for patch releases that don't touch the tri-tool surface) — #150's published Sockguard + Portwing + drydock conformance matrix does not run on every PR (see `.github/workflows/quality-tri-tool-conformance.yml`'s header for why), so it has to be run deliberately before promoting a candidate to GA:

   - Go to **Actions → Quality: Tri-Tool Conformance → Run workflow**
   - Set `sockguard_image` to the release-candidate image (e.g. `ghcr.io/codeswhat/sockguard:1.6.0-rc.11`) — never leave it empty when gating a specific candidate; an empty input resolves `current-standard`/`current-edge` to whatever stable version is already tagged and published (`legacy-floor` stays pinned to the audited floor `codeswhat/sockguard:1.5.1`), same as a scheduled run — still not the candidate you're trying to gate
   - Require all three matrix rows (`current-standard`, `current-edge`, `legacy-floor`) green before proceeding; the `summary` job's aggregated `$GITHUB_STEP_SUMMARY` and each row's `conformance-<row>.json` artifact have the per-assertion detail if anything fails

5. **Update CHANGELOG.md**

   - Rename `## [Unreleased]` → `## [v<version>] - <YYYY-MM-DD>`
   - Add a fresh empty `## [Unreleased]` block above it
   - The release workflow (`release-cut.yml`) validates that a non-empty CHANGELOG entry exists for the tag before pushing it; the build will fail if this step is skipped

6. **Sync release metadata** — sockguard does not hardcode its binary version in source. The binary's `sockguard version` output is injected at build time via goreleaser ldflags:

   ```
   -X github.com/codeswhat/sockguard/v2/app/internal/version.Version={{.Version}}
   -X github.com/codeswhat/sockguard/v2/app/internal/version.Commit={{.FullCommit}}
   -X github.com/codeswhat/sockguard/v2/app/internal/version.BuildDate={{.CommitDate}}
   ```

   On v2.4 and later, `BuildDate` is the UTC source commit date, and builds use `-trimpath` and `-buildvcs=false`. Follow the target branch's `app/.goreleaser.yaml`: older v2.2/v2.3 branches retain their existing build-date settings. The [reproduction procedure](docs/content/docs/verification.mdx#reproducible-go-binaries) applies to the v2.4 binary contract, not retroactively to older artifacts.

   The release-facing files still need explicit updates in the same PR:

   - `website/src/lib/site-config.ts` — current stable version shown by the site
   - `website/src/lib/site-content.ts` and `README.md` — roadmap/current-release copy
   - `chart/sockguard/Chart.yaml` and `chart/sockguard/values.yaml` — lockstep chart/application versions plus the two-stage image digest state (see [Helm chart](#helm-chart) below)
   - `docs/content/docs/roadmap.mdx` — served on the docs site; it went stale for a full release line because it wasn't on this list
   - `SECURITY.md` — the supported-versions table: the line being cut goes to the top marked supported, the previous minor line stays supported, everything older is unsupported. It went stale twice in three days (#421, #431) because nothing in this procedure named it.
   - `renovate.json` — `baseBranchPatterns` names the dev branch of the line being cut (`dev/vX.Y` for `vX.Y.0`, the maintenance branch for a maintenance cut). `release-cut.yml` asserts this before creating the tag, so a stale value fails the cut; the v2.2.0 dispatch failed exactly there because this step did not name the file.
   - Star chart — dispatch `starchart.yml` with `--ref` set to the branch being released, and let it commit (or confirm "chart unchanged") before tagging. The workflow is dispatch-only and commits to whatever branch it was dispatched on: a `release: [published]` trigger would never fire on this repo's own cuts, because GoReleaser publishes the release with `GITHUB_TOKEN` and GitHub suppresses workflow runs caused by that credential (CodesWhat/.github#36). Without this step the released README ships the previous release's chart.

   `scripts/release-metadata.test.mjs` enforces that the website version, website roadmap, docs roadmap, Helm chart/application versions, README latest-stable banner, and CHANGELOG release heading all agree with each other. It never reads the tag itself, so it stays green even if all of those files are stale relative to what's actually being tagged. `scripts/verify-tag-release-metadata.mjs` closes that gap by comparing the tag against `website/src/lib/site-config.ts`, `chart/sockguard/Chart.yaml`, `chart/sockguard/values.yaml`, `SECURITY.md`, and the CHANGELOG heading directly, and runs as a gate in both `release-cut.yml` (before the tag is pushed) and `release-from-tag.yml` (right after the tag-format assertion, before any artifact builds) — so skipping this step now hard-fails the cut instead of shipping a mislabeled release the way v1.7.1 did (#304). For a stable tag it requires exact agreement across all five surfaces, including an empty prepublication Helm image pin and a `SECURITY.md` supported-versions table whose first row is the tag's own `X.Y.x` line marked `:white_check_mark:`; for a prerelease tag (`vX.Y.Z-rc.N`) it only requires the CHANGELOG heading, since the website, chart, and SECURITY.md correctly still show the current stable version while an rc soaks.

7. **Lefthook pre-push** — runs automatically on `git push`. Sequence: clean-tree → goreleaser snapshot → go-lint → go-test → go-fuzz smoke → lockfile-dedupe → knip → biome → ts-test → build → zizmor. The push is blocked if any step fails. Branch CI independently runs the same GoReleaser snapshot and asserts that it rendered `dist/homebrew/Casks/sockguard.rb`.

8. **Release credentials** — confirm the repository Actions secret `HOMEBREW_TAP_TOKEN` is available and has contents-write access to `CodesWhat/homebrew-tap`. GoReleaser uses it only for current stable tags from `main`; prereleases and older maintenance releases skip the cask upload.

---

## Cutting the tag

**Preferred path: use the `release-cut` workflow.**

Go to **Actions → Release: Cut** → **Run workflow** and select the branch that owns the tag. Dispatch prerelease tags from `dev/vX.Y` or `maintenance/X.Y.x`; dispatch current stable tags from `main` and older supported patches from their matching maintenance branch. The workflow rejects a prerelease dispatched from `main` or a mismatched branch, and rejects a stable release outside `main` or its supported maintenance line before creating a tag.

The workflow:

- Polls until `ci-verify.yml` has a successful push run on the selected branch's HEAD
- Computes the next **stable** semver from conventional-commit history — **or**, if you supply the optional `release_tag` input (e.g. `v1.4.0-rc.1`), cuts that exact tag instead. This is how prereleases / rc's are cut: the auto-computer only emits stable versions.
- Validates the CHANGELOG entry is non-empty for the tag
- Creates and pushes an annotated tag using the repo bot identity

This automatically triggers `release-from-tag.yml`.

> Tags are **not** GPG-signed — the bot pushes a plain annotated tag (`git tag -a`). Release provenance comes from cosign keyless signing of the image plus SLSA Build L2 attestation in `release-from-tag.yml`, not from a git-tag signature. `v*` tags are protected against deletion and rewrite by a repo tag ruleset, so the signature of record for a release is the Cosign signatures and SLSA Build L2 attestations, not the tag itself.

**Manual path** (fallback if you can't use the workflow):

```
git tag -a v<version> -m "v<version>"
git push origin v<version>
```

Swap `-a` for `-s` if you want to GPG-sign locally, but signing is optional and not enforced anywhere. The `release-from-tag.yml` workflow fires on any `v*` tag push and gates the release on a green `ci-verify` run for the tag SHA.

The tag-triggered publisher independently resolves the branch that owns the release line. A current stable tag must equal the default branch's exact HEAD after promotion through `main`. An older stable tag must equal the matching maintenance branch's exact HEAD and pass the default branch support-policy check. A prerelease must equal the matching development or maintenance head; maintenance prereleases also need a supported older line. All paths require successful branch CI on that exact SHA.

---

## After tagging

`release-from-tag.yml` runs these jobs in order:

1. **verify-ci** — confirms the tag is the exact HEAD of its protected stable, development, or maintenance branch and that `ci-verify.yml` passed on the tag SHA; fails the release otherwise
2. **changelog** — extracts the CHANGELOG entry for the tag into release notes
3. **goreleaser** — builds Linux and Darwin `amd64` + `arm64` binaries, archives, checksums, and a CycloneDX SBOM per archive (via syft); cosign-signs `checksums.txt` and each archive into a sigstore bundle (`.sigstore.json`); attaches them to the GitHub release; reads the published body back and compares it to the extracted CHANGELOG entry; and updates `Casks/sockguard.rb` in `CodesWhat/homebrew-tap` for current stable tags
4. **release** — builds and pushes the multi-arch Docker image, then:
   - Signs the image with cosign (keyless, via GitHub OIDC)
   - Verifies the cosign signature in the same job
   - Signs the release tarball with cosign (blob signing) into a sigstore bundle (`.sigstore.json`); see `docs/content/docs/verification.mdx`
   - Attests SLSA Build L2 provenance and persists the GHCR image's linked artifact metadata (public repo only; activates automatically when the repo is public)
5. **verify-homebrew** — on current stable tags, clears the hosted runner's implicit `--no-quarantine` setting, installs the cask from `CodesWhat/homebrew-tap` on macOS, proves the installed version matches the tag and has no quarantine attribute, then uninstalls it
6. **verify-published** — QA-6 end-to-end gate: pulls each published image tag (ghcr, docker.io, quay.io) and the release tarball + signature assets, then runs the *exact* `cosign verify` / `cosign verify-blob` commands published in `docs/content/docs/verification.mdx`. Catches drift between the operator-facing docs and the actual pipeline.

**Verify the release:**

- GitHub Actions: `release-from-tag.yml` run is green
- GitHub release notes match the tagged CHANGELOG entry
- GHCR image exists: `ghcr.io/codeswhat/sockguard:<version>`
- Docker Hub mirror updated: `docker.io/codeswhat/sockguard:<version>`
- Quay.io mirror updated: `quay.io/codeswhat/sockguard:<version>`
- Homebrew cask updated for current stable releases: `brew install --cask codeswhat/tap/sockguard`
- Cosign verify — see `docs/content/docs/verification.mdx` for the canonical invocation

### Stable patch plus active release-candidate line

When a fix applies to the current stable release while a later release candidate is active, use two tracks instead of tagging the RC branch first:

1. Land and tag the stable patch from `main`; wait for `release-from-tag.yml` and its published-artifact verification to pass.
2. Merge the stable tag commit forward into the active development branch. Resolve CHANGELOG, site version, roadmap, and chart metadata deliberately — do not drop the stable release history during conflict resolution.
3. Add an exact prerelease CHANGELOG heading, run the full gates again, and cut the next RC with the explicit `release_tag` workflow input.
4. Keep the next minor milestone marked as prerelease/next until its soak completes. For the active v2.3 line, a candidate that only carries fixes already released on v2.2 keeps the existing GA date; a v2.3-only behavior change restarts the 14-day window. Every new candidate still needs a fresh four-hour soak and TLS scan on its exact head before stable promotion.

---

## Helm chart

The chart is in `chart/sockguard/`. It is not auto-published by any current workflow. Keep `version` and `appVersion` equal to the stable release version. This is a release contract, not an independently versioned chart line.

The image pin uses a two-stage flow because the immutable image digest does not exist until after the release is published:

1. Before tagging, set both fields in `chart/sockguard/Chart.yaml` to the release version without the leading `v`. Before tagging, leave `image.tag` empty so the chart falls back to `appVersion`.
2. Cut and verify the stable release from `main`. The tagged chart selects the versioned release tag and never falls back to `latest`; the postpublication digest pin supplies immutability on the active development branch.
3. After the release images are live, resolve the new multi-arch manifest-list digest with `docker buildx imagetools inspect codeswhat/sockguard:<appVersion>`. Use the top-level `Digest:` field, not a per-platform digest.
4. After the release images are live, pin `image.tag` to `<appVersion>@sha256:<digest>`. The `release-from-tag.yml` `pin-chart-digest` job runs on every stable tag: it resolves the GHCR manifest-list digest, refuses a digest different from the one it published, reads the target branch from the tagged `renovate.json`, writes the pin with `scripts/pin-chart-image-digest.mjs`, re-runs the release metadata test, and records `chore(chart): pin the <version> image to its multi-arch digest`. Development-line pins commit to the active development branch. Maintenance pins use `chore/chart-pin-<version>` and a reviewed PR targeting the matching `maintenance/X.Y.x` branch. Neither path commits to `main`, and an existing matching pin is a logged no-op.

For a failed development-line pin, check out the development branch and read the chart's current `appVersion`. If it still matches the release, run `node scripts/pin-chart-image-digest.mjs --version <version> --digest <digest>` using step 3's verified digest. If development has moved past the released `appVersion`, the job logs version skew, writes nothing, and stays green. Before pinning that newer chart manually, resolve and verify the multi-arch manifest-list digest for its current `appVersion` as in step 3, then pass that version and its matching digest to the pin command. If the current image has not been published, defer the pin until publication; leave `image.tag` empty so the chart uses `appVersion`.

For a failed maintenance pin, start from the matching `maintenance/X.Y.x` branch, create or check out its `chore/chart-pin-<version>` branch, and run the same pin command with the maintenance release version and verified digest. Open or update the PR against that maintenance branch, then follow normal checks and review. Do not write a maintenance release's digest onto the development branch or push directly to the protected maintenance branch.

The test accepts only an empty prepublication image tag or `<appVersion>@sha256:<digest>` with 64 lowercase hexadecimal characters. Do not advance `main` past the release tag solely for this follow-up; the next release metadata PR clears the pin before its tag is cut.

There is no chart-release workflow at this time. If a Helm repository is available, package and publish the chart only after the Docker images are live.

---

## If something goes wrong

Do not delete the bad release or the tag — that breaks `go install` version pinning and any existing image digests. Instead:

1. Revert the merge commit that introduced the bug: `git revert <merge-sha>`
2. Tag a patch release following the normal process
3. Edit the bad release on GitHub: prepend a warning to the release notes and link to the patched version (e.g. _"⚠️ This release contains a known issue — upgrade to v<patch>."_)
