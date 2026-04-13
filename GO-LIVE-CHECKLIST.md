# Go-Live Checklist

Working document tracking everything that must be true before the `sockguard` repo flips from private to public. Checkboxes flip from `[ ]` to `[x]` as each item lands in `main`.

## Decision log

- **License**: sockguard relicenses AGPL-3.0 → Apache-2.0. Drydock stays AGPL-3.0. Rationale: sockguard is security middleware whose value comes from being embedded — Apache-2.0 removes the "call legal" speed bump that blocks AGPL adoption in enterprise compose files and hardening guides. Drydock is an end-user web UI where AGPL is defensible. Matches Tecnativa/docker-socket-proxy so migration/comparison narratives stay clean.
- **Public infrastructure** (`getsockguard.com`, `docs.getsockguard.com`, demo): blocked on repo going public; nothing to do here until Phase 6.
- **Interactive demo**: replaced post-launch with an asciinema recording of real sockguard denying a privileged container create. Keep the current TS rule-tester as a fallback / sandbox but don't feature it as the hero.
- **External validation story**: synthetic Colima load-gen benchmark **plus** NAS production snapshot pulled from the real access log, both published to `BENCHMARKS.md`.
- **Known issues to fix before launch**: all three (health test flake, Biome suppression warning, Grype CVE scan on 0.3.1).
- **Pre-release warning in README**: stays. Sockguard is 0.3.x and the API contract isn't frozen. Honesty over cosmetics.

## Phase 1 — License relicense to Apache-2.0 ✅

- [x] Replace `LICENSE` with canonical Apache-2.0 text, copyright `2026 CodesWhat`
- [x] `README.md` badge src/alt (`AGPL-3.0` → `Apache-2.0`)
- [x] `README.md` footer "Licensed under …" link text
- [x] `Dockerfile` `LABEL org.opencontainers.image.licenses`
- [x] `website/src/app/page.tsx` hero badge text, Shields.io image URL, footer copyright line
- [x] `CHANGELOG.md` `[Unreleased] / Changed` entry documenting the relicense and rationale
- [x] Commit + push (`75c882a`)

## Phase 2 — Security surface

- [ ] `SECURITY.md` mirroring drydock's structure (supported versions, email `80784472+s-b-e-n-s-o-n@users.noreply.github.com`, GitHub private vulnerability reporting link, 48h ack / 7d status / fix ASAP, credit reporters in release notes). Add a `Scope` section listing what's in-scope (the Go proxy, published images) and what's not (the website, the demo sandbox, third-party deployments), plus a short "What to include in a report" checklist.
- [ ] Cosign verification docs: new page `docs/src/content/verification.mdx` with exact `cosign verify` invocation for `ghcr.io/codeswhat/sockguard:<tag>`, derived from `.github/workflows/release-from-tag.yml` (GitHub Actions OIDC issuer `https://token.actions.githubusercontent.com`, subject matching the release workflow run). Include:
  - What Cosign is verifying (signature, SBOM attestation, build provenance)
  - Expected OIDC `--certificate-identity-regexp` and `--certificate-oidc-issuer` values
  - One-liner copy-paste verify command
  - "If this fails, do not run the image" paragraph
- [ ] `README.md` Security section links to the new verification page
- [ ] Commit + push

## Phase 3 — Known issues and code audit findings

Organized by severity. Everything in "Ship blockers" has to land before Phase 6. Everything in "Should-fix" is a cheap win we bundle in to avoid rework. Anything not here is listed under "Post-launch" at the bottom of this document.

### Ship blockers — security

- [ ] **Unbounded body read → OOM DoS** (HIGH): `app/internal/filter/container_create.go:65` and `app/internal/ownership/middleware.go:348` both call `io.ReadAll(r.Body)` with no cap. Allowlisted client posting a multi-GB body to `/containers/create`, `/networks/create`, or `/volumes/create` can OOM the proxy. Fix: `http.MaxBytesReader` at ~1 MiB (Docker create payloads are always tiny). Add regression that posts 2 MiB and asserts a bounded 4xx rather than an OOM. Same fix pattern applies to both files.
- [ ] **Verbose deny response leaks raw client path** (MEDIUM): `app/internal/filter/middleware.go:148-150` `redactDeniedPath` default case echoes the raw request path back in the 403 body. `/secrets/*` and `/swarm/unlockkey` are already redacted, but any other Docker path with embedded secrets (labels, IDs) still leaks. Decide: flip default `response.deny_verbosity` from `verbose` to `minimal`, and/or expand the redaction allowlist. Minimal-by-default matches the README's "recommended for production" guidance and is the safer choice. Commit the default flip + add a doc note that `verbose` is dev-only.
- [ ] **Client ACL upstream fan-out is an amplification vector** (MEDIUM): `app/internal/clientacl/middleware.go:317-327` resolves the caller by querying upstream `/containers/json` on every inbound request when `clients.container_labels.enabled=true`. One inbound request → one upstream Docker API call + JSON decode. A burst of traffic from an allowed CIDR amplifies into a burst of Docker API load. Fix: short-TTL cache (5-10 s) keyed on source IP, with a small LRU cap. Invalidate on error.
- [ ] **JSON round-trip truncates large integers** (MEDIUM): `app/internal/ownership/middleware.go:266-275` `mutateJSONBody` decodes into `map[string]any`, which uses `float64` for numbers. Any Docker container-create field with a 53-bit+ integer silently loses precision on re-encode. Fix: `json.NewDecoder(...).UseNumber()` and handle `json.Number` in the mutation path, or narrow the decode to only the fields we actually mutate and keep the rest as raw bytes.
- [ ] **Docker filter negation semantics** (MEDIUM): `app/internal/ownership/middleware.go:308-342` `decodeDockerFilters` walks only `[]any` and `map[string]any` values and drops everything else. Docker's filter spec allows negation (e.g., `label!=foo`) and has evolved; our decoder silently loses any future shape. Document the subset we support, or fail fast on unknown shapes so we don't ship a silent-dropper.
- [ ] **testcert TLS version mismatch**: `app/internal/testcert/testcert.go:138-144` `ClientTLSConfig` still pins `tls.VersionTLS12` while the production mTLS server config is TLS 1.3. Bump to match so integration tests actually exercise the deployed TLS version. Test-only code so not a deployment risk, but a correctness/alignment fix.

### Ship blockers — correctness / stability

- [ ] **Health test flake**: `TestHealthCheckerCoalescesConcurrentCacheMisses` — race when stragglers become new leaders after the leader cleared `inFlight`. Fix with explicit sync in the test so all callers are queued before releasing dial, OR harden the impl to keep late entrants on the cached error within the coalesce window. Regression test on a frozen clock.
- [ ] **Sentinel error wrap-safety**: `app/internal/cmd/serve.go:126` uses `err != http.ErrServerClosed`. Change to `errors.Is(err, http.ErrServerClosed)`. Aligns with Go best practice; no observable behavior change today.
- [ ] **Four-valued return shape is a footgun**: `app/internal/ownership/middleware.go:122-154` `allowOwnershipRequest` returns `(bool, bool, string, error)` where the first bool is meaningless when `found==false`. Replace with a typed struct or decision enum. Bundle with the OOM fix since we're already in the file.
- [ ] **Health failure-cache semantics — document intent and add coverage**: `app/internal/health/health.go:102` tests outer caller `ctx.Err()` to decide whether to cache a failure. Current behavior: cache dial-timeouts with healthy caller (correct — broken upstream should coalesce), skip cache on caller cancel/deadline (correct — caller gave up, don't judge upstream). Intent is right, reading is confusing. Add block comment + exhaustive tests for: (a) dial-timeout + healthy caller → cache, (b) caller-cancelled dial → no cache, (c) caller-deadline dial → no cache. Only flip behavior if we decide intent should change.
- [ ] **Client ACL map-iteration flake latent**: `app/internal/clientacl/middleware.go compileContainerLabelRules` iterates `map[string]string` with no sort and builds rules by index. Two labels → non-deterministic rule ordering → first-match-wins becomes flaky. Current tests only plant one bad key so the flake doesn't fire. Fix: sort keys before iterating. Add a multi-label test.
- [ ] **No test cancels a live request context mid-proxy**: we have no coverage for the "client disconnects mid-stream" case on the standard reverse-proxy path. Hijack path has this, reverse-proxy doesn't. Add a test that cancels the request context halfway through a bodied response and asserts no goroutine or body leak.
- [ ] **Header injection not asserted through access-log sink**: CR/LF injection in `X-Request-ID` is filtered at the request layer but the access-log slog sink has no test that asserts the rendered log line is safe. Add one.
- [ ] **Hardcoded `/tmp/dp-*-%d.sock` paths**: `proxy_test.go` / `hijack_test.go` collide on `-count=2` or interrupted runs that leave stale sockets behind. Fix: `t.TempDir()` + unique names.
- [ ] **Race-sensitive `time.Sleep(10ms)` in hijack tests**: 3 call sites. Replace with channel-based sync or `testing/synctest` where applicable.

### Ship blockers — housekeeping

- [ ] **Biome suppression warning**: `docs/src/app/[[...mdxPath]]/page.tsx:16` — stale `biome-ignore` comment. Delete it.
- [ ] **Grype CVE scan**: run against `ghcr.io/codeswhat/sockguard:0.3.1`. Patch any High/Critical. Document Medium/Low in `SECURITY.md` or accept with rationale.
- [ ] **Dead code**: `cmd/serve.go:317-328 isWildcardTCPBind` is production code only referenced by tests. Delete or convert to an `export_test.go` helper.
- [ ] **Test-only wrappers in production surface**: `CompiledRule.matches()` and `matchesNormalizedUpper()` exist only for tests. Move to `export_test.go`.

### Should-fix — code quality (bundle while we're in the file)

- [ ] **De-duplicate `containsString`**: defined separately in `filter`, `ownership`, and `clientacl`. Replace all three with stdlib `slices.Contains` (Go 1.21+, matches zero-deps constraint).
- [ ] **De-duplicate `setDeniedMeta`**: clientacl and ownership each define the same helper. Consolidate as `logging.SetDenied(w, r, reason)` and import from both sites.
- [ ] **Unify unix-socket `http.Client` boilerplate**: `clientacl.upstreamResolver` and `ownership.upstreamInspector` build nearly identical transports. Extract a shared `internal/dockerclient` helper that returns an `*http.Client` pointed at a unix socket.
- [ ] **Ownership `NormalizePath` called twice per request**: `ownership/middleware.go:61` re-normalizes a path the filter middleware already stored in `meta.NormPath`. Read from meta instead. Same shape as the earlier hijack `IsHijackEndpoint` fix.
- [ ] **Collapse the four `*Identifier` helpers**: `ownership/middleware.go:222-264` `containerIdentifier` / `execIdentifier` / `networkIdentifier` / `volumeIdentifier` / `imageIdentifier` all have the same structure. Replace with a table-driven `identifierFor(kind, normPath)`.
- [ ] **Missing `b.ReportAllocs()`**: `filter/bench_test.go`, `filter/perf_bench_test.go:50,104,136`, and the middleware benches don't report alloc numbers. Without them, alloc regressions hide under `-bench`. Add to every `Benchmark*` in the new bench files.
- [ ] **Config defaults mirrored in 3 places**: `config/load.go:22-46` silently risks env-var precedence breakage if one mirror is forgotten. Source defaults from `Defaults()` only; the other two paths should call it or reference the same struct literal.
- [ ] **Pick one error-ignore convention**: codebase mixes `_ =` and a single `//nolint:errcheck` (`hijack.go:539`). Pick `_ =` everywhere and update the one outlier.

### Should-fix — documentation polish

- [ ] Add a WHY comment on `filter/rules.go:84-123 pathNeedsClean` fast-path citing the benchmark delta, not just WHAT it does.

### Wrap-up

- [ ] Commit + push (multiple commits, grouped: security fixes | stability/test hardening | code-quality dedup/refactor | doc polish). Keep each commit passing tests + lint independently.

## Phase 4 — Audits (parallel)

- [ ] **Comparison matrix audit** (research agent): verify every cell of `README.md` comparison table, `website/src/app/data/comparison-rows.ts`, and `docs/src/content/index.mdx` hero bullets against current upstream Tecnativa / LSIO / wollomatic sources. Return diff of facts that need changing. No hype, no "we'll support this soon," just cells that are wrong or stale. The earlier v0.3.0 competitive analysis is the starting point but is already slightly out of date.
- [ ] **Getting-started walkthrough**: fresh Colima context `colima start sockguard-audit`, docker-compose up the README Quick Start verbatim, curl every documented endpoint, track each step PASS/FAIL. Only steps that actually work end-to-end count as passing. Fix anything that breaks before launch. Tear down the Colima context when done.
- [ ] Commit any doc fixes produced by the audits
- [ ] Commit + push

## Phase 5 — External validation → BENCHMARKS.md

- [ ] **Synthetic bench**: local Colima + stdlib Go mock-Docker on unix socket + sockguard 0.3.1 binary + stdlib Go load generator. Scenarios: `GET /_ping`, `GET /containers/json`, `POST /exec/*/start` (deny), with concurrency levels 10 / 50 / 200 for 20s each. Record p50/p90/p99/max/RPS, FD growth, goroutine count before/after. Baseline: same loadgen against the mock's socket direct (no sockguard) so overhead is attributable.
- [ ] **Production snapshot**: pull 48 hours of sockguard access logs from the NAS (`docker logs sockguard` or wherever the JSON access log lands), summarize: total requests, allow/deny ratio, top 10 paths by frequency, p50/p99 latency, rule match distribution. No PII, redact any IPs or container IDs that matter.
- [ ] Write `BENCHMARKS.md` at repo root with both sections, reproduction commands, and honest caveats. No hype — numbers first.
- [ ] Commit + push

## Phase 6 — Final sweep and public flip

- [ ] README final audit: every badge resolves, every link works, roadmap matches reality, "pre-release" warning language reviewed
- [ ] CHANGELOG audit: `[Unreleased]` either empty or ready to be cut as a patch release when we flip
- [ ] Dependabot config sanity check: gomod, npm, github-actions, docker all still present; cooldown acceptable
- [ ] Run the `ci-verify` workflow once more against the final SHA, require green
- [ ] Flip repo visibility: Settings → General → Change repository visibility → Make public
- [ ] Verify the GHCR package visibility is public (may need a separate flip on the package settings page)
- [ ] Post-flip smoke tests:
  - GHCR image pull works anonymously
  - Cosign verify command from Phase 2 docs works anonymously
  - `gh repo view` shows the repo as public
  - `getsockguard.com`, `docs.getsockguard.com`, demo deploy and resolve
- [ ] Merge the first Dependabot PR (docker digest bump on next Monday) to prove the automation pipeline works end-to-end on the public repo

## Post-launch (not ship blockers)

### Content / distribution
- Asciinema recording of sockguard denying a privileged container create, embed on website
- Docker Hub mirror publish (if still wanted)
- Quay mirror publish (if still wanted)
- Launch announcement content (Show HN draft, r/selfhosted thread) — only once comfortable with stability
- `sockguard verify` subcommand that runs the Cosign verify for the running image's own digest, for belt-and-suspenders self-check

### Refactors — deferred to avoid scope creep during launch
- **Collapse `*WithDeps` / `*Deps` injection pattern**: `filter`, `hijack`, `testcert`, `clientacl`, `ownership` each add indirection to drive one test error path. `testcert` has 4 nested dep structs. Replace with direct function values passed by the test via `TestMain` / exported vars, or swap with real fakes. 5-package refactor, not launch-critical.
- **Unify unix-socket HTTP client** into `internal/dockerclient` (listed under Should-fix above; if time slips, defer here instead).

### Performance — post-launch micro-opts (bench evidence already in hand)
- **Ownership JSON round-trip alloc budget** (~73 KB / 124 allocs/req): the `map[string]any` → mutate → re-encode pipeline dominates ownership middleware allocations. Streaming decoder that mutates only the `Labels` field and passes everything else through as raw bytes would cut most of it. Not needed for launch; revisit under `0.5.0` observability if real-world RPS makes it matter.
- **Health success-path mutex → `atomic.Pointer[cacheEntry]`**: current success path takes `sync.Mutex` to read the cache. An `atomic.Pointer` swap would drop the lock on the fast path. Micro-optimization, not a latency-critical win for `/health` (probe frequency is low). Revisit if health probe rate becomes a concern.

### Testing — larger investments
- **`t.Parallel()` coverage**: only 3 tests in the suite call `t.Parallel()`. Whole-suite wall time under `-race` is ~25 s. Marking independent tests parallel would cut that in half. Sweep after launch, not a blocker.

### Nice-to-have polish
- Rewrite the four `*Identifier` helpers in `ownership/middleware.go:222-264` to a table-driven `identifierFor(kind, normPath)` (also listed under should-fix; defer here if we skip the bundle).
