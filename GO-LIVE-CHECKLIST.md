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

- [x] **Unbounded body read → OOM DoS** (HIGH) — `424f1d8`. Capped both `container_create.go` and `ownership/middleware.go` at `1 << 20` via `io.LimitReader(..., max+1)`, regression tests lock in the deny reason on oversized input.
- [x] **Verbose deny response leaks raw client path** (MEDIUM) — `16dd74e`. Flipped the `config.Defaults()` default from `verbose` to `minimal`, made `ParseDenyResponseVerbosity` fall back to minimal on unknown input, added `verboseMiddleware` test helper so explicit verbose tests still lock in the opt-in path. README + configuration.mdx updated.
- [ ] **Client ACL upstream fan-out is an amplification vector** (MEDIUM): `app/internal/clientacl/middleware.go:317-327` resolves the caller by querying upstream `/containers/json` on every inbound request when `clients.container_labels.enabled=true`. One inbound request → one upstream Docker API call + JSON decode. A burst of traffic from an allowed CIDR amplifies into a burst of Docker API load. Fix: short-TTL cache (5-10 s) keyed on source IP, with a small LRU cap. Invalidate on error.
- [ ] **JSON round-trip truncates large integers** (MEDIUM): `app/internal/ownership/middleware.go:266-275` `mutateJSONBody` decodes into `map[string]any`, which uses `float64` for numbers. Any Docker container-create field with a 53-bit+ integer silently loses precision on re-encode. Fix: `json.NewDecoder(...).UseNumber()` and handle `json.Number` in the mutation path, or narrow the decode to only the fields we actually mutate and keep the rest as raw bytes.
- [ ] **Docker filter negation semantics** (MEDIUM): `app/internal/ownership/middleware.go:308-342` `decodeDockerFilters` walks only `[]any` and `map[string]any` values and drops everything else. Docker's filter spec allows negation (e.g., `label!=foo`) and has evolved; our decoder silently loses any future shape. Document the subset we support, or fail fast on unknown shapes so we don't ship a silent-dropper.
- [x] **testcert TLS version mismatch** — `cf49c26`. `ClientTLSConfig` now pins `tls.VersionTLS13` to match `config.BuildMutualTLSServerConfig`, `TestClientTLSConfig` updated.

### Ship blockers — correctness / stability

- [x] **Health test flake** — stability bundle. `TestHealthCheckerCoalescesConcurrentCacheMisses` now overrides `failureTTL` to 10s so any straggler entering `check()` after the leader cleared `inFlight` still hits the cached error instead of becoming a new leader. Verified stable under `go test -race -count=50`.
- [x] **Sentinel error wrap-safety** — `424f1d8`. `serve.go:126` now uses `errors.Is(err, http.ErrServerClosed)`.
- [x] **Four-valued return shape is a footgun** — `424f1d8`. Replaced `(allowed, found bool, reason string, err error)` with `(ownershipVerdict, string, error)` enum returning `verdictPassThrough` / `verdictAllow` / `verdictDeny`. Caller reads as `if verdict != verdictDeny { next.ServeHTTP(...) }`.
- [x] **Health failure-cache semantics — document intent and add coverage** — stability bundle. Added block comment on `health.go:96-104` spelling out the "caller gave up vs upstream broke" rationale. Cases (a) dial-timeout + healthy caller and (b) cancelled-caller are already covered by `TestHealthBrieflyCachesUnhealthyStatusForLateCallers` and `TestHealthDoesNotCacheCallerCancelledFailure`; added `TestHealthDoesNotCacheCallerDeadlineFailure` for (c) deadline-caller.
- [x] **Client ACL map-iteration flake latent** — `955b22a`. Keys sorted with `sort.Strings` before iterating. Regression test plants 2 labels in reverse order and locks in sorted indices; verified stable under `-count=10`.
- [x] **No test cancels a live request context mid-proxy** — stability bundle. Added `TestNew_ClientCancelMidResponsePropagates` in `proxy_test.go`: upstream streams chunks on a loop, client reads one chunk then cancels, test asserts the upstream handler observes `r.Context().Done()` within 3s.
- [x] **Header injection not asserted through access-log sink** — stability bundle. Added `TestAccessLogEscapesCRLFInRequestID` in `access_test.go` asserting slog's JSON encoder escapes CR/LF from `X-Request-ID` so the rendered log line contains exactly one newline and no raw CR.
- [x] **Hardcoded `/tmp/dp-*-%d.sock` paths** — stability bundle. New `tempSocketPath(t, label)` helper wraps `os.CreateTemp("/tmp", ...)` so every call yields a unique, collision-free socket path that still fits macOS's 104-byte sun_path limit. 14 sites in `proxy_test.go` / `hijack_test.go` / `serve_test.go` updated. Verified under `-race -count=2` and `-count=3`.
- [ ] ~~**Race-sensitive `time.Sleep(10ms)` in hijack tests**~~ — re-audited: the three call sites are all inside 2-second polling loops (`waitForGoroutineDrain` + two log-appearance waits). The goroutine-count poll is inherent (no channel interface on `runtime.NumGoroutine()`); the log-appearance polls have generous timeouts and are not empirically flaky. Deferring to post-launch unless they actually start flaking.

### Ship blockers — housekeeping

- [x] **Biome suppression warning** — `cf49c26`. Stale `biome-ignore` in `page.tsx:16` deleted; `useMDXComponents` no longer triggers the `useHookAtTopLevel` rule so the suppression had no effect anyway.
- [ ] **Grype CVE scan**: run against `ghcr.io/codeswhat/sockguard:0.3.1`. Patch any High/Critical. Document Medium/Low in `SECURITY.md` or accept with rationale.
- [x] **Dead code (`isWildcardTCPBind`)** — `cf49c26`. Moved from `cmd/serve.go` into `serve_test.go` as a test-only helper so the function still covers its one test caller without bloating the production binary.
- [x] **Test-only wrappers in production surface** — `cf49c26`. `CompiledRule.matches` and `CompiledRule.matchesNormalizedUpper` moved from `rules.go` into `rules_test.go`; production `evaluateNormalized` already uses the `WithBit` hot path so the wrappers were never needed in production.

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
