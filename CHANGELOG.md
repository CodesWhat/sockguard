# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Relicensed Sockguard from AGPL-3.0 to Apache-2.0 so the proxy can be embedded inside other projects, docker-compose templates, and enterprise security hardening guides without the copyleft speed bump that blocks AGPL adoption for middleware. Matches `tecnativa/docker-socket-proxy` so migration and comparison narratives stay consistent with the incumbent. The sibling CodesWhat project `drydock` remains AGPL-3.0 because it is an end-user web application with a different adoption model — different role, different license.
- Flipped the default `response.deny_verbosity` from `verbose` to `minimal` so `403` deny responses no longer echo the request method, path, and matched rule reason back to callers by default. Verbose mode is still supported as an explicit opt-in for rule authoring and dev work but should never run in production because even with `/secrets/*` and `/swarm/unlockkey` redacted, it can leak request details that a honest security product should not hand a denied caller. `ParseDenyResponseVerbosity` now falls back to minimal on empty or unknown values as well, so a broken config never accidentally widens the response.

### Security

- Capped request body reads at 1 MiB (`maxContainerCreateBodyBytes` and `maxOwnershipBodyBytes`) in the container-create inspection path (`internal/filter/container_create.go`) and the ownership mutation path (`internal/ownership/middleware.go`). An allowlisted client can no longer OOM the proxy by posting a multi-GB JSON body to `/containers/create`, `/networks/create`, or `/volumes/create`; an over-limit body short-circuits with a policy deny reason or error before the JSON decode runs.
- Added a singleflight + 10-second TTL cache in front of the client ACL `/containers/json` resolver (`internal/clientacl/cache.go`). Before, every inbound request from an allowed CIDR fired a fresh upstream Docker API call to map source IP → caller container; a burst of N concurrent requests amplified into N upstream calls, turning one allowlisted client into a steady source of Docker-daemon load. Concurrent misses for the same IP now coalesce into one upstream call, successful lookups are reused for up to 10 s, and the cache is bounded to 256 entries with a size-aware scrub-then-evict path. Errors are never cached so transient upstream recovery still works on the next caller.
- Switched `ownership.mutateJSONBody` to `json.NewDecoder(...).UseNumber()` so Docker container-create fields above 2^53 — `Memory`, `MemorySwap`, `PidsLimit`, `NanoCpus` — round-trip their exact digits through the Labels-injection rewrite. The default `map[string]any` decode silently coerced every JSON number to `float64` and truncated large integers on the re-encode pass.

### Fixed

- Replaced the four-valued `(bool, bool, string, error)` return from `allowOwnershipRequest` and `checkOwnedResource` with an `ownershipVerdict` enum (`verdictPassThrough`, `verdictAllow`, `verdictDeny`) so the caller no longer has to juggle a meaningless-on-falsehood first bool. Behavior is unchanged — the shape is just safer to read and harder to misuse.
- Wrapped the `http.ErrServerClosed` sentinel check in `serve.go` with `errors.Is` so the shutdown listener loop stays correct against any future wrapping of the listen error path. No observable behavior change today because `http.Server.ListenAndServe` returns the sentinel unwrapped.
- Stabilized `TestHealthCheckerCoalescesConcurrentCacheMisses` by letting the test override the failure-cache TTL so any straggler entering `check()` after the leader cleared `inFlight` still hits the cached error under `-race` scheduling jitter. Added a block comment on `internal/health/health.go` documenting why caller-cancelled and deadline-exceeded failures deliberately bypass the cache, plus a new `TestHealthDoesNotCacheCallerDeadlineFailure` closing that coverage gap. Added `TestNew_ClientCancelMidResponsePropagates` in `internal/proxy/proxy_test.go` so mid-stream client disconnects on the reverse-proxy path have regression coverage (hijack path already had this). Added `TestAccessLogEscapesCRLFInRequestID` asserting the slog JSON sink escapes CR/LF from `X-Request-ID` and cannot forge a new log record. Replaced 14 hardcoded `/tmp/dp-*-%d.sock` socket paths in the proxy and serve tests with a `tempSocketPath(t, label)` helper built on `os.CreateTemp("/tmp", ...)` so `go test -count=N` and crashed prior runs never collide on a leftover socket.

### Documentation

- Expanded `SECURITY.md` with an explicit `Scope` section listing what's in-scope (the Go proxy at `app/`, the published `ghcr.io/codeswhat/sockguard` image, release binaries) and what's not (the marketing site, the docs site, the browser-only rule-tester demo, third-party deployments), plus a "What to include in a report" checklist for reproducer, version/digest, impact assessment, and disclosure timeline. The email address and response SLAs are unchanged.
- Added a new `docs/src/content/verification.mdx` page with the canonical `cosign verify` invocation for `ghcr.io/codeswhat/sockguard:<tag>`, derived directly from the release-from-tag workflow so the `certificate-identity-regexp` and `certificate-oidc-issuer` values track the actual signer. Covers a one-liner verify, digest-pinned verify, a "what to do if it fails" triage checklist, and `cosign verify-blob` for the signed release tarballs. Linked from `README.md` Security and from `docs/src/content/security.mdx`.
- Documented the Docker filter decoder shape in `internal/ownership/middleware.go:decodeDockerFilters`: the two supported wire formats (array-of-strings and object-with-keys), why `label!=value` negation is transparent (the `!=` lives inside the string value), and why unknown shapes are fail-fast rather than silently dropped. Paired with new `TestDecodeDockerFilters` cases locking in negation pass-through and rejection of numeric/bool filter values.

## [0.3.1] - 2026-04-13

### Security

- Pinned the production `Dockerfile` base images to immutable `@sha256:` digests so a compromised or retagged upstream can no longer silently flow into a Sockguard release build. The build stage now targets the concrete `golang:1.26.2-alpine3.23@sha256:c2a1f7b2...0826166` tag, and the runtime stage pins `cgr.dev/chainguard/static:latest@sha256:d6d54da1...6d5dbc` — Chainguard only publishes `latest` and `latest-glibc` cosmetic tags for the `static` image since it is a rolling daily rebuild of a minimal distroless base with CA certs, so the digest is the version lock. Dependabot's existing `package-ecosystem: docker` updater will continue to open weekly PRs bumping both digests.

## [0.3.0] - 2026-04-13

### Changed

- Raised the default minimum version for `listen.tls` mutual-TLS listeners to TLS 1.3.
- Added foundational per-client ACL primitives: `clients.allowed_cidrs` now gates TCP callers by source CIDR, and `clients.container_labels` can enforce per-client method/path allowlists from caller container labels resolved by source IP.
- Implemented `POST /containers/create` request-body inspection. Sockguard now blocks privileged containers, host networking, and non-allowlisted bind mounts by default, while leaving the remaining body-sensitive write endpoints behind `insecure_allow_body_blind_writes=true` until their request bodies are inspected too.
- Added per-proxy owner-label enforcement. When `ownership.owner` is set, Sockguard now stamps created containers, networks, volumes, and build-produced images with an owner label, filters list/prune/events requests by that label, and denies cross-owner access to labeled resources.
- Specialized path matching by discriminating literal, match-all, trailing `/**`, per-segment glob, and regex matcher kinds at compile time so the rule evaluator skips the regex engine entirely for the common rule shapes used by every bundled preset.
- Wrote httpjson deny-response headers by direct `http.Header` map assignment instead of `Header.Set` so the canonicalization walk does not run twice on every denied request hot path.
- Bundled filter, logging, and proxy microbenchmarks under `internal/{filter,logging,proxy}/*_bench_test.go` so future perf work has a documented baseline to measure against (`go test -bench=. -benchmem -run=^$`).

### Fixed

- Redacted denied verbose-response paths for `/secrets/*` and `/swarm/unlockkey`, and documented `response.deny_verbosity: minimal` as the recommended production setting so `403` bodies do not echo request details unnecessarily.
- Cached short-lived upstream failures in the `/health` checker (100 ms default) so late-arriving probes reuse the cached failure instead of becoming new singleflight leaders when the previous leader has already returned an error, preventing a retry dial stampede against an unreachable Docker socket. Caller-cancelled and deadline-exceeded failures still bypass the cache.
- Handled the body `Close` return value in the ownership and clientacl upstream inspectors so a silent close error cannot be ignored, dropped three nil-context coverage subtests that were exercising stdlib `http.NewRequestWithContext` behaviour rather than Sockguard code.

## [0.2.0] - 2026-04-12

### Changed

- Changed the default TCP listener from `:2375` to loopback `127.0.0.1:2375`, added mutual TLS support for non-loopback TCP listeners, and now reject plaintext non-loopback TCP unless `listen.insecure_allow_plain_tcp=true` is set explicitly for legacy compatibility.
- Added a startup warning when Sockguard is intentionally run in insecure plaintext remote-TCP mode, with recommendations to switch to mTLS, loopback-only TCP, or a unix socket.
- Added validation guardrails for body-sensitive write endpoints such as `POST /containers/create`, `POST /containers/*/exec`, `POST /exec/*/start`, `POST /build`, and Swarm service writes. These rules now require `insecure_allow_body_blind_writes=true` until request body inspection exists, and the shipped Drydock, Watchtower, and Portainer presets now opt in explicitly.
- Added an explicit 120 second HTTP `IdleTimeout` so idle TCP keep-alive connections are reaped instead of lingering indefinitely after a request completes.
- Stopped cloning the entire inbound request when forwarding hijack upgrade requests upstream, and instead build a minimal outbound request with only the method, URL, host, protocol, headers, and body fields that the serialized Docker upgrade path actually needs.
- Extracted the repeated hijack `502 Bad Gateway` JSON-response path into a shared helper so upstream dial, write, and read failures stay consistent in one place.
- Split hijack handling into an explicit upgrade phase and a bidirectional stream relay phase so the control flow is easier to audit without changing Docker attach/exec behavior.
- Simplified log-output normalization by handling empty output values before the main switch in both the logging package and config validation mirror, reducing nested control flow without changing behavior.
- Unexported the test-only `CompiledRule.matches` wrapper while leaving `filter.Evaluate` exported, since the command layer still uses it for production rule evaluation.
- Refactored `runServe` into named lifecycle helpers for config loading, logger setup, rule compilation, upstream verification, handler construction, startup logging, shutdown coordination, and socket cleanup so the `serve` command flow is easier to audit and extend.
- Moved rule compilation and body-sensitive endpoint policy checks out of `internal/config` and into the command layer so config validation no longer depends upward on the filter or logging packages.
- Replaced the `serve` command's package-level dependency-injection hooks with a per-run `serveDeps` struct so command tests can stub dependencies without mutating global process state, which removes the main blocker to running those tests in parallel.
- Added regression coverage for first-match rule precedence, concurrent filter metadata isolation, `splitMethods` edge cases, adversarial YAML config loading fuzzing, deterministic health-check coalescing, and `httpjson.Write` nil/write-failure paths.
- Documented the explicit `WriteTimeout: 0` streaming rationale beside the existing `ReadTimeout: 0` note, clarified the inline Tecnativa compatibility expansion point in `serve`, asserted health endpoint version/uptime fields in tests, and added env-var override coverage for `SOCKGUARD_LISTEN_ADDRESS` and `SOCKGUARD_LISTEN_SOCKET`.
- Added a `.qlty/qlty.toml` configuration so the qlty code-quality tool runs with comment-only smells and project-appropriate file exclusions across local and CI runs.
- Split `runServeWithDeps` into a `serveRuntime` struct plus `prepareServeRuntime`, `loadServeRuntimeConfig`, `buildVerifiedServeHandler`, and `openServeListener` helpers, and split `createListener` into `createSocketListener`, `createTCPListener`, and `wrapListenerWithTLS` so the TLS wrap path is no longer buried inside the TCP branch.
- Split `upgradeHijackConnection` into `writeHijackUpstreamRequest`, `readHijackUpstreamResponse`, `writeNonUpgradeHijackResponse`, and `finalizeHijackUpgrade`, and replaced the two duplicated upstream↔client copy goroutines with a single parameterized `startHijackCopy` launcher driven by a `hijackCopyStream` value.
- Extracted the testcert mutual-TLS bundle writer into `newCertificateAuthority`, `newServerCertificate`, `newClientCertificate`, `newLeafCertificate`, and `writeBundleFiles` helpers so the `WriteMutualTLSBundle` entry point reads as a linear CA → server → client → write pipeline.
- Extracted a `commitReleaseLevel` helper in `scripts/release-next-version.mjs` so the per-commit major/minor/patch classification is isolated from the priority-aggregation loop in `inferReleaseLevel`.
- Added demo evaluator coverage for `/**` wildcard expansion across path separators, `*` segments stopping at separators, method-mismatch default-deny fallthrough, and default-deny match reason reporting, and scoped the Go coverage artifact upload to the `app/` packages.

### Fixed

- Returned the deferred `file.Close` error from `writePEM` via a named return so a silent close failure can no longer leave a half-written PEM file on disk, and reworked the three "pool returns wrong type" logging tests to swap only the pool's `New` hook and `Put` a pointer-typed wrong value so they no longer trip `govet` `copylocks` or `staticcheck` `SA6002`.

## [0.1.1] - 2026-04-11

### Fixed

- Stopped Tecnativa compatibility mode from regenerating rules when `rules:` was explicitly provided in config but happened to equal the built-in defaults. Explicit user rules now win over compat env vars regardless of value equality.
- Sanitized hijack upstream requests before serialization so client-controlled hop-by-hop headers and transfer encoding metadata are not forwarded verbatim to the Docker socket. The proxy now emits its own fixed Docker upgrade hint instead, the upstream Unix-socket dial fails fast after 5 seconds instead of blocking indefinitely, and idle hijack streams now reap stalled peers after 10 minutes of per-direction inactivity.
- Added an end-to-end hijack regression for mid-stream upstream disconnects that asserts the upgraded connection tears down cleanly and the handler does not leave extra goroutines behind after the Docker side closes.
- Pinned the HTTP server `MaxHeaderBytes` cap to 1 MiB explicitly so request-header limits remain an intentional hardening choice instead of an implicit stdlib default.
- Added a filter regression that compiles deep `**` glob patterns and matches them against long paths under a 100ms ceiling to guard the glob-to-regex path against regex-style denial-of-service regressions.
- Added shared request-correlation fields to the access log and reverse-proxy upstream error log so `request_id` and filter metadata can be used to join a failed upstream attempt to its outer request log entry.
- Collapsed config validation onto `config.Validate` as the single validation-and-compilation entry point so `serve`, `validate`, and preset checks all exercise the same path.
- Added an end-to-end serve-path precedence regression that proves explicit CLI flags override env, env overrides YAML, and YAML overrides defaults across conflicting config sources.
- Documented the full `flag > env > file > default` precedence directly in `config.Load` so the code-level merge contract is visible where configuration sources come together.
- Collapsed the repeated `applyStringFlagOverride` calls in `serve.go` behind a table-driven helper so CLI override coverage and future flag additions stay aligned in one path.

## [0.1.0] - 2026-04-11

### Changed

- **Default listener flipped to TCP `:2375`** to match `tecnativa/docker-socket-proxy` and `linuxserver/socket-proxy`. Running `sockguard serve` with no config now binds TCP on `:2375` inside the container instead of a unix socket at `/var/run/sockguard.sock`. The unix socket listener is still fully supported — opt in by setting `SOCKGUARD_LISTEN_SOCKET` (or `listen.socket` in YAML). This makes zero-config drop-in migration from Tecnativa/LinuxServer actually zero-config, and eliminates the named-volume uid/gid friction for users running sockguard as a non-root user.
- Stripped the `listen:` block from every bundled preset (`drydock`, `traefik`, `portainer`, `watchtower`, `homepage`, `homarr`, `diun`, `autoheal`, `readonly`, `sockguard`) so they inherit the new default. Presets are about rules, not transport.
- README Quick Start now leads with the TCP-mode example. The unix-socket recipe (including the `user: "0:0"` note for named-volume setups) is documented under a collapsible "Unix socket mode" section.

## [0.0.1] - 2026-04-11

### Added

- Initial project scaffolding
- Go proxy with method + path filtering
- YAML configuration with env var overrides
- Tecnativa/LinuxServer env var compatibility
- Structured JSON access logging
- Health check endpoint (`/health`)
- CLI: `serve`, `validate`, `version` commands
- Multi-stage Wolfi container image
- Preset configs for drydock, Traefik, Portainer, Watchtower, Homepage, Homarr, Diun, Autoheal, read-only
- GitHub issue templates and CI workflows
- Nextra documentation site
- Next.js landing page
- Interactive rule tester demo

- All preset configs bundled in container image at `/etc/sockguard/`
- Optional Docker integration tests behind the `integration` build tag, including live proxy and health checks against a real daemon socket
- Fuzz coverage for proxy request headers and bodies in both the standard reverse-proxy and hijack forwarding paths

### Changed

- Renamed health endpoint from `/healthz` to `/health`

- Documented the intentional `ReadTimeout: 0` streaming tradeoff and slowloris mitigations in server code comments and README operational notes
- Wired `log.output` into logger initialization (`stderr`, `stdout`, or file path), with validation and tests
- Stopped ignoring CLI flag override `GetString` errors by returning explicit errors from `applyFlagOverrides`
- Expanded `cmd/serve_test.go` coverage for `createListener`, `healthInterceptor`, and `listenerAddr` helpers
- Added `cmd/validate_test.go`, full middleware-chain integration coverage, and edge-case tests for empty rules, nil meta, and implicit 200 response capture writes
- Expanded adversarial filter coverage for encoded path, Unicode normalization, and method-case matching edge cases
- Expanded hijack proxy coverage for malformed upstream responses, upgrade disconnects, copy-loop panics, and half-close failures
- Replaced `reflect.DeepEqual` in compat default-rule detection with explicit rule field comparisons and direct helper coverage
- Replaced untyped health response maps with a documented `HealthResponse` struct
- Added lightweight workspace tests for `website` and `docs`, plus a root workspace `test` command for the TypeScript apps
- Replaced the kernel-backlog-dependent health timeout test with a deterministic blocking-dial mock
- Added a compile-time `http.Hijacker` assertion for the access-log `responseCapture` wrapper
- Replaced the remaining untyped proxy/hijack JSON error maps with a shared typed error response struct
- Cached demo glob literal-character escaping so regex compilation stops running the same one-character `.replace()` work repeatedly
- Sanitized `/health` client error responses so they no longer leak raw socket paths or OS dial errors
- Buffered JSON helper encoding before headers are committed so encode failures do not partially send the wrong response metadata
- Dropped the filter plaintext denial fallback after JSON write failures so denied requests cannot end up with mismatched content types or secondary reflected writes
- Removed the unreachable empty-output branch from the logger writer after normalization rejects blank log targets up front
- Coalesced concurrent `/health` cache misses onto a single in-flight upstream probe so repeated requests do not stampede the Unix socket before the TTL cache fills
- Removed the redundant `/health` `Content-Type` header write and left JSON response metadata ownership with the shared HTTP JSON helper
- Consolidated the repeated non-101 hijack fallback tests behind a shared table-driven harness to keep proxy fallback coverage aligned without duplicating socket setup boilerplate
- Switched demo glob compilation to `Array.from(pattern)` so surrogate-pair literals are handled as single code points instead of split UTF-16 halves
- Extracted the landing-page feature cards and comparison table datasets into dedicated website data modules so `page.tsx` is easier to scan and maintain
- Pooled the 64KB hijack copy buffers so concurrent upgraded streams can reuse the same scratch allocations instead of allocating fresh slices per direction
- Documented the non-root runtime socket requirement, updated quick-start examples to place the listen socket inside a shared named volume, and added Linux `--user 65534:$(stat -c %g /var/run/docker.sock)` guidance for direct `/var/run/sockguard.sock` deployments
- Added configurable deny response verbosity so operators can switch between verbose rule-debugging responses and minimal generic `403` bodies
- Added deterministic coverage harnesses for CLI and hijack edge paths, expanded branch tests across the Go app, and brought `go test ./... -coverprofile` to 100% statement coverage

### Fixed

- Extracted a shared JSON response writer so proxy, filter, and health handlers stop repeating the same encoding/status boilerplate
- Logged hijack connection close failures at debug level instead of silently discarding them during upgrade error paths and final cleanup
- Cached `/health` upstream reachability checks for 2 seconds so frequent probes do not dial the Docker socket on every request
- Added a `ReadHeaderTimeout` on the HTTP server so TCP listeners get partial slowloris protection without breaking Docker streaming endpoints
- Hardened log file output handling to reject non-local paths like absolute paths and `..` traversal before opening files
- Stopped proxy and hijack 502 responses from leaking raw upstream error strings like socket paths and permission details to clients
- Made filter glob compilation rune-aware so literal Unicode path rules match correctly under adversarial normalization tests
- Aligned the demo rule evaluator with the Go proxy so trailing `/**` also matches the bare path, and added regression coverage for bare and version-stripped paths
- Precompiled demo rule matchers so repeated request evaluations reuse regexes instead of rebuilding them on every click
