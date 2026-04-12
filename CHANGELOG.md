# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
