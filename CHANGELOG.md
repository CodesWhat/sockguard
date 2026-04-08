# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
