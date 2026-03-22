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

### Changed

- Renamed health endpoint from `/healthz` to `/health`

- Documented the intentional `ReadTimeout: 0` streaming tradeoff and slowloris mitigations in server code comments and README operational notes
- Wired `log.output` into logger initialization (`stderr`, `stdout`, or file path), with validation and tests
- Stopped ignoring CLI flag override `GetString` errors by returning explicit errors from `applyFlagOverrides`
- Expanded `cmd/serve_test.go` coverage for `createListener`, `healthInterceptor`, and `listenerAddr` helpers
- Added `cmd/validate_test.go`, full middleware-chain integration coverage, and edge-case tests for empty rules, nil meta, and implicit 200 response capture writes
