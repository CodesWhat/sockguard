# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Sockguard?

Sockguard is a Docker socket proxy written in Go. It sits between Docker API consumers (Traefik, drydock, Portainer, etc.) and the Docker socket, filtering requests by HTTP method, path, and request body content (`containers/create`, exec create/start, service create/update, swarm init, image pull, and build are all inspected; the remaining blind-write guardrail is arbitrary exec without an allowlist). Default-deny posture, structured logging, per-client policy profiles, owner-label isolation, and read-side visibility/redaction set it apart from socket proxies that stop at method/path filtering.

## Repository Structure

This is a monorepo with three workspaces:

- **`app/`** — Go proxy (the core binary). Built with Go 1.26, uses stdlib `net/http/httputil.ReverseProxy` for proxying, Cobra+Viper for CLI/config.
- **`website/`** — Next.js landing page at getsockguard.com. Hosts the benchmarks + feature pages.
- **`docs/`** — Fumadocs documentation site served under `getsockguard.com/docs` (the `docs/` Next.js app is built with `basePath: "/docs"`, then `website/package.json`'s `prebuild` script copies its static export into `website/public/docs/` so the marketing site serves it as a subpath).

Turborepo orchestrates the TypeScript workspaces. The Go app is built independently.

## Build, Test, and Lint Commands

```bash
# Go proxy — run from app/
go build -o sockguard ./cmd/sockguard/   # Build binary
go test ./...                              # All tests with coverage
go test -fuzz=FuzzPathMatch ./internal/filter/       # Fuzz: path matching pipeline
go test -fuzz=FuzzGlobToRegex ./internal/filter/     # Fuzz: glob-to-regex conversion
go test -fuzz=FuzzNormalizePath ./internal/filter/   # Fuzz: version prefix stripping
go test -fuzz=FuzzCompileRule ./internal/filter/     # Fuzz: rule compilation + matching
golangci-lint run                          # Lint

# TypeScript workspaces — run from repo root
npm run dev                    # Dev servers for all TS workspaces
npm run build                  # Build all TS workspaces
npx biome check .              # Lint all TS/JS
npx biome check --fix .        # Lint + autofix
npx biome format --write .     # Format

# Docker
docker build -t sockguard:dev .
```

## Architecture

### Proxy Core

The proxy is a middleware chain built on `net/http`:

```
Listener (Unix socket or TCP)
  → Access Logger
  → Health Interceptor (/health)
  → Rule Evaluator (method + path matching)
  → httputil.ReverseProxy → Docker socket
```

### Filter Rules

Rules are defined in YAML and compiled to matchers at startup:

```yaml
rules:
  - match: { method: GET, path: "/containers/**" }
    action: allow
```

Path patterns use glob syntax. Docker API version prefixes (`/v1.45/`) are stripped before matching.

Rules evaluate in order — first match wins. No match = deny (default-deny).

### Tecnativa Compatibility

Env vars like `CONTAINERS=1`, `POST=0`, `ALLOW_START=1` are automatically converted to equivalent rules for drop-in migration from Tecnativa/LinuxServer socket proxies.

## Configuration

YAML config file + env var overrides via Viper. Precedence: CLI flags > env vars > config file > defaults.

Env vars use `SOCKGUARD_` prefix with underscore nesting: `SOCKGUARD_LISTEN_SOCKET=/var/run/sockguard.sock`.

## Testing Patterns

- **Table-driven tests** with `testing.T` and `httptest`
- **Fuzz tests** for filter matching and config parsing
- **Integration tests** using `httptest.NewServer` as mock Docker daemon
- No external test dependencies — stdlib only

## Commit Convention

Plain Conventional Commits, no emoji: `<type>(<scope>): <description>`

| Type | Use |
|------|-----|
| `feat` | New feature |
| `fix` | Bug fix (including security fixes) |
| `docs` | Documentation |
| `refactor` | Refactor |
| `test` | Tests |
| `build` | Build system, dependencies |
| `ci` | CI/CD pipeline |
| `chore` | Config/tooling |
| `perf` | Performance |
| `style` | UI/cosmetic changes |
| `revert` | Revert a previous commit |

Add `!` before the colon for a breaking change (`feat(api)!: drop v1 tokens`), or add a `BREAKING CHANGE:` footer. Allowed types are exactly the ones above — nothing else. Git-generated subjects are exempt from validation: merge commits, `Revert "..."` commits, and `fixup!`/`squash!` autosquash commits.

## Pre-push Checks (Lefthook)

Runs piped (sequential, fail-fast): go-lint → go-test → biome → build.

## Key Constraints

- No third-party code executes on the proxy's request hot path — filtering, proxying, logging. This is about what runs, not what links: `internal/filter` also holds the image-trust and signed-policy-bundle verification code, so `internal/proxy`'s dependency graph pulls in sigstore/sigstore-go, go-containerregistry, and their transitive deps (grpc, protobuf, and the rest) at the package level even though none of it executes unless the opt-in `image_trust` path is configured. The binary's direct external dependencies are Cobra+Viper (+go-viper/mapstructure for config decoding), fsnotify (config hot-reload), golang.org/x/net + google.golang.org/protobuf (buildkitproxy's HTTP/2 and protobuf handling for Docker build proxying), sigstore/sigstore + sigstore/sigstore-go + sigstore/protobuf-specs + theupdateframework/go-tuf (image-trust and signed-policy-bundle verification), and go-containerregistry (OCI registry fetch for image-trust signatures — only on the opt-in `image_trust` path, never the core proxy path).
- Container image is **Wolfi-based** (Chainguard) for near-zero CVEs and built-in SBOM/provenance.
- Biome is a direct devDependency in the root workspace for TS/JS linting.
- `.planning/` is gitignored — local-only working notes; never reference its contents in committed files.
- CHANGELOG and README updates should be atomic with each logical change.
- **Roadmap summary lives in `README.md`** (committed). Local-only longer-form notes live under `.planning/` and stay gitignored.
