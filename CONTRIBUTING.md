# Contributing to Sockguard

Thanks for your interest in contributing! Whether it's a bug fix, new feature, documentation improvement, or something else — all contributions are welcome.

Questions or ideas? Start a [GitHub Discussion](https://github.com/CodesWhat/sockguard/discussions) or open an [issue](https://github.com/CodesWhat/sockguard/issues).

## Getting started

1. **Fork** the repository and clone your fork.
2. **Install Go 1.26+** (required for the proxy):

   ```bash
   go version  # should be 1.26+
   ```

3. **Install Node.js 22+** (required for website/docs):

   ```bash
   nvm use || nvm install
   ```

4. **Install dependencies**:

   ```bash
   # Go proxy
   cd app && go mod download

   # Website/docs
   npm install  # from repo root (Turborepo workspace)
   ```

5. **Create a branch** from the appropriate base:
   - Bug fixes for the current release: branch from `main`
   - New features targeting the next release: branch from the active dev branch

## Development setup

### Go Proxy (`app/`)

```bash
go build -o sockguard ./cmd/sockguard/   # Build
go test ./...                              # Run all tests
go test ./internal/filter/...              # Run specific package tests
go test -fuzz=FuzzPathMatch ./internal/filter/  # Fuzz tests
```

### Website (`website/`)

```bash
npm run dev --workspace=website    # Dev server
npm run build --workspace=website  # Production build
```

### Docs (`docs/`)

```bash
npm run dev --workspace=docs       # Dev server
npm run build --workspace=docs     # Production build
```

## Code style

### Go (proxy)

- **Formatter:** `gofmt` / `goimports` (enforced by CI)
- **Linter:** [golangci-lint](https://golangci-lint.run/)
- Line length: no hard limit, use judgement
- Follow [Effective Go](https://go.dev/doc/effective_go) conventions

### TypeScript (website/docs)

- **Linter/formatter:** [Biome](https://biomejs.dev/)
- **Line width:** 100
- **Quotes:** double (Next.js convention)
- **Semicolons:** always

Run from repo root:

```bash
npx biome check .        # Lint
npx biome check --fix .  # Lint + fix
npx biome format --write .  # Format
```

## Commit convention

We use **Gitmoji + Conventional Commits**:

```text
<emoji> <type>(<scope>): <description>
```

| Emoji | Type | Use |
|-------|------|-----|
| :sparkles: | `feat` | New feature |
| :bug: | `fix` | Bug fix |
| :memo: | `docs` | Documentation |
| :lipstick: | `style` | UI/cosmetic changes |
| :recycle: | `refactor` | Code refactor (no feature/fix) |
| :zap: | `perf` | Performance improvement |
| :white_check_mark: | `test` | Adding/updating tests |
| :wrench: | `chore` | Build, config, tooling |
| :lock: | `security` | Security fix |
| :arrow_up: | `deps` | Dependency upgrade |
| :wastebasket: | `revert` | Revert a previous commit |

Scope is optional. Subject line should be imperative, lowercase, no trailing period.

```text
:sparkles: feat(filter): add request body inspection
:bug: fix: resolve socket EACCES (#38)
:recycle: refactor(proxy): simplify middleware chain
```

## Testing

### Go

- **Table-driven tests** using stdlib `testing` package
- **`httptest`** for HTTP handler and middleware tests
- **Fuzz tests** for filter/config parsing
- Coverage target: 90%+

### TypeScript

- Website/docs use framework-provided testing where applicable

## Pre-push checks

[Lefthook](https://github.com/evilmartians/lefthook) runs checks on every push:

| Step | What it does |
|------|-------------|
| `go-lint` | golangci-lint on Go code |
| `go-test` | Full test suite with coverage |
| `biome` | Biome lint and format check on TS/JS |
| `build` | Verify all packages build |

## Pull requests

- **Target branch:** `main` for bug fixes on the current release; the active dev branch for new features
- Keep commits focused and atomic — one concern per commit
- Ensure all pre-push checks pass before opening a PR
- Include tests for new functionality and bug fixes
- Update documentation when changing user-facing behavior

## Reporting bugs

Open a [GitHub Issue](https://github.com/CodesWhat/sockguard/issues) with steps to reproduce.

## Security vulnerabilities

**Do not open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
