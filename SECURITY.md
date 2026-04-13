# Security Policy

## Supported Versions

Sockguard is pre-1.0 and we ship fixes on the latest minor line only. Once
1.0 lands we'll commit to a rolling window.

| Version        | Supported          |
| -------------- | ------------------ |
| 0.3.x (latest) | :white_check_mark: |
| < 0.3          | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in sockguard, please report it
responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **<80784472+s-b-e-n-s-o-n@users.noreply.github.com>** or use
[GitHub's private vulnerability reporting](https://github.com/CodesWhat/sockguard/security/advisories/new).

You can expect:

- **Acknowledgement** within 48 hours
- **Status update** within 7 days
- **Fix or mitigation** as soon as feasible, depending on severity

We appreciate responsible disclosure and will credit reporters in the
release notes unless you prefer to stay anonymous.

## Scope

**In scope**

- The Go proxy at `app/` — filter engine, ownership middleware, client
  ACLs, hijack/upgrade handling, access log, `/health` endpoint, config
  parsing, CLI flags.
- The published container image at `ghcr.io/codeswhat/sockguard:<tag>`,
  including its SBOM, build provenance, and cosign signatures.
- Any compiled binary distributed via a GitHub release tagged
  `v0.x.x` or later.

**Out of scope**

- The marketing website under `website/` and anything served from
  `getsockguard.com`. Report bugs here via a regular GitHub issue.
- The docs site under `docs/` and `docs.getsockguard.com`. Same —
  regular issues.
- The interactive rule tester under `demo/`. It runs entirely in the
  browser, has no server component, and never talks to a real Docker
  socket.
- Third-party deployments of sockguard. If you find a misconfigured
  compose file in the wild, contact that operator directly. We can
  help triage but we can't ship a fix for it.
- Denial-of-service via CPU/memory exhaustion from an allowlisted
  client that already has full Docker-socket access. Sockguard's trust
  boundary is the client CIDR; a client inside the trust boundary is
  assumed to be cooperating in good faith.

If you're unsure whether something is in scope, err on the side of
reporting — we'd rather deduplicate than miss a real bug.

## What to include in a report

A good report makes triage fast and reduces the risk we misread the
severity. Please include as much of the following as you can:

- **Sockguard version and image digest** — `sockguard --version` and
  the digest of the image you tested (`docker image inspect`).
- **Reproducer** — the minimal config, rules, and request(s) that
  demonstrate the issue. If the repro needs a specific Docker daemon
  version, mention which one.
- **Observed behavior** — what sockguard did, including any relevant
  access-log lines and exit codes. Redact hostnames, IPs, or container
  names if you prefer — we don't need them to understand the bug.
- **Expected behavior** — what you believe sockguard should have done
  instead, and why (policy intent, Docker API semantics, etc.).
- **Impact assessment** — your read on severity, who it affects, and
  whether it requires authentication, a compromised client, or
  physical access.
- **Disclosure timeline** — when you found it, whether you've told
  anyone else, and whether a specific embargo date suits you.

If the bug involves a supply-chain concern (a tampered image, a cosign
verification failure, a compromised dependency), also include the
exact `cosign verify` command you ran and its full output. See the
[image verification guide](./docs/src/content/verification.mdx) for
the canonical invocation.
