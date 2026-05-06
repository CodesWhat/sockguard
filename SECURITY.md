# Security Policy

## Supported Versions

Sockguard is pre-1.0 and we ship fixes on the latest minor line only. Once
1.0 lands we'll commit to a rolling window.

| Version        | Supported          |
| -------------- | ------------------ |
| 0.5.x (latest) | :white_check_mark: |
| < 0.5          | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in sockguard, please report it
responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use
[GitHub's private vulnerability reporting](https://github.com/CodesWhat/sockguard/security/advisories/new)
or email **<security@getsockguard.com>**. GitHub private reports are
preferred because they keep report details private and tie disclosure to
the advisory and fix workflow.

For non-security contact, email **<hello@getsockguard.com>**.

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
- The docs site under `docs/` and served at `getsockguard.com/docs`.
  Same — regular issues.
- Third-party deployments of sockguard. If you find a misconfigured
  compose file in the wild, contact that operator directly. We can
  help triage but we can't ship a fix for it.
- Denial-of-service via CPU/memory exhaustion from an allowlisted
  client that already has full Docker-socket access. Sockguard's trust
  boundary is the client CIDR; a client inside the trust boundary is
  assumed to be cooperating in good faith.

### Why sockguard runs as root inside the container

Sockguard defaults to root inside the container because its job is to
open `/var/run/docker.sock`, and that socket is already a
root-equivalent trust boundary on a stock Docker host. In the threat
model that matters for a Docker socket proxy, an attacker who can coerce
sockguard into sending arbitrary Docker API requests can ask the daemon
to create a privileged container, mount `/`, or otherwise pivot onto the
host regardless of whether the proxy process is UID 0 or UID 65534.

A non-root image default therefore adds more compatibility friction than
meaningful protection: on typical hosts `/var/run/docker.sock` is
`root:docker`, so a non-root container needs `user`, `group_add`, or
host-specific gid plumbing before the proxy can even start. Sockguard
chooses the drop-in default and treats runtime hardening as an explicit
deployment concern instead.

The controls that materially harden this class of tool are:

- **Policy correctness** — deny dangerous Docker API methods, paths, and
  request bodies unless they are explicitly required.
- **Read-only root filesystem** — set `read_only: true` so a compromised
  process cannot persist inside the container filesystem.
- **Dropped Linux capabilities** — set `cap_drop: [ALL]`; sockguard does
  not need ambient capabilities.
- **No new privileges + seccomp** — set
  `security_opt: ["no-new-privileges:true"]` and keep Docker's default
  seccomp profile or replace it with a stricter custom one.
- **AppArmor/SELinux confinement** — keep your runtime's default profile
  or apply a stricter host policy.
- **Rootless Docker on the host** — reduce the daemon's authority at the
  actual trust boundary.

See the Compose examples in `README.md` and the docs site's getting
started guide for concrete `read_only`, `cap_drop`, and `security_opt`
examples.

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
