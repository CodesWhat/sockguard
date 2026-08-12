# Sockguard Security Assurance Case

Last reviewed: 2026-08-11

This document maps Sockguard's security requirements to its threat model,
implementation controls, and public verification evidence. It complements the
detailed [security model](docs/content/docs/security.mdx) and does not claim
that any Docker API access can be made harmless.

## Security requirements and limits

Sockguard is intended to:

- deny every Docker API operation that is not explicitly permitted;
- canonicalize methods, paths, versions, and inspected request bodies before
  policy decisions so alternate encodings cannot bypass a rule;
- authenticate or tightly scope clients on exposed listeners and require
  explicit acknowledgements for unsafe compatibility modes;
- filter sensitive read responses and isolate resources by client ownership
  where configured;
- apply resource, concurrency, timeout, and body-size limits at network and
  inspection boundaries; and
- publish signed artifacts, SBOMs, and provenance, then verify the published
  artifacts against the expected workflow identity.

An allowed Docker operation still runs with the authority of the Docker daemon.
A policy that allows privileged container creation, host mounts, broad archive
exports, or unrestricted exec can grant host-root impact. Sockguard enforces the
configured policy; it cannot make an intentionally broad policy least privilege.
Supported versions and disclosure commitments are in [`SECURITY.md`](SECURITY.md).

## Threat model and trust boundaries

Threat actors include unauthenticated network clients, an authenticated but
malicious workload, a client trying alternate encodings or body shapes, hostile
Docker daemon responses, a malicious policy update, and a contributor or
dependency attempting to alter a release artifact.

The principal trust boundaries are:

1. **Client to listener.** Unix peer identity, source network, or mTLS identity
   selects a policy profile before a request is admitted.
2. **HTTP request to policy engine.** Method, canonical path, query, headers,
   and inspected bodies become a fail-closed allow or deny decision.
3. **Sockguard to Docker daemon.** Only an allowed and possibly rewritten
   request crosses to the root-equivalent upstream socket.
4. **Docker response to client.** Visibility filters and redaction mediate
   sensitive list, inspect, log, archive, and metadata responses.
5. **Configuration to live policy.** Startup validation and atomic reload keep
   invalid or partially verified policy from becoming active.
6. **Source to release artifact.** CI, review, signing, provenance, SBOM, and
   published-artifact verification protect the supply-chain boundary.

## Claims and evidence

### Fail-safe defaults and complete mediation

No matching rule means deny. Requests pass through one canonical policy engine
before the reverse proxy can reach Docker. Non-loopback plaintext or
unauthenticated listeners and broad read-exfiltration surfaces require explicit,
separately named acknowledgements. Invalid security-critical configuration
prevents startup or reload.

Evidence: [`app/internal/filter/`](app/internal/filter),
[`app/internal/proxy/`](app/internal/proxy),
[`app/internal/config/`](app/internal/config), the bundled policies in
[`app/configs/`](app/configs), and their adjacent tests.

### Canonicalization and body-aware policy

Sockguard decodes escaped separators, removes API-version prefixes, cleans path
segments, and classifies the canonical endpoint before matching. Security-
relevant Docker write bodies are parsed and checked for privileges, mounts,
namespaces, capabilities, resource limits, image trust, ownership, and other
endpoint-specific constraints. Unsupported blind writes remain denied unless an
operator explicitly accepts that risk.

Evidence: the [security model](docs/content/docs/security.mdx),
[`app/internal/filter/`](app/internal/filter), and the fuzz, unit, and real-
daemon integration tests under [`app/`](app).

### Client isolation, transport, and response controls

Remote TCP supports TLS 1.3 and mTLS identity constraints. Unix listeners can
use peer credentials. Per-client profiles, ownership rules, rate and concurrency
limits, bounded bodies, upstream timeouts, and read-side filtering reduce
cross-client access and denial-of-service exposure.

Evidence: [`docs/content/docs/multi-host.mdx`](docs/content/docs/multi-host.mdx),
[`docs/content/docs/configuration.mdx`](docs/content/docs/configuration.mdx),
[`app/internal/`](app/internal), and the public configuration reference.

### Least privilege and defense in depth

The release image runs as UID 65532 and the documented deployment uses a
read-only root filesystem, drops all capabilities, prevents new privileges, and
keeps the raw socket mounted read-only. These container controls reduce
process-level impact while the policy engine remains the primary boundary.

Evidence: [`Dockerfile`](Dockerfile), [`SECURITY.md`](SECURITY.md), and the
hardened deployment examples in [`README.md`](README.md).

### Common weakness, test, and release controls

CI applies formatting, vetting, static security analysis, dependency and image
vulnerability scans, race-enabled tests, real-daemon integration, fuzzing, and
a 96% coverage floor. Monthly mutation testing adds a separate assertion-quality
signal. Releases include signed images and archives, SBOMs, checksums, and
provenance, followed by verification against the expected workflow identity.

Evidence: [`.github/workflows/ci-verify.yml`](.github/workflows/ci-verify.yml),
[`.github/workflows/release-from-tag.yml`](.github/workflows/release-from-tag.yml),
the public [coverage report](https://qlty.sh/gh/CodesWhat/projects/sockguard),
and [`docs/content/docs/verification.mdx`](docs/content/docs/verification.mdx).

## Residual risk

Policy mistakes are the dominant residual risk. An allowed privileged Docker
operation, stolen client identity, compromised daemon, malicious signed policy
publisher, or explicit blind-write/read-exfiltration opt-in can still cause
host-level impact. Operators remain responsible for reviewing policies,
restricting listener reachability, protecting identity material, patching the
host daemon, and validating release signatures before deployment.
