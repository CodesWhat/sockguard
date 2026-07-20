# Sockguard Security Pass

Date: 2026-07-20

## Executive summary

Sockguard has a strong baseline security posture: default-deny routing, canonicalized Docker API paths, bounded body inspectors, race and fuzz coverage, non-root container execution, pinned CI actions and container digests, signed-release verification, and explicit acknowledgements for dangerous compatibility modes.

This pass found five actionable issues. All five are remediated, and the hosting-layer fix in SEC-004 was verified on the production website and copied docs export after the v1.4.3 deployment.

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| SEC-001 | High | Owner isolation did not authorize resource references embedded in create/update payloads | Remediated |
| SEC-002 | High | Positive ownership decisions were cached by mutable Docker names for 10 seconds | Remediated |
| SEC-003 | Medium | Startup exfiltration validation omitted image and plugin push endpoints | Remediated |
| SEC-004 | Low | The production website and docs lacked browser hardening headers beyond HSTS | Remediated; production verified |
| SEC-005 | Low | The Helm chart did not pin non-root execution or the runtime-default seccomp profile | Remediated |

The highest-priority issue was SEC-001. Container and service writes now extract and authorize embedded images, volumes, networks, secrets, and configs during the same bounded decode used to stamp owner labels.

No known reachable dependency vulnerabilities or committed high-confidence secrets were found.

## Scope and methodology

Reviewed:

- Go proxy request filtering, ownership, visibility, upstream transport, TLS, body handling, caching, logging, configuration, and administrative surfaces under `app/`
- Website and documentation applications under `website/` and `docs/`
- Docker image, Helm chart, CI workflows, release controls, and repository-wide dependencies
- Live response headers for `https://www.getsockguard.com/` and `https://www.getsockguard.com/docs` on 2026-07-20

Checks run:

- `go test -race ./...`
- `govulncheck -show verbose ./...`
- `gosec -quiet ./...`, followed by source review of every result
- `npm audit --omit=dev --audit-level=low`
- `trivy fs --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --ignore-unfixed`
- `zizmor .github/workflows`
- `npm test`
- `npm run build`
- `npx biome check .`
- `helm lint chart/sockguard`
- `helm template sockguard chart/sockguard`

## Findings

### SEC-001 — Embedded resource references bypass owner isolation

- Status: Remediated on 2026-07-20
- Severity: High
- Category: Authorization / tenant isolation
- CWE: CWE-639, Authorization Bypass Through User-Controlled Key
- Affected configuration: `ownership.owner` is set and the relevant create/update endpoint is allowed
- Locations:
  - `app/internal/ownership/middleware.go`
  - `app/internal/ownership/middleware_test.go`
  - `app/internal/filter/container_create_types.go`
  - `app/internal/filter/container_create.go`
  - `app/internal/filter/service.go`

#### Evidence

`mutateOwnershipRequest` stamps labels on container and service bodies, but only returns authorization targets for the five `container:<ref>` namespace mode fields. `allowOwnershipRequest` then special-cases those namespace references and otherwise checks identifiers parsed from the request URL.

The container-create payload also carries resource identifiers in:

- `Image`
- named volume sources in `HostConfig.Binds` and `HostConfig.Mounts`
- network names in `NetworkingConfig.EndpointsConfig`

The service create/update payload carries resource identifiers in:

- `TaskTemplate.ContainerSpec.Image`
- non-bind volume mounts
- service networks
- service secret and config references

None of those embedded identifiers are resolved through the ownership inspector. The request-body policy intentionally allows named volumes because they are not host bind mounts, and service mount inspection skips every non-bind mount. Service secrets and configs are not part of the filter's decoded policy subset at all.

#### Impact

An owner can create an owner-stamped container that mounts a named volume belonging to another owner, attach it to another owner's network, or run it from another owner's locally stored image. A service create/update can likewise attach foreign volumes, networks, secrets, or configs. This breaks the documented claim that owner labeling turns a shared Docker socket into isolated identity views.

A representative data-access path is:

1. Owner B has a named Docker volume containing sensitive data.
2. Owner A is permitted to call `POST /containers/create`.
3. Owner A supplies a `HostConfig.Mounts` entry with `Type: "volume"` and B's volume name.
4. Sockguard stamps the new container as A-owned but does not inspect the volume.
5. The created container receives B's volume and can expose its contents through an allowed workload output path.

#### Recommended fix

Extract every Docker resource reference from container and service create/update payloads during the existing bounded decode pass, using the same case-insensitive and duplicate-key protections already applied to namespace references. Resolve and authorize each reference before forwarding:

- container image
- named volumes in both bind-string and structured mount forms
- create-time network endpoint keys
- service image, volume mounts, networks, secrets, and configs

Deny foreign and unresolved references according to an explicit policy. Preserve `allow_unowned_images` only for genuinely unlabeled images; it must not permit an image carrying a different owner label. Add table-driven tests for same-owner, foreign-owner, unlabeled, missing, duplicate-case, and multi-reference payloads.

#### Remediation

The ownership mutation pass now extracts container images, named bind-string and structured volumes, custom network modes, all endpoint-config network keys/IDs, service images, named service volumes, networks, secrets, and configs. Each unique reference is freshly inspected before the request is forwarded. Foreign and unresolved dependencies are denied; `allow_unowned_images` applies only to a successfully resolved but genuinely unlabeled image and never overrides a foreign owner label.

Regression coverage includes cross-owner and same-owner matrices for every resource type, unlabeled image/resource behavior, secret-name fallback when the ID is empty, and multiple references. The focused ownership suite and full race suite pass.

#### Temporary mitigation

Do not treat `ownership.owner` as a complete tenant boundary where untrusted clients can create containers or services. Until fixed, deny those endpoints for mutually untrusted owners or isolate them behind separate Docker daemons.

### SEC-002 — Positive ownership decisions are stale for mutable resource names

- Status: Remediated on 2026-07-20
- Severity: High
- Category: Authorization cache / time-of-check-time-of-use
- CWE: CWE-367, Time-of-check Time-of-use Race Condition
- Affected configuration: `ownership.owner` is set
- Locations:
  - `app/internal/ownership/middleware.go`
  - `app/internal/ownership/middleware_test.go`
  - `app/internal/inspectcache/cache.go`
  - `app/internal/ownership/paths.go`

#### Evidence

Ownership inspection uses a shared cache with a 10-second TTL. Its key is the resource kind plus the identifier supplied in the Docker API path. Docker accepts mutable names and tags for many of those identifiers.

The cache correctly avoids storing negative lookups because a missing name can be created during the TTL. It still stores positive label results. If an A-owned name is deleted and recreated or retagged as a B-owned resource, A's next request during the TTL receives the cached A labels while Docker applies the forwarded operation to the current B resource.

#### Impact

Within the deterministic cache window, a request can be authorized against one resource and executed against another. Depending on the endpoint, this can expose, modify, stop, delete, export, attach to, or otherwise operate on a foreign resource. Predictable workload names and rapid reconciliation make name reuse realistic in orchestrated environments.

#### Recommended fix

Do not use mutable names or tags as durable authorization-cache keys. For owner-sensitive operations:

1. Resolve the supplied name to an immutable Docker ID or image digest.
2. Authorize labels for that immutable identity.
3. Forward the operation using the same immutable identity, so the checked and used target cannot diverge.

If path rewriting is not practical for an endpoint, bypass the TTL cache for writes, destructive operations, hijacks, archives, exports, logs, and other sensitive reads. Mutation-driven invalidation alone is insufficient because the daemon can be changed outside this Sockguard instance. Add a regression test where the resolver returns owner A and then owner B for the same name inside the TTL.

#### Remediation

Authorization-critical ownership lookups now bypass `inspectcache` entirely and inspect current Docker state on every request. The cache remains available to visibility-only reads. Embedded references are deduplicated within each request to avoid redundant same-request calls.

An integration-style regression test serves owner A on the first inspect and owner B on the second inspect for the same mutable container name; the second request is denied and the test proves two upstream inspections occurred.

#### Temporary mitigation

Use immutable resource IDs for owner-sensitive requests where clients support them, and avoid sharing a daemon with other controllers that rapidly delete and recreate predictable names.

### SEC-003 — Exfiltration startup guard omits registry push endpoints

- Status: Remediated on 2026-07-20
- Severity: Medium
- Category: Security configuration guardrail
- CWE: CWE-284, Improper Access Control
- Locations:
  - `app/internal/cmd/rules.go`
  - `app/internal/cmd/rules_test.go`
  - `app/internal/proxy/timeout.go`
  - `app/configs/portainer.yaml`

#### Evidence

The startup validator tests archive, export, log, attach, and image-download paths before requiring `insecure_allow_read_exfiltration`. It does not test:

- `POST /images/{name}/push`
- `POST /plugins/{name}/push`

The proxy's timeout classifier explicitly recognizes both as long-lived registry transfer endpoints, so they are known API surfaces. A broad rule such as `method: "*", path: "/images/**"` or `/plugins/**` therefore enables outbound content transfer without triggering the exfiltration acknowledgement.

#### Impact

A client covered by a broad image or plugin management rule can push locally available artifacts to a registry it selects. This can disclose proprietary image layers, embedded application material, or plugin contents. Default deny still protects configurations that do not allow the endpoints, so this is a guardrail gap rather than an unconditional bypass.

#### Recommended fix

Generalize the validator from read-only exfiltration to data-exfiltration endpoints and add representative push sentinels for images and plugins. Add tests for exact push rules, broad wildcards, per-client profiles, and acknowledged configurations. Update the option name or documentation so operators understand that outbound writes can also exfiltrate data.

#### Remediation

The sensitive-exfiltration sentinel set now includes `POST /images/{name}/push` and `POST /plugins/{name}/push`. Startup errors explain that registry pushes read and transmit local artifacts. The existing `insecure_allow_read_exfiltration` key is retained for compatibility, and operator documentation explicitly describes the broader write-side scope.

Regression tests cover exact image/plugin push rules, broad wildcard rules, client-profile rules, and the explicit acknowledgement path.

#### Temporary mitigation

Use method-specific image and plugin rules. Permit `POST /images/create` for pulls without allowing `POST /images/**`, and omit plugin push unless explicitly required.

### SEC-004 — Public sites lack defense-in-depth browser headers

- Status: Remediated and verified in production on 2026-07-20
- Severity: Low
- Category: Browser security hardening
- Locations:
  - `website/vercel.json`
  - `scripts/security-headers.test.mjs`
  - `website/next.config.ts`
  - `docs/next.config.ts`
  - production responses observed on 2026-07-20

#### Evidence

The site and docs are static Next.js exports, and their application configuration does not define a hosting-layer header policy. Live responses include HSTS but did not include:

- `Content-Security-Policy`
- `X-Content-Type-Options`
- clickjacking protection via `frame-ancestors` or `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`

The reviewed `dangerouslySetInnerHTML` uses are build-time constants or statically generated JSON-LD; no direct user-controlled XSS sink was identified.

#### Impact

The public, unauthenticated sites have low direct exposure, but missing headers reduce containment if a dependency, injected script, or hosting misconfiguration introduces active content. Framing and MIME-sniffing protections are also left to browser defaults.

#### Recommended fix

Configure these headers at the CDN or static hosting layer. Roll out a CSP in report-only mode first, then enforce a policy compatible with the static Next.js output and any analytics. Keep the existing HSTS policy.

#### Remediation

`website/vercel.json`, colocated with the configured Vercel project root, now applies a catch-all response-header policy to the marketing site and copied `/docs` export. It includes an enforced CSP, `X-Content-Type-Options: nosniff`, both `frame-ancestors 'none'` and `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and HSTS. Scripts and analytics connections remain same-origin; external scripts and `unsafe-eval` are disallowed. The static Next.js bootstrap and generated styles require inline compatibility, so `unsafe-inline` is scoped to `script-src` and `style-src` rather than opening external origins.

`scripts/security-headers.test.mjs` parses the actual hosting configuration and verifies the catch-all route, required headers, CSP invariants, and absence of external script origins/`unsafe-eval`. The test and both static Next.js builds pass. Production verification after the v1.4.3 deployment confirmed the same contract on both `/` and `/docs`: enforced CSP, `nosniff`, clickjacking protection, strict referrer and permissions policies, HSTS with subdomains, and no `unsafe-eval` allowance.

### SEC-005 — Helm defaults do not enforce the image's non-root identity

- Status: Remediated on 2026-07-20
- Severity: Low
- Category: Kubernetes workload hardening
- Locations:
  - `chart/sockguard/templates/daemonset.yaml`
  - `chart/sockguard/values.yaml`
  - `scripts/helm-security-context.test.mjs`

#### Evidence

The container security context correctly enables a read-only root filesystem, disables privilege escalation, and drops all capabilities. The image also declares a non-root user. The chart does not independently set `runAsNonRoot`, a known UID/GID, or `seccompProfile.type: RuntimeDefault`; the pod-level security context is empty unless an operator overrides it.

#### Impact

There is no current root-execution finding because the shipped image is non-root. The missing Kubernetes controls mean a future image regression or override could run as root, and the workload does not explicitly opt into the runtime-default seccomp policy. This is especially worth pinning for a pod that mounts the host Docker socket.

#### Recommended fix

Set `runAsNonRoot: true` and `seccompProfile: { type: RuntimeDefault }` in chart defaults. Pin `runAsUser: 65532` and `runAsGroup: 65532` if compatible with the documented Docker-socket supplemental group workflow. Add a rendered-chart policy test so future changes preserve these invariants.

#### Remediation

Chart defaults now set `runAsNonRoot: true`, `runAsUser: 65532`, `runAsGroup: 65532`, and `seccompProfile.type: RuntimeDefault`. The documented `supplementalGroups` socket-GID override merges with those secure defaults.

`scripts/helm-security-context.test.mjs` renders the real chart and verifies the pod identity/seccomp policy, existing read-only/no-escalation/drop-all container controls, and the supplemental-group workflow. The rendered-chart tests and `helm lint` pass.

## Reviewed scanner results and accepted conditions

- `go test -race ./...`: passed for all Go packages.
- `govulncheck`: no reachable symbol or imported-package vulnerabilities. It reported GO-2026-5932 in the transitive `golang.org/x/crypto/openpgp` module, but Sockguard does not import or call the affected package.
- `npm audit --omit=dev`: zero production dependency vulnerabilities.
- Trivy: zero high/critical dependency vulnerabilities and no high-confidence committed secrets. Its sole high result is the Docker-socket hostPath alert intrinsic to Sockguard's function; the chart now independently pins non-root identity, seccomp, read-only rootfs, no privilege escalation, and dropped capabilities around that required mount.
- `zizmor`: no unsuppressed GitHub Actions findings.
- `gosec`: findings were reviewed as intentional fixed-point integer conversions, explicit insecure-TLS opt-in behavior, fixed Docker side-channel requests through a custom transport, operator-controlled log paths, or required OS syscalls. No separate exploitable issue was confirmed from those results.
- `npm test`: all 89 tests passed, including the new Vercel policy and rendered Helm tests.
- `npm run build`: both static Next.js workspaces built successfully.
- Biome completed with two pre-existing performance warnings for static `<img>` elements and configuration-version notices; none were security findings.
- Helm linting and rendering completed successfully.

## Positive controls observed

- Request paths are normalized before policy evaluation, including Docker API version stripping and escaped separator/dot-segment handling.
- Body-bearing security inspectors use bounded reads and request-body deadlines.
- Raw write and stream-like data access surfaces are generally fail-closed behind explicit insecure acknowledgements.
- The proxy uses TLS 1.2+ controls, explicit mTLS options, response-header timeouts, and bounded ordinary upstream requests while preserving Docker streaming behavior.
- The runtime container is digest-pinned, minimal, non-root, and built with provenance/SBOM-oriented release controls.
- CI actions are pinned and hardened, with vulnerability, static analysis, race, fuzz, build, and workflow checks already present.

## Remediation status

1. SEC-001: complete — embedded resource authorization and cross-owner regression coverage added.
2. SEC-002: complete — authorization cache bypassed and mutable-name regression coverage added.
3. SEC-003: complete — image/plugin pushes covered by the exfiltration guard and tests.
4. SEC-004: remediated and production verified — static policy checks and live `/` plus `/docs` responses enforce the expected browser-hardening contract.
5. SEC-005: complete — non-root UID/GID and runtime-default seccomp are rendered and tested.
