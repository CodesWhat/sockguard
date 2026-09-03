# Tri-tool conformance harness (#150)

Driver for `.github/workflows/quality-tri-tool-conformance.yml`, which boots
the audited [`examples/compose/tri-tool/`](../../examples/compose/tri-tool/)
bundle from **published images only** (never source-built) and asserts the
behavior contract that bundle's `README.md` and the `app/configs/portwing*.yaml`
/ `drydock*.yaml` presets document. It exists because source-level compat
testing did not catch the 2026-07-28 audit's failures — a broken published
image reference and fresh-volume socket ownership — the class of bug that
only shows up against what `ghcr.io`/`docker.io`/`quay.io` actually publish.

## Matrix rows

| Row | sockguard | portwing | drydock | Mode |
|---|---|---|---|---|
| `current-standard` | input/newest stable release | `latest` | `latest` | Standard (shared secret) + Ed25519 identity acceptance |
| `current-edge` | input/newest stable release | `latest` | `latest` | Edge (Ed25519) + configured exec |
| `legacy-floor` | input/`1.5.1` | `0.8.1` | `1.5.2` (+`DD_EXPERIMENTAL_PORTWING=true`) | Standard only |

`legacy-floor`'s pins are the audited-floor versions from sockguard PR #155
and are **not** overridable by the workflow's `portwing_version`/
`drydock_version` dispatch inputs — that row exists specifically to keep the
compatibility promise honest, so letting a manual override drift it would
defeat the point. Edge mode is unsupported on portwing 0.8.1 and isn't
tested there.

`current-standard`/`current-edge`'s sockguard default is **not** a floating
`latest` the way portwing/drydock's is on those same rows: `run-matrix.sh`
resolves it once, at run time, from local `git tag` history (`git tag
--list 'v*' --sort=-v:refname`, prerelease tags filtered out — the same
logic `release-cut.yml`'s "Find latest release tag" step uses) to a
concrete version like `codeswhat/sockguard:1.7.1`.

Newest-first, it stops at the first tag whose image is actually published
(`docker manifest inspect`), because a tag and its image aren't
simultaneous — `v1.7.1` is pushed minutes before release-from-tag finishes
publishing `codeswhat/sockguard:1.7.1`, and a failed publish job leaves a
tag with no image behind indefinitely. "Current" means the newest sockguard
you can actually pull, not the newest one tagged. Each skipped tag is
announced on stderr, so a broken publish shows up in the log instead of
passing quietly as an older version. A registry it can't reach is fatal,
not a reason to walk back. That's deliberate: we
already burned three CI runs bisecting a failure on a row that just said
`latest` and left no record of what image that actually was at the time.
The resolved triple is echoed into both the run log (`sockguard=... portwing=...
drydock=...`) and the job summary table, so a red run always names its own
inputs (#289 item 2).

## Running it

```
scripts/tri-tool-conformance/run-matrix.sh --row current-standard
scripts/tri-tool-conformance/run-matrix.sh --row current-edge \
  --portwing-version 0.9.2 --drydock-version 1.6.0
scripts/tri-tool-conformance/run-matrix.sh --self-test   # jq + awk only, no Docker
```

Needs `bash`, `curl`, `jq`, `docker`, `docker compose`, and `openssl` on
`PATH`, plus a real Docker daemon at `/var/run/docker.sock` (the GitHub-hosted
`ubuntu-latest` runner ships all of this; there is no dind container, no
special privileges — the harness measures what a real deployment would
actually see, same rationale as `quality-integration.yml`).

Each row is fully independent: fresh named volumes and fresh secrets every
run (`docker compose down -v` guard plus a unique project name), a fresh
`conformance-<row>.json` artifact armed before setup and written on every exit
after row selection, pass or fail, plus full teardown (including any throwaway
sentinel containers and negative-auth-probe containers) via an `EXIT` trap.

## Assertions (in order)

1. **Pristine boot** — fresh volume, sockguard reaches healthy with **no**
   manual ownership repair: socket owner `65532:65532` mode `600`, plus a
   real `_ping` through it. Mirrors `ci-verify.yml`'s "Verify fresh
   socket-volume startup" step.
2. **Auth handshake** — drydock logs `Handshake successful` for the portwing
   agent, plus one negative probe per mode: Standard fires a throwaway
   second drydock agent-config with the wrong shared secret and expects a
   `401` in its logs; Edge fires a throwaway second portwing agent-config
   with an unregistered Ed25519 key and expects a rejection
   (`bad-signature`/`unknown-key`/similar) in drydock's logs. Neither probe
   ever touches the row's real containers.
3. **Identity lifecycle** — `current-standard` starts an isolated second
   published Portwing + drydock pairing on the row's real sockguard socket.
   A wrong enrollment credential is denied without burning the single-use
   credential; the enrolled key authenticates a real controller; reuse is
   denied. The agent then hot-reloads an overlapping replacement key on
   `SIGHUP`, accepts fresh handshakes from both controllers, revokes the old
   key on a second reload, and rejects that controller with
   `X-Portwing-Reason: unknown-key` while the replacement stays healthy. A
   final published controller runs with a test-only `Date.now()` offset, is
   rejected with `X-Portwing-Reason: timestamp-skew`, then recovers in the same
   process after the offset returns to zero. A transparent TCP observer running
   inside the exact published Drydock image forwards controller traffic
   byte-for-byte and records the real HTTP response status and reason header;
   Portwing's JSON denial logs remain a second required signal. The other rows
   record explicit skips because this five-operation gate needs to run once
   against the current tagged pair, not once per transport or compatibility
   floor.
4. **Inventory & inspect** — passive: polls sockguard's own access log for
   Portwing's organic `GET /containers/json` + `GET /containers/*/json`
   polling traffic.
5. **Events** — creates and removes a sentinel container directly through
   the proxied socket; probes `GET /events` through the proxy expecting a
   `200` on the stream open (sockguard only writes an access-log line when
   a request completes, and the events stream outlives the row — #211), and
   asserts the `DELETE` shows up allowed in sockguard's access log.
6. **Logs** — creates a running sentinel with a distinctive stdout marker
   and fetches `GET /containers/{id}/logs` through the proxied socket,
   asserting the marker comes back.
7. **Lifecycle** — stop/start/restart the same sentinel through the proxied
   socket; asserts `docker inspect` converges to the expected state after
   each.
8. **Configured exec** — `current-edge` only. A non-privileged exec
   create+start succeeds; a `Privileged: true` exec create is denied `403`
   with a documented reason (`sockguard-with-exec.yaml`'s
   `allow_privileged: false` gate, `deny_verbosity: verbose` since #158).
9. **Remote update trigger** — creates a sentinel pinned at an old
   `busybox` digest through the proxied socket, waits for it to reach
   drydock's own `GET /api/v1/containers` store (paginated `{data: [...]}`
   envelope on the `legacy-floor` 1.5.2 pin and on the current release the
   `current-*` rows resolve — presence proves the full sockguard-mediated
   Portwing inventory-sync path; anything else on a `2xx` is treated as a
   harness failure rather than polled to a timeout), then fires
   `POST /api/v1/triggers/docker/update` (agent-qualified when the document
   names one) with the required `{id: <drydock container id>}` body — the
   shape pinned from drydock's `app/api/trigger.ts` (#211). Every row
   passes only on the documented refusal: the audited bundle configures no
   docker update trigger in drydock, and the published pair cannot compute
   update candidates in this topology anyway (drydock's watch-now delegates
   registry checks to the Portwing agent, whose watcher endpoint answers
   `501` expecting controller-side checking). drydock 1.5.2 refuses with
   `404` `{"error":"Remote update trigger <name> not found"}` (the middle is
   the agent-qualified trigger name, so the match is on `trigger ... not
   found` rather than a literal string); 1.6.x gets one step further and refuses with
   `400` "No update available for this container", which still means it
   accepted the request shape. **Both accepted refusals are matched on the
   response body, not on the status alone** — a wrong trigger URL also
   answers `404`, so a bare-status check would pass while testing nothing,
   which is the same shape as the bug that hid in the store poll. A `2xx` —
   an unconfigured trigger executing — or anything else, including drydock's
   other `400` "Invalid trigger request body" — is a failure that prints the
   status and body. The body is what separates the
   two `400`s, so this stays version-agnostic rather than branching on a
   drydock version.
10. **Expected denials** — `POST /build` denied with a reason;
   `POST /containers/*/exec` denied on the non-exec preset (skipped on
   `current-edge`, which runs the exec-enabled preset by design — see
   assertion 8 for its denial case instead); `GET /containers/{id}/export`
   (exfiltration-gated read) denied.
11. **Route-drift tripwire** — see below.

## Verification strategy: why assertions 4–10 key on sockguard's access log

Portwing's and drydock's own HTTP/WS APIs aren't documented anywhere in
*this* repo — their JSON shapes live in the portwing/drydock repos, which
this harness has no access to pin against. Rather than guess at those
shapes and risk a harness that silently asserts the wrong thing, assertions
4–10 drive Docker Engine API calls **directly through sockguard's proxied
socket** (exactly the shape Portwing itself sends, per the presets) and
verify outcomes against **sockguard's own structured access log** — the one
interface this repo fully owns, documents, and tests
(`app/internal/logging/access.go`). This proves the sockguard-side half of
every contract precisely; it does not re-verify Portwing's or drydock's own
internal wiring, which is out of scope for a sockguard-repo CI job and
belongs to those projects' own test suites.

## Route-drift tripwire

After a row's scenario traffic runs, `assert_route_drift` captures
sockguard's full access log (`docker compose logs sockguard`, which is JSON,
one line per request — `log.format: json` / `access_log: true` in every
tri-tool preset) and normalizes each `(method, normalized_path)` pair into a
route **shape**: a path segment that's one of the fixed Docker API keywords
the presets match on literally (`containers`, `json`, `start`, `_ping`, …) is
kept as-is; the harness reads sockguard's `normalized_path` field, which
already has the `/vX.YZ/` Docker API version prefix stripped, so the
normalizer only has to handle segment-level dynamism. Every other segment
(container/network/volume/service/exec IDs and names, image references)
becomes `*`, and a run of consecutive dynamic segments collapses to `**` —
see `normalize-routes.jq`'s header comment for the exact rules.

The resulting shapes are diffed against
[`known-routes.json`](known-routes.json), which was seeded by hand-enumerating
every allow rule in `app/configs/portwing.yaml` and
`app/configs/portwing-with-exec.yaml` (the union of both, since
`legacy-floor`/`current-standard` run the plain preset and `current-edge`
runs the exec preset) plus the two deliberate-denial probe shapes assertion
10 sends (`POST /build`, `GET /containers/*/export`) so those expected
denials don't themselves trip the tripwire.

**Any route observed that isn't in the manifest fails the job** with:

> peer repository sent a route sockguard policy has not reviewed — review
> policy, then update known-routes.json

This is the literal implementation of "a route added by either peer
repository fails conformance until Sockguard policy is reviewed." It is
intentionally one-directional: a manifest entry that's never observed in a
given run is not a failure (not every scenario exercises every allowed
route every time), only an *unexpected* observed route is.

**Zero observed routes fails closed, too.** An empty observed set is not
treated as an empty (trivially-passing) diff — it almost always means log
capture or the normalizer broke, not that nothing happened, and PASSing
that silently would defeat the whole tripwire. `assert_route_drift` records
a `FAIL` ("no access-log records captured — log capture or shape broke")
instead.

### Updating `known-routes.json`

The manifest was seeded from static analysis of the presets, not from a
live run — **the first real `workflow_dispatch` (or the first weekly
schedule run) may legitimately surface additions**, e.g. a route Portwing
or drydock started calling as part of a feature this repo hasn't reviewed
yet, or simply a scenario shape this harness didn't anticipate. Do not
rubber-stamp a failure here: when it fires, (1) confirm the new route shape
against the relevant sockguard preset's intent, (2) decide whether it should
be allowed at all, and only then (3) add it to `known-routes.json` in the
same PR that reviews the policy question — never as a silent, unreviewed
addition.

### Self-testing the normalizer without Docker

`run-matrix.sh --self-test` exercises `normalize-routes.jq` and the
`known-routes.json` diff against
[`testdata/access-log-fixture.jsonl`](testdata/access-log-fixture.jsonl) — a
fixture with 7 real access-log-shaped lines (6 already in the manifest, 1
deliberately absent: `GET /containers/*/attach`, which no preset ever
allows and which isn't one of assertion 10's probe shapes either), one
access-log-shaped line with `normalized_path` missing entirely, one
non-access-log line (`msg: startup`), one bare-string JSON value (valid
JSON, not an object), and one line that isn't JSON at all. A correct run
produces exactly 6 route shapes and isolates exactly the one unknown route,
and both `normalize-routes.jq` and `lib.sh`'s `ACCESS_LOG_ROUTE_MATCH_JQ`
must tolerate the three malformed/partial lines without erroring. The
self-test also proves `route_drift_status` fails closed (not an
empty-diff PASS) when given zero observed routes. This needs only `jq` and
`awk` (the SIGPIPE regression pin generates its synthetic stream with awk) — no
Docker, no network — and is wired into `npm test` via
`../tri-tool-conformance-run-matrix.test.mjs` (one directory up, since
`package.json`'s test script globs `scripts/*.test.mjs` non-recursively)
plus a dedicated `self-test` job in `quality-tri-tool-conformance.yml`
itself.

## Artifacts

Each row writes `conformance-<row>.json` and a
`conformance-<row>-logs/` directory to the repo root (uploaded by the workflow
with 90-day retention, always, pass or fail). The JSON contains: timestamp,
matrix row, resolved image refs *and* digests
(`docker image inspect --format '{{index .RepoDigests 0}}'`, captured right
after `compose up` in `assert_pristine_boot` — from the images the row
actually ran, not a re-pull at the end that could catch a tag having moved
mid-run) for all three tools, Docker Engine version + API
version (via `GET /version` through the proxy), the sockguard preset in use,
the portwing mode, identity key ids, Portwing denial-log counts, and exact
response-header observation counts when the identity lane runs, every observed
route shape, and per-assertion pass/fail/skip with a detail string. The logs
directory preserves the compose stack, each identity agent/controller log, and
the response-header observer log. A valid row arms this output before image
resolution or Docker setup, so a setup failure preserves its original exit
status while still writing a failed JSON verdict and diagnostics. Missing
artifacts fail their matrix upload. The workflow's `summary` job aggregates all
three rows into `$GITHUB_STEP_SUMMARY`.

## Live behavior notes and resolved gaps

The harness began as an offline implementation, then was corrected against
live published-image runs. These notes retain the important contracts and the
failure modes those runs exposed:

- **The v1.0 identity acceptance sequence is exercised by real published
  processes.** The harness never handcrafts a signed request. Drydock v1.6.0's
  own Standard-mode client performs every authenticated request. The clock
  fault is injected into that same published Node process by overriding only
  `Date.now()`, the clock its signer reads; changing the mounted offset back to
  zero proves recovery without a restart. A raw TCP observer running from the
  exact Drydock image forwards those signed requests unchanged and captures the
  actual `X-Portwing-Reason` response header. Both that exact header and
  Portwing's matching JSON reason log are required for the `unknown-key` and
  `timestamp-skew` negative controls. The observer mounts no controller private
  material.

- **Assertion 9's trigger-invocation HTTP contract** — RESOLVED across the
  2026-08-08/09 live runs (#211) and a local repro against the published
  pair. The body requires drydock's own container-store `id` (400 "Invalid
  trigger request body" otherwise, on every drydock version). `GET
  /api/v1/containers` returns a paginated `{data: [...]}` envelope on both
  drydock latest and the 1.5.2 legacy pin — the first store-poll read it
  as a bare array and could never see the sentinel. The unversioned
  `/api/containers`/`/api/triggers/*` aliases this assertion used until
  CodesWhat/drydock#802 were removed (410) in drydock v1.6.0; polling
  them silently produced the same empty-result timeout as a real sync
  failure, because the 410 body fed straight into `jq '.data // .'`, the
  resulting type error went to `2>/dev/null`, and an empty result is what
  a real sync failure looks like too. The harness now uses `/api/v1` and
  fails loudly on a non-2xx response or a jq parse error instead of
  swallowing both. And the update flow itself is bounded by the audited
  bundle: no docker update trigger is configured in drydock
  (correctly-shaped invocations are refused on every version, 404 "trigger
  not found" on 1.5.2 and 400 "No update available for this container" on
  1.6.x), and the published pair cannot
  flag `updateAvailable` in this topology at all — drydock's watch-now
  delegates registry checking to the Portwing agent
  (`Error watching on agent: Request failed with status code 501`), while
  Portwing's watcher endpoint answers 501 expecting the controller to do
  it. Assertion 9 therefore asserts store sync plus the documented refusal
  on every row, and drops the `updateAvailable`/recreation expectations
  that no published pairing can satisfy.
- **Assertion 9's store-population cadence** — RESOLVED by the 2026-08-09
  live run. Portwing has no Docker-events subscription: its container
  inventory refreshes once at startup, then on a fixed tick defaulting to
  `DD_POLL_INTERVAL=300` seconds, so a sentinel created mid-run could never
  reach drydock's store inside the assertion's 120s wait (drydock itself
  ingests a `container-added` agent event immediately — the bottleneck is
  purely Portwing's tick). The conformance overlay now sets
  `DD_POLL_INTERVAL=5` on the portwing service, test-only, keeping the
  audited bundles at their documentation-grade defaults. **Edge caveat**
  (round 6): the overlay cannot speed up `current-edge` — Portwing's edge
  client takes its refresh cadence from the `pollInterval` in drydock's
  WebSocket welcome, which drydock hardcodes to 300s with no override
  (`app/api/portwing-ws.ts`), so that row's store wait is 360s (one full
  poll cycle plus slack) instead of 120s.
- **The access-log wait's pipeline exit status** — RESOLVED in round 6.
  `wait_for_access_log_route` ended its pipeline with `grep -q`, which
  exits on the first match; when the route matched more than once (portwing
  polling every 5s guarantees it), jq took SIGPIPE writing the next match
  and `pipefail` reported the wait as failed with the routes plainly in the
  log. That failed `inventory-inspect` on every standard row of the v1.6.0
  gate — deterministically, and only when traffic was healthy. The matcher
  tail now reads to EOF (`grep -c`), and `--self-test` pins the regression
  with a 5000-match synthetic stream.
- **Portwing's exact protected-endpoint surface for the wrong-secret probe.**
  `assert_standard_wrong_secret_probe` observes the failure from drydock's
  own logs (`401`) rather than calling a specific portwing endpoint
  directly, precisely to avoid needing to know that surface — but the exact
  log text portwing/drydock emit for this case is inferred from the tri-tool
  README's troubleshooting prose, not pinned by a test in either repo.
- **Exact drydock rejection log text for an unknown Edge key.**
  `assert_edge_unknown_key_probe` matches
  `bad-signature|unknown-key|unauthorized|reject` (case-insensitive) against
  drydock's logs, again inferred from the README's troubleshooting section
  rather than a pinned string.

None of these notes weaken assertions 1, 4–8, 10, or 11, which are grounded
entirely in sockguard's own documented, tested surface.
