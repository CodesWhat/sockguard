# Dozzle conformance

Checks that the published [Dozzle](https://github.com/amir20/dozzle) image works
through the `dozzle` preset (`app/configs/dozzle.yaml`) on a real Docker engine,
and that calls the preset forbids stay denied. It is a smaller sibling of the
[tri-tool conformance harness](../tri-tool-conformance/README.md) and follows the
same shape: published images, a JSON evidence file, a route-drift tripwire.

Workflow: `.github/workflows/quality-dozzle-conformance.yml`, weekly and
`workflow_dispatch`. A `workflow_dispatch` run only resolves once the workflow
file is on the default branch.

## What it does

1. Starts sockguard (published image, preset injected as a compose config),
   Dozzle (`amir20/dozzle:v11.5.0`), a marker container that prints a unique
   sentinel every second, and a curl probe, all on a private compose network.
   Nothing is published to the host and no checkout path is bind-mounted, so it
   works against a remote engine.
2. Reads Dozzle's `GET /api/events/stream` and asserts the container list
   includes the marker.
3. `POST /api/containers/logs` for the marker and asserts the sentinel is in the
   response.
4. Reads sockguard's JSON access log and asserts nothing was denied during those
   flows, and that every route shape seen is in `known-routes.json`. Dozzle also
   calls `GET /system/df`, which the preset denies on purpose; it is listed under
   `expected_denials` so it doesn't count as a failure.
5. Sends forbidden calls straight at sockguard (`POST /containers/create`,
   `GET /images/json`, `GET /volumes`, `POST /containers/<id>/stop`), asserts
   each returns 403 and that the denial is in the access log.
6. Writes `dozzle-conformance.json` (assertions, image refs and digests,
   observed routes) and per-service logs under `dozzle-conformance-logs/`.

Dozzle API facts come from amir20/dozzle v11.5.0 (`internal/web/routes.go`,
`events.go`, `container_logs.go`, `internal/container/types.go`) and are noted in
`lib.mjs`.

## Running it

```bash
scripts/dozzle-conformance/run.sh --out ./out
scripts/dozzle-conformance/run.sh --self-test          # no Docker
node --test scripts/dozzle-conformance.test.mjs        # parsing helpers
```

Options: `--sockguard-image REF` (allowlisted sockguard references only, default
`codeswhat/sockguard:latest`), `--dozzle-image amir20/dozzle:<tag>`, `--out DIR`.

The script shells out to `docker` and never starts an engine. For a remote test
engine, put a `docker` shim first on `PATH` that forwards to it.

## Updating known-routes.json

The tripwire fails on any route shape not listed. When Dozzle changes what it
calls, review the preset first. Add the route to `known-routes.json` only if the
preset should allow it, in the same PR. The forbidden probes run after the
tripwire's log snapshot, so they are not listed.

## Not covered

Swarm mode, agent mode, `DOZZLE_ENABLE_ACTIONS` and `DOZZLE_ENABLE_SHELL` are
outside the preset and not exercised beyond the forbidden-call probes.
