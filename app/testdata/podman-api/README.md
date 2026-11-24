# Podman API field snapshots

Each JSON file here pins the root request-body keys of one libpod endpoint, taken from containers/podman source at a recorded tag. The drift tests fail when a classification or gate list and its snapshot disagree, so a field Podman adds shows up as a red test instead of an uninspected key.

| File | Endpoint | Upstream file | Tag | Read by |
| --- | --- | --- | --- | --- |
| `spec-generator-root-fields.json` | `POST /libpod/containers/create` | `pkg/specgen/specgen.go` (`SpecGenerator`) | v6.2.0 | `app/internal/ownership/libpod_spec_generator_drift_test.go` |
| `pod-spec-generator-root-fields.json` | `POST /libpod/pods/create` | `pkg/specgen/podspecgen.go` (`PodSpecGenerator`) | v6.2.0 | `app/internal/ownership/libpod_spec_generator_drift_test.go` |
| `update-entities-root-fields.json` | `POST /libpod/containers/{name}/update` | `pkg/api/handlers/libpod/containers.go` and friends (`updateEntitiesWire`) | v5.8.1 (re-verified at v6.1.1) | `app/internal/filter/libpod_container_update_drift_test.go` |

The file's own `podman_tag`, `recorded` and `fetch` keys are the record for that file.

## Checking against upstream

Offline, the tests compare the committed snapshot with the classifications. Set the ref to also compare the snapshot with Podman's source, fetched over the network and parsed with go/ast (the shared helpers are in `app/internal/testhelp/podmanspec`):

```sh
cd app
SOCKGUARD_TEST_PODMAN_UPSTREAM_REF=v6.2.0 go test ./internal/ownership/ ./internal/filter/ -run 'SpecGenerator|UpdateSnapshot' -count=1
```

The monthly `quality-api-version-watch.yml` workflow runs the same check against `main`.

## Regenerating a snapshot

On a mismatch the test prints the sorted `root_fields` list to paste into the file. Then bump `podman_tag` and `recorded`, classify every new field in the matching test file (reference, host path or inert for the ownership tests, a gate list for the update test), and re-run the offline tests. If a new field could affect isolation (namespaces, mounts, devices, privileges, network, user, cgroups), confirm the create inspector in `app/internal/filter` already holds it before calling it inert.
