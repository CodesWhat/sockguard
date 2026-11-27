package filter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/codeswhat/sockguard/v3/app/internal/testhelp/podmanspec"
)

// This file is the drift guard for POST /libpod/containers/{name}/update.
//
// The inspector allows an UpdateEntities root key it does not recognize
// (libpodContainerUpdateUnknownFields says why: Podman discards a field its
// own build does not define, so deny-on-unknown refuses working requests on
// every Podman minor that adds one). Allow-unknown is only safe if somebody
// notices when the upstream body grows, which is what these tests are for:
// libpodContainerUpdateKnownFields is assembled from the same gate lists
// inspectLibpod enforces, so it cannot drift from the code, and it is
// compared here against a snapshot of Podman's own type.
//
// TestLibpodContainerUpdateKnownFieldsMatchPodmanSnapshot runs offline on
// every push. TestLibpodContainerUpdateSnapshotMatchesUpstreamPodman refreshes
// the snapshot's other end from Podman's source and is skipped unless
// SOCKGUARD_TEST_PODMAN_UPSTREAM_REF names a ref; the monthly
// quality-api-version-watch.yml workflow sets it.

const (
	libpodUpdateEntitiesSnapshotPath = "../../testdata/podman-api/update-entities-root-fields.json"
	libpodUpdateEntitiesRefEnvVar    = podmanspec.RefEnvVar
)

type libpodUpdateEntitiesSnapshot struct {
	PodmanTag          string   `json:"podman_tag"`
	RuntimeSpecVersion string   `json:"runtime_spec_version"`
	RootFields         []string `json:"root_fields"`
}

func readLibpodUpdateEntitiesSnapshot(t *testing.T) libpodUpdateEntitiesSnapshot {
	t.Helper()

	raw, err := os.ReadFile(libpodUpdateEntitiesSnapshotPath)
	if err != nil {
		t.Fatalf("read %s: %v", libpodUpdateEntitiesSnapshotPath, err)
	}

	var snapshot libpodUpdateEntitiesSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("decode %s: %v", libpodUpdateEntitiesSnapshotPath, err)
	}
	if snapshot.PodmanTag == "" {
		t.Fatalf("%s records no podman_tag; the snapshot is worthless without the release it was taken from", libpodUpdateEntitiesSnapshotPath)
	}
	if len(snapshot.RootFields) == 0 {
		t.Fatalf("%s records no root_fields", libpodUpdateEntitiesSnapshotPath)
	}
	return snapshot
}

// TestLibpodContainerUpdateKnownFieldsMatchPodmanSnapshot fails when Podman's
// UpdateEntities root field set and the inspector's gate lists disagree in
// either direction, naming every field that moved.
//
// A field only upstream is the dangerous direction: it reaches the daemon
// through an inspector that has no gate for it. A field only in the gate
// lists is a typo or a stale entry, which is a gate that can never fire.
func TestLibpodContainerUpdateKnownFieldsMatchPodmanSnapshot(t *testing.T) {
	snapshot := readLibpodUpdateEntitiesSnapshot(t)

	// Folded, because containerUpdateHasAnyField matches with
	// strings.EqualFold and so does encoding/json.
	known := make(map[string]string, len(libpodContainerUpdateKnownFields))
	for _, field := range libpodContainerUpdateKnownFields {
		folded := strings.ToLower(field)
		if previous, ok := known[folded]; ok {
			t.Errorf("gate lists in libpod_container_update.go classify %q twice (already present as %q): inspectLibpod returns on the first gate that matches, so the later gate is dead for that field", field, previous)
			continue
		}
		known[folded] = field
	}

	upstream := make(map[string]struct{}, len(snapshot.RootFields))
	var uninspected []string
	for _, field := range snapshot.RootFields {
		folded := strings.ToLower(field)
		upstream[folded] = struct{}{}
		if _, ok := known[folded]; !ok {
			uninspected = append(uninspected, field)
		}
	}
	if len(uninspected) > 0 {
		slices.Sort(uninspected)
		t.Errorf("Podman %s UpdateEntities carries root field(s) no gate in libpod_container_update.go classifies: %s.\n"+
			"They reach the daemon unfiltered on POST /libpod/containers/{name}/update. Decide which gate each belongs to (libpodContainerUpdateUngoverned, ...BlindWriteFields, ...DeviceFields, ...LifecycleFields, ...ResourceControlFields) and add it there; %s is the pinned upstream set.",
			snapshot.PodmanTag, strings.Join(uninspected, ", "), libpodUpdateEntitiesSnapshotPath)
	}

	var stale []string
	for folded, field := range known {
		if _, ok := upstream[folded]; !ok {
			stale = append(stale, field)
		}
	}
	if len(stale) > 0 {
		slices.Sort(stale)
		t.Errorf("gate lists in libpod_container_update.go name root field(s) Podman %s does not have: %s.\n"+
			"Each one is a gate that can never fire — either a typo, or a field upstream removed. Fix the spelling or drop the entry, and refresh %s if the removal is real.",
			snapshot.PodmanTag, strings.Join(stale, ", "), libpodUpdateEntitiesSnapshotPath)
	}
}

// TestLibpodContainerUpdateAllowsAndReportsUnrecognizedRootFields pins the
// 2026-09-05 decision that allow-unknown stays: a root key the inspector does
// not classify is allowed, and named at debug level so the drift is visible on
// a deployment running a newer Podman than this build was pinned against.
func TestLibpodContainerUpdateAllowsAndReportsUnrecognizedRootFields(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantAllow   bool
		wantLogged  []string
		wantOmitted []string
	}{
		{
			name:       "an unrecognized root field is allowed and named",
			body:       `{"health_startup_grace":"5s","memory_v2":{"limit":1}}`,
			wantAllow:  true,
			wantLogged: []string{"health_startup_grace", "memory_v2"},
		},
		{
			name:        "a known field in a different case is not reported as unknown",
			body:        `{"MEMORY":{"limit":1},"Health_Cmd":"true"}`,
			wantAllow:   false,
			wantOmitted: []string{"MEMORY", "Health_Cmd"},
		},
		{
			name:        "an unrecognized field is still reported when another field denies",
			body:        `{"memory":{"limit":1},"brand_new_podman_field":true}`,
			wantAllow:   false,
			wantLogged:  []string{"brand_new_podman_field"},
			wantOmitted: []string{"memory"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

			req := httptest.NewRequest(http.MethodPost, "/libpod/containers/abc/update", strings.NewReader(tt.body))
			reason, err := newContainerUpdatePolicy(ContainerUpdateOptions{}).inspectLibpod(logger, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspectLibpod() error = %v", err)
			}
			if tt.wantAllow && reason != "" {
				t.Fatalf("inspectLibpod(%q) denied with %q, want allow: an unrecognized root key must not deny", tt.body, reason)
			}
			if !tt.wantAllow && reason == "" {
				t.Fatalf("inspectLibpod(%q) allowed, want deny", tt.body)
			}

			logged := logs.String()
			for _, want := range tt.wantLogged {
				if !strings.Contains(logged, want) {
					t.Errorf("debug log does not name unrecognized field %q; got %q", want, logged)
				}
			}
			for _, unwanted := range tt.wantOmitted {
				if strings.Contains(logged, unwanted) {
					t.Errorf("debug log names %q as unrecognized, but it is a field the inspector classifies; got %q", unwanted, logged)
				}
			}
		})
	}
}

// TestLibpodContainerUpdateUnknownFieldReportIsBounded pins the two caps on
// the debug line. The body cap is 1 MiB and all of it can be root key names,
// so an unbounded report would let an allowed caller drive log volume.
func TestLibpodContainerUpdateUnknownFieldReportIsBounded(t *testing.T) {
	t.Run("caps how many fields are named", func(t *testing.T) {
		root := make(map[string]json.RawMessage, libpodContainerUpdateUnknownFieldLogLimit+3)
		for i := range libpodContainerUpdateUnknownFieldLogLimit + 3 {
			root[fmt.Sprintf("unknown_%02d", i)] = json.RawMessage(`1`)
		}

		got := libpodContainerUpdateUnknownFields(root)
		if len(got) != libpodContainerUpdateUnknownFieldLogLimit+1 {
			t.Fatalf("libpodContainerUpdateUnknownFields() reported %d entries, want %d names plus one overflow marker", len(got), libpodContainerUpdateUnknownFieldLogLimit+1)
		}
		if want := "+3 more"; got[len(got)-1] != want {
			t.Errorf("overflow marker = %q, want %q", got[len(got)-1], want)
		}
		if !slices.IsSorted(got[:libpodContainerUpdateUnknownFieldLogLimit]) {
			t.Errorf("reported names are not sorted, so the log line is not stable across requests: %v", got)
		}
	})

	t.Run("caps one field name and keeps it valid UTF-8", func(t *testing.T) {
		// Multi-byte runes straddling the cut: a naive slice would emit a
		// half rune into the log.
		name := strings.Repeat("é", libpodContainerUpdateUnknownFieldNameLimit)
		got := libpodContainerUpdateUnknownFields(map[string]json.RawMessage{name: json.RawMessage(`1`)})
		if len(got) != 1 {
			t.Fatalf("libpodContainerUpdateUnknownFields() = %v, want one entry", got)
		}
		if len(got[0]) > libpodContainerUpdateUnknownFieldNameLimit+len("...") {
			t.Errorf("reported name is %d bytes, want at most %d", len(got[0]), libpodContainerUpdateUnknownFieldNameLimit+len("..."))
		}
		if !strings.HasSuffix(got[0], "...") {
			t.Errorf("reported name %q is not marked as truncated", got[0])
		}
		if !utf8.ValidString(strings.TrimSuffix(got[0], "...")) {
			t.Errorf("reported name %q is not valid UTF-8", got[0])
		}
	})
}

// TestLibpodContainerUpdateSnapshotMatchesUpstreamPodman re-derives the root
// field set from Podman's own source at SOCKGUARD_TEST_PODMAN_UPSTREAM_REF and
// fails when it disagrees with the committed snapshot. It parses the upstream
// declarations with go/ast rather than grepping them, so an embedded struct
// that moves, or a json tag that changes, is resolved the way encoding/json
// resolves it instead of guessed at.
//
// Skipped without the env var: the rest of the suite has to run offline. The
// monthly quality-api-version-watch.yml workflow sets it to `main`, so an
// UpdateEntities field lands as a red monthly check rather than as an
// uninspected key nobody looks for.
func TestLibpodContainerUpdateSnapshotMatchesUpstreamPodman(t *testing.T) {
	ref := strings.TrimSpace(os.Getenv(libpodUpdateEntitiesRefEnvVar))
	if ref == "" {
		t.Skipf("set %s to a containers/podman ref (a tag such as v6.1.1, or main) to check %s against upstream; this test fetches over the network", libpodUpdateEntitiesRefEnvVar, libpodUpdateEntitiesSnapshotPath)
	}

	snapshot := readLibpodUpdateEntitiesSnapshot(t)

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	wire := podmanspec.ParseStructs(t, podmanspec.FetchSource(ctx, t, "containers/podman", ref, "pkg/api/handlers/libpod/containers.go"))
	handlers := podmanspec.ParseStructs(t, podmanspec.FetchSource(ctx, t, "containers/podman", ref, "pkg/api/handlers/types.go"))
	healthchecks := podmanspec.ParseStructs(t, podmanspec.FetchSource(ctx, t, "containers/podman", ref, "libpod/define/healthchecks.go"))
	defineContainer := podmanspec.ParseStructs(t, podmanspec.FetchSource(ctx, t, "containers/podman", ref, "libpod/define/container.go"))

	specVersion := podmanspec.RuntimeSpecVersion(t, podmanspec.FetchSource(ctx, t, "containers/podman", ref, "go.mod"))
	if specVersion != snapshot.RuntimeSpecVersion {
		t.Logf("containers/podman@%s pins opencontainers/runtime-spec %s; the snapshot was taken at %s", ref, specVersion, snapshot.RuntimeSpecVersion)
	}
	ociSpec := podmanspec.ParseStructs(t, podmanspec.FetchSource(ctx, t, "opencontainers/runtime-spec", specVersion, "specs-go/config.go"))

	// Resolved per declaring file rather than through one merged index, so a
	// type name that also exists in another of these files cannot silently
	// answer for the one we mean.
	owners := map[string]*ast.StructType{}
	for name, file := range map[string]map[string]*ast.StructType{
		"updateEntitiesWire":           wire,
		"UpdateEntities":               handlers,
		"UpdateHealthCheckConfig":      healthchecks,
		"UpdateContainerDevicesLimits": defineContainer,
		"LinuxResources":               ociSpec,
	} {
		declared, ok := file[name]
		if !ok {
			t.Fatalf("containers/podman@%s no longer declares %s where this test expects it; UpdateEntities has been restructured and %s must be regenerated by hand", ref, name, libpodUpdateEntitiesSnapshotPath)
		}
		owners[name] = declared
	}

	fields := map[string]struct{}{}
	podmanspec.FlattenRootFields(t, "updateEntitiesWire", owners, map[string]bool{}, fields)

	upstream := make([]string, 0, len(fields))
	for field := range fields {
		upstream = append(upstream, field)
	}
	slices.Sort(upstream)

	recorded := slices.Clone(snapshot.RootFields)
	slices.Sort(recorded)
	if slices.Equal(upstream, recorded) {
		return
	}

	added := podmanspec.SetDifference(upstream, recorded)
	removed := podmanspec.SetDifference(recorded, upstream)
	t.Errorf("containers/podman@%s UpdateEntities no longer matches %s (pinned at %s).\nAdded upstream: %s\nGone upstream: %s\nUpdate the snapshot's root_fields to the sorted list below, add every new field to a gate list in libpod_container_update.go, and re-run the offline drift test:\n%s",
		ref, libpodUpdateEntitiesSnapshotPath, snapshot.PodmanTag,
		podmanspec.JoinOrNone(added), podmanspec.JoinOrNone(removed), podmanspec.FormatRootFields(upstream))
}
