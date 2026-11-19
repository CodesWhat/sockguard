package ownership

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/dockerresource"
)

const embeddedTestLabel = "com.sockguard.owner"

func embeddedTestRun(t *testing.T, opts Options, resources map[string]map[string]inspectResult, method, path, body string) (code int, forwarded bool, fi *recordingInspector) {
	t.Helper()
	if opts.Owner == "" {
		opts.Owner = "job-123"
	}
	opts.LabelKey = embeddedTestLabel
	fi = &recordingInspector{resources: resources}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		forwarded = true
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec.Code, forwarded, fi
}

func ownerLabel(owner string) inspectResult {
	return inspectResult{labels: map[string]string{embeddedTestLabel: owner}, found: true}
}

func TestServiceTaskTemplateNetworksAreCollected(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"TaskTemplate":{"Networks":[{"Target":"net-a"},{"Target":"net-a"},{"Target":"id1234"}]},"Networks":[{"Target":"net-a"}]}`,
		`{"tasktemplate":{"networks":[{"target":"net-a"},{"TARGET":"id1234"}]},"networks":[{"target":"net-a"}]}`,
	} {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatal(err)
		}
		got := serviceEmbeddedOwnershipReferences(decoded)
		var ids []string
		for _, ref := range got {
			if ref.kind != dockerresource.KindNetwork {
				t.Fatalf("kind = %s", ref.kind)
			}
			ids = append(ids, ref.identifier)
		}
		if want := []string{"net-a", "id1234"}; !reflect.DeepEqual(ids, want) {
			t.Fatalf("ids = %v, want %v (deduplicated across both locations)", ids, want)
		}
	}
}

func TestMiddlewareChecksServiceTaskTemplateNetworks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		path      string
		body      string
		resources map[string]map[string]inspectResult
		wantCode  int
		forwarded bool
	}{
		{
			name:     "foreign network on create",
			path:     "/services/create",
			body:     `{"TaskTemplate":{"Networks":[{"Target":"other-net"}]}}`,
			wantCode: http.StatusForbidden,
			resources: map[string]map[string]inspectResult{
				"networks": {"other-net": ownerLabel("job-999")},
			},
		},
		{
			name:     "foreign network by id, lowercase keys, on owned update",
			path:     "/v1.45/services/svc/update",
			body:     `{"tasktemplate":{"networks":[{"target":"abc123def"}]}}`,
			wantCode: http.StatusForbidden,
			resources: map[string]map[string]inspectResult{
				"networks": {"abc123def": ownerLabel("job-999")},
				"services": {"svc": ownerLabel("job-123")},
			},
		},
		{
			name:     "unlabeled network",
			path:     "/services/create",
			body:     `{"TaskTemplate":{"Networks":[{"Target":"shared"}]}}`,
			wantCode: http.StatusForbidden,
			resources: map[string]map[string]inspectResult{
				"networks": {"shared": {labels: map[string]string{}, found: true}},
			},
		},
		{
			name:      "missing network",
			path:      "/services/create",
			body:      `{"TaskTemplate":{"Networks":[{"Target":"ghost"}]}}`,
			wantCode:  http.StatusNotFound,
			resources: map[string]map[string]inspectResult{},
		},
		{
			name:     "lookup failure",
			path:     "/services/create",
			body:     `{"TaskTemplate":{"Networks":[{"Target":"broken"}]}}`,
			wantCode: http.StatusBadGateway,
			resources: map[string]map[string]inspectResult{
				"networks": {"broken": {err: errors.New("boom")}},
			},
		},
		{
			name:      "same-owner network is forwarded",
			path:      "/services/create",
			body:      `{"TaskTemplate":{"Networks":[{"Target":"mine"}]}}`,
			wantCode:  http.StatusOK,
			forwarded: true,
			resources: map[string]map[string]inspectResult{
				"networks": {"mine": ownerLabel("job-123")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, forwarded, _ := embeddedTestRun(t, Options{}, tt.resources, http.MethodPost, tt.path, tt.body)
			if code != tt.wantCode || forwarded != tt.forwarded {
				t.Fatalf("status = %d forwarded = %v, want %d / %v", code, forwarded, tt.wantCode, tt.forwarded)
			}
		})
	}
}

// TestMiddlewareRefusesTemplatedServiceVolumeAndNetworkNames pins that a
// SwarmKit template in a volume source or network target is refused: it expands
// after the literal text is authorized and can name another owner's resource.
func TestMiddlewareRefusesTemplatedServiceVolumeAndNetworkNames(t *testing.T) {
	t.Parallel()
	bodies := map[string]string{
		"volume source":       `{"TaskTemplate":{"ContainerSpec":{"Mounts":[{"Type":"volume","Source":"{{\"victim-vol\"}}","Target":"/d"}]}}}`,
		"volume source mixed": `{"TaskTemplate":{"ContainerSpec":{"Mounts":[{"Type":"volume","Source":"vol-{{.Task.Slot}}"}]}}}`,
		"lowercase keys":      `{"tasktemplate":{"containerspec":{"mounts":[{"type":"volume","source":"{{\"v\"}}"}]}}}`,
		"template network":    `{"TaskTemplate":{"Networks":[{"Target":"{{\"victim-net\"}}"}]}}`,
		"top-level network":   `{"Networks":[{"Target":"{{\"victim-net\"}}"}]}`,
	}
	for name, body := range bodies {
		for _, path := range []string{"/services/create", "/services/svc/update"} {
			t.Run(name+" "+path, func(t *testing.T) {
				t.Parallel()
				res := map[string]map[string]inspectResult{"services": {"svc": ownerLabel("job-123")}}
				code, forwarded, _ := embeddedTestRun(t, Options{}, res, http.MethodPost, path, body)
				if code != http.StatusForbidden || forwarded {
					t.Fatalf("status = %d forwarded = %v, want a 403 refusal", code, forwarded)
				}
			})
		}
	}
	t.Run("plain names still pass", func(t *testing.T) {
		t.Parallel()
		res := map[string]map[string]inspectResult{
			"volumes":  {"mine": ownerLabel("job-123")},
			"networks": {"mine-net": ownerLabel("job-123")},
		}
		body := `{"TaskTemplate":{"ContainerSpec":{"Mounts":[{"Type":"volume","Source":"mine"}]},"Networks":[{"Target":"mine-net"}]}}`
		code, forwarded, _ := embeddedTestRun(t, Options{}, res, http.MethodPost, "/services/create", body)
		if code != http.StatusOK || !forwarded {
			t.Fatalf("status = %d forwarded = %v", code, forwarded)
		}
	})
}
