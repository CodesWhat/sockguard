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

func TestContainerIdentifierAuthorizesTheWholeSlashBearingName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method, path, want string
		ok                 bool
	}{
		{http.MethodPost, "/containers/web/stop", "web", true},
		{http.MethodPost, "/containers/A/x/stop", "A/x", true},
		{http.MethodPost, "/containers/A/x/kill", "A/x", true},
		{http.MethodPost, "/containers/A/x/update", "A/x", true},
		{http.MethodPost, "/containers/A/x/exec", "A/x", true},
		{http.MethodPost, "/containers/A/x/attach", "A/x", true},
		{http.MethodGet, "/containers/A/x/attach/ws", "A/x", true},
		{http.MethodGet, "/containers/A/x/archive", "A/x", true},
		{http.MethodPut, "/containers/A/x/archive", "A/x", true},
		{http.MethodHead, "/containers/A/x/archive", "A/x", true},
		{http.MethodGet, "/containers/A/x/json", "A/x", true},
		{http.MethodDelete, "/containers/A/x", "A/x", true},
		{http.MethodDelete, "/containers/web", "web", true},
		{http.MethodPost, "/containers/create/start", "create", true},
		{http.MethodGet, "/containers/json/json", "json", true},
		{http.MethodPost, "/containers/create", "", false},
		{http.MethodPost, "/containers/prune", "", false},
		{http.MethodGet, "/containers/json", "", false},
	}
	for _, tt := range tests {
		got, ok := containerIdentifier(tt.method, tt.path)
		if got != tt.want || ok != tt.ok {
			t.Errorf("containerIdentifier(%s, %q) = (%q, %v), want (%q, %v)", tt.method, tt.path, got, ok, tt.want, tt.ok)
		}
	}
}

// TestMiddlewareChecksTheFullNameOfASlashBearingContainerRoute pins the fix for
// a legacy link alias: "/A/x" names the linked victim, and POST
// /containers/A/x/stop used to be authorized as container "A", the caller's own.
func TestMiddlewareChecksTheFullNameOfASlashBearingContainerRoute(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	requests := []struct {
		method, target, want string
	}{
		{http.MethodPost, "/containers/A/x/stop", "A/x"},
		{http.MethodPost, "/v1.45/containers/A/x/kill?signal=KILL", "A/x"},
		{http.MethodPost, "/containers/A%2Fx/stop", "A/x"},
		{http.MethodPost, "/containers/A/x/update", "A/x"},
		{http.MethodPost, "/containers/A/x/exec", "A/x"},
		{http.MethodPost, "/containers/A/x/restart", "A/x"},
		{http.MethodPost, "/containers/A/x/rename?name=z", "A/x"},
		{http.MethodGet, "/containers/A/x/archive?path=/etc", "A/x"},
		{http.MethodGet, "/containers/A/x/json", "A/x"},
		{http.MethodGet, "/containers/A/x/logs", "A/x"},
		{http.MethodGet, "/containers/A/x/attach/ws", "A/x"},
		{http.MethodDelete, "/containers/A/x?force=1", "A/x"},
		{http.MethodPost, "/containers/web/stop", "web"},
		{http.MethodDelete, "/containers/web", "web"},
	}
	for _, req := range requests {
		for _, tc := range []struct {
			name      string
			labels    map[string]string
			found     bool
			err       error
			wantCode  int
			forwarded bool
		}{
			{name: "foreign", labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true, wantCode: http.StatusForbidden},
			{name: "unlabeled", labels: map[string]string{}, found: true, wantCode: http.StatusForbidden},
			{name: "missing", wantCode: http.StatusNotFound},
			{name: "lookup error", err: errors.New("boom"), wantCode: http.StatusBadGateway},
			{name: "same owner", labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true, wantCode: http.StatusOK, forwarded: true},
		} {
			t.Run(req.method+" "+req.target+" "+tc.name, func(t *testing.T) {
				t.Parallel()
				fi := &recordingInspector{resources: map[string]map[string]inspectResult{
					string(dockerresource.KindContainer): {req.want: {labels: tc.labels, found: tc.found, err: tc.err}},
				}}
				forwarded := false
				handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					forwarded = true
				}))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(req.method, req.target, strings.NewReader(`{}`)))
				if rec.Code != tc.wantCode || forwarded != tc.forwarded {
					t.Fatalf("status = %d forwarded = %v, want %d / %v", rec.Code, forwarded, tc.wantCode, tc.forwarded)
				}
				want := []resourceInspectCall{{kind: dockerresource.KindContainer, id: req.want}}
				if !reflect.DeepEqual(fi.calls, want) {
					t.Fatalf("inspect calls = %#v, want %#v", fi.calls, want)
				}
			})
		}
	}
}

func TestContainerLinkSourcesAreCollected(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"HostConfig":{"Links":["victim:x","/other","dup:alias","dup","  spaced :y",17,null]}}`,
		`{"hostconfig":{"links":["victim:x","/other","dup:alias","dup","  spaced :y"]}}`,
	} {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatal(err)
		}
		want := []embeddedOwnershipReference{
			{dockerresource.KindContainer, "victim", "container HostConfig.Links"},
			{dockerresource.KindContainer, "other", "container HostConfig.Links"},
			{dockerresource.KindContainer, "dup", "container HostConfig.Links"},
			{dockerresource.KindContainer, "spaced", "container HostConfig.Links"},
		}
		if got := containerCreateEmbeddedOwnershipReferences(decoded); !reflect.DeepEqual(got, want) {
			t.Fatalf("references = %#v, want %#v", got, want)
		}
	}
}

func TestMiddlewareAuthorizesLinkSourcesOnContainerCreate(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	container := func(id string, r inspectResult) map[string]map[string]inspectResult {
		return map[string]map[string]inspectResult{string(dockerresource.KindContainer): {id: r}}
	}
	tests := []struct {
		name      string
		body      string
		resources map[string]map[string]inspectResult
		wantCode  int
	}{
		{name: "foreign victim", body: `{"HostConfig":{"Links":["victim:x"]}}`, resources: container("victim", ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "leading slash", body: `{"HostConfig":{"Links":["/victim:x"]}}`, resources: container("victim", ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "no alias", body: `{"HostConfig":{"Links":["victim"]}}`, resources: container("victim", ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "lowercase keys", body: `{"hostconfig":{"links":["victim:x"]}}`, resources: container("victim", ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "unlabeled", body: `{"HostConfig":{"Links":["victim:x"]}}`, resources: container("victim", inspectResult{labels: map[string]string{}, found: true}), wantCode: http.StatusForbidden},
		{name: "missing", body: `{"HostConfig":{"Links":["victim:x"]}}`, resources: map[string]map[string]inspectResult{}, wantCode: http.StatusNotFound},
		{name: "lookup failure", body: `{"HostConfig":{"Links":["victim:x"]}}`, resources: container("victim", inspectResult{err: errors.New("boom")}), wantCode: http.StatusBadGateway},
		{name: "own container", body: `{"HostConfig":{"Links":["mine:x"]}}`, resources: container("mine", ownerLabel("job-123")), wantCode: http.StatusOK},
		{name: "no links", body: `{"HostConfig":{"Links":[]}}`, resources: map[string]map[string]inspectResult{}, wantCode: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, _, _ := embeddedTestRun(t, opts, tt.resources, http.MethodPost, "/containers/create", tt.body)
			if code != tt.wantCode {
				t.Fatalf("status = %d, want %d", code, tt.wantCode)
			}
		})
	}
}

// TestPodmanContainerGrammarStaysSingleSegment pins that the libpod container
// parser still reads the first segment as the name, since Podman's {name}
// matches one segment.
func TestPodmanContainerGrammarStaysSingleSegment(t *testing.T) {
	t.Parallel()
	got, ok := libpodContainerIdentifier(http.MethodPost, "/libpod/containers/web/stop")
	if !ok || got != "web" {
		t.Fatalf("libpodContainerIdentifier = (%q, %v), want (web, true)", got, ok)
	}
	got, ok = libpodContainerIdentifier(http.MethodPost, "/libpod/containers/A/x/stop")
	if !ok || got != "A" {
		t.Fatalf("libpodContainerIdentifier(slash name) = (%q, %v), want first segment A", got, ok)
	}
}
