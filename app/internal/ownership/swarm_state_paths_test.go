package ownership

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
)

func TestSwarmStatePathsAreOwnerChecked(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/swarm", "/swarm/unlockkey", "/swarm/leave"} {
		if !isSwarmPath(path) {
			t.Errorf("isSwarmPath(%q) = false", path)
		}
	}
	for _, path := range []string{"/swarm/update", "/swarm/join", "/swarm/init", "/swarm/unlock", "/swarm/leave/x"} {
		if isSwarmPath(path) {
			t.Errorf("isSwarmPath(%q) = true", path)
		}
	}
}

func TestMiddlewareChecksSwarmUnlockKeyAndLeave(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	requests := []struct {
		method string
		target string
	}{
		{http.MethodGet, "/swarm/unlockkey"},
		{http.MethodGet, "/v1.45/swarm/unlockkey"},
		{http.MethodPost, "/swarm/leave?force=1"},
		{http.MethodPost, "/v1.45/swarm/leave?force=1"},
		{http.MethodPost, "/swarm/leave"},
	}
	states := []struct {
		name      string
		result    *inspectResult
		wantCode  int
		forwarded bool
	}{
		{name: "foreign", result: &inspectResult{labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true}, wantCode: http.StatusForbidden},
		{name: "unlabeled", result: &inspectResult{labels: map[string]string{}, found: true}, wantCode: http.StatusForbidden},
		{name: "missing", result: nil, wantCode: http.StatusNotFound},
		{name: "lookup error", result: &inspectResult{err: errors.New("boom")}, wantCode: http.StatusBadGateway},
		{name: "same owner", result: &inspectResult{labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}, wantCode: http.StatusOK, forwarded: true},
	}
	for _, req := range requests {
		for _, state := range states {
			t.Run(req.method+" "+req.target+" "+state.name, func(t *testing.T) {
				t.Parallel()
				fi := &recordingInspector{resources: map[string]map[string]inspectResult{}}
				if state.result != nil {
					fi.resources[string(dockerresource.KindSwarm)] = map[string]inspectResult{"": *state.result}
				}
				forwarded := false
				handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					forwarded = true
				}))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(req.method, req.target, nil))
				if rec.Code != state.wantCode || forwarded != state.forwarded {
					t.Fatalf("status = %d forwarded = %v, want %d / %v", rec.Code, forwarded, state.wantCode, state.forwarded)
				}
				if len(fi.calls) != 1 || fi.calls[0].kind != dockerresource.KindSwarm {
					t.Fatalf("inspect calls = %#v, want one swarm lookup", fi.calls)
				}
			})
		}
	}
}

// TestSwarmUpdateStillClaimsUnlabeledSwarm pins that only /swarm/update keeps
// the unlabeled-swarm claim exception.
func TestSwarmUpdateStillClaimsUnlabeledSwarm(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := &recordingInspector{resources: map[string]map[string]inspectResult{
		string(dockerresource.KindSwarm): {"": {labels: map[string]string{}, found: true}},
	}}
	forwarded := false
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		forwarded = true
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/swarm/update?version=1", strings.NewReader(`{"Name":"cluster"}`)))
	if rec.Code != http.StatusOK || !forwarded {
		t.Fatalf("status = %d forwarded = %v, want claim to forward", rec.Code, forwarded)
	}
}
