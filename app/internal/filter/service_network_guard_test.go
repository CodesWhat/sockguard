package filter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

const hostNetworkID = "9f1c5b7d2a0e4c3b8d6a1f2e3c4b5a69"

func TestServiceNetworkGuardResolvesHostNetwork(t *testing.T) {
	previousSpec := ServiceInspectResult{Version: 3, HasPreviousSpec: true}
	inspect := func(_ context.Context, target string) (NetworkInspectResult, bool, error) {
		switch target {
		case hostNetworkID, hostNetworkID[:12]:
			return NetworkInspectResult{Name: "host", Driver: "host"}, true, nil
		case "renamed":
			return NetworkInspectResult{Name: "renamed", Driver: "host"}, true, nil
		case "tenant-net":
			return NetworkInspectResult{Name: "tenant-net", Driver: "overlay"}, true, nil
		case "missing":
			return NetworkInspectResult{}, false, nil
		case "boom":
			return NetworkInspectResult{}, false, errors.New("daemon down")
		}
		t.Fatalf("unexpected lookup %q", target)
		return NetworkInspectResult{}, false, nil
	}

	tests := []struct {
		name      string
		path      string
		body      string
		allowHost bool
		inspect   NetworkInspectFunc
		// previous is the stored PreviousSpec the service inspector reports;
		// nil leaves the service inspector unset unless inspectServiceErr.
		previous          *ServiceInspectResult
		inspectServiceErr bool
		wantStatus        int
		wantForwards      int
	}{
		{name: "full ID in TaskTemplate", path: "/services/create", body: `{"TaskTemplate":{"Networks":[{"Target":"` + hostNetworkID + `"}]}}`, inspect: inspect, wantStatus: http.StatusForbidden},
		{name: "ID prefix in TaskTemplate", path: "/services/create", body: `{"TaskTemplate":{"Networks":[{"Target":"` + hostNetworkID[:12] + `"}]}}`, inspect: inspect, wantStatus: http.StatusForbidden},
		{name: "ID in deprecated top-level Networks on update", path: "/services/svc1/update?version=3", body: `{"Networks":[{"Target":"` + hostNetworkID + `"}]}`, inspect: inspect, wantStatus: http.StatusForbidden},
		{name: "host driver under another name", path: "/services/create", body: `{"TaskTemplate":{"Networks":[{"Target":"renamed"}]}}`, inspect: inspect, wantStatus: http.StatusForbidden},
		{name: "literal host skips lookup", path: "/services/create", body: `{"TaskTemplate":{"Networks":[{"Target":"Host"}]}}`, inspect: nil, wantStatus: http.StatusForbidden},
		{name: "overlay network allowed", path: "/services/create", body: `{"TaskTemplate":{"Networks":[{"Target":"tenant-net"}]}}`, inspect: inspect, wantStatus: guardedRequestAllowedStatus, wantForwards: 1},
		{name: "not found allowed", path: "/services/create", body: `{"TaskTemplate":{"Networks":[{"Target":"missing"}]}}`, inspect: inspect, wantStatus: guardedRequestAllowedStatus, wantForwards: 1},
		{name: "lookup error fails closed", path: "/services/create", body: `{"TaskTemplate":{"Networks":[{"Target":"boom"}]}}`, inspect: inspect, wantStatus: http.StatusBadGateway},
		{name: "nil inspector fails closed when a network is named", path: "/services/create", body: `{"TaskTemplate":{"Networks":[{"Target":"tenant-net"}]}}`, inspect: nil, wantStatus: http.StatusBadGateway},
		{name: "no networks needs no lookup", path: "/services/create", body: `{"TaskTemplate":{}}`, inspect: nil, wantStatus: guardedRequestAllowedStatus, wantForwards: 1},
		{name: "allow_host_network skips the guard", path: "/services/create", body: `{"TaskTemplate":{"Networks":[{"Target":"` + hostNetworkID + `"}]}}`, allowHost: true, inspect: nil, wantStatus: guardedRequestAllowedStatus, wantForwards: 1},
		{name: "create with rollback=previous still checks a host ID", path: "/services/create?rollback=previous", body: `{"TaskTemplate":{"Networks":[{"Target":"` + hostNetworkID + `"}]}}`, inspect: inspect, wantStatus: http.StatusForbidden},
		{name: "create with rollback=previous still denies literal host", path: "/services/create?rollback=previous", body: `{"TaskTemplate":{"Networks":[{"Target":"host"}]}}`, inspect: nil, wantStatus: http.StatusForbidden},
		{name: "manual rollback ignores body", path: "/services/svc1/update?version=3&rollback=previous", body: `{"Networks":[{"Target":"` + hostNetworkID + `"}]}`, inspect: nil, previous: &previousSpec, wantStatus: guardedRequestAllowedStatus, wantForwards: 1},
		{name: "manual rollback to a host-ID PreviousSpec target", path: "/services/svc1/update?version=3&rollback=previous", body: `{}`, inspect: inspect, previous: &ServiceInspectResult{Version: 3, HasPreviousSpec: true, PreviousSpecNetworkTargets: []string{"tenant-net", hostNetworkID}}, wantStatus: http.StatusForbidden},
		{name: "manual rollback to a literal host PreviousSpec target", path: "/services/svc1/update?version=3&rollback=previous", body: `{}`, inspect: nil, previous: &ServiceInspectResult{Version: 3, HasPreviousSpec: true, PreviousSpecNetworkTargets: []string{"host"}}, wantStatus: http.StatusForbidden},
		{name: "manual rollback to an overlay-only PreviousSpec", path: "/services/svc1/update?version=3&rollback=previous", body: `{}`, inspect: inspect, previous: &ServiceInspectResult{Version: 3, HasPreviousSpec: true, PreviousSpecNetworkTargets: []string{"tenant-net"}}, wantStatus: guardedRequestAllowedStatus, wantForwards: 1},
		{name: "manual rollback network lookup failure fails closed", path: "/services/svc1/update?version=3&rollback=previous", body: `{}`, inspect: inspect, previous: &ServiceInspectResult{Version: 3, HasPreviousSpec: true, PreviousSpecNetworkTargets: []string{"boom"}}, wantStatus: http.StatusBadGateway},
		{name: "manual rollback service inspect failure fails closed", path: "/services/svc1/update?version=3&rollback=previous", body: `{}`, inspect: inspect, inspectServiceErr: true, wantStatus: http.StatusBadGateway},
		{name: "manual rollback without a service inspector fails closed", path: "/services/svc1/update?version=3&rollback=previous", body: `{}`, inspect: inspect, wantStatus: http.StatusBadGateway},
		{name: "manual rollback with a stale version is a conflict", path: "/services/svc1/update?version=2&rollback=previous", body: `{}`, inspect: inspect, previous: &ServiceInspectResult{Version: 3, HasPreviousSpec: true, PreviousSpecNetworkTargets: []string{"tenant-net"}}, wantStatus: http.StatusConflict},
		{name: "manual rollback with allow_host_network skips the guard", path: "/services/svc1/update?version=3&rollback=previous", body: `{}`, allowHost: true, wantStatus: guardedRequestAllowedStatus, wantForwards: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := ResourceLimitGuardOptions{InspectNetwork: tt.inspect}
			if tt.previous != nil {
				result := *tt.previous
				opts.InspectService = func(context.Context, string) (ServiceInspectResult, bool, error) { return result, true, nil }
			} else if tt.inspectServiceErr {
				opts.InspectService = func(context.Context, string) (ServiceInspectResult, bool, error) {
					return ServiceInspectResult{}, false, errors.New("daemon down")
				}
			}
			opts.Service.AllowHostNetwork = tt.allowHost
			out := runResourceGuardRequest(t, opts, http.MethodPost, tt.path, tt.body, "")
			if out.status != tt.wantStatus || out.forwarded != tt.wantForwards {
				t.Fatalf("status=%d forwarded=%d, want %d/%d; body: %s", out.status, out.forwarded, tt.wantStatus, tt.wantForwards, out.body)
			}
			if tt.wantForwards == 1 && out.forwardedBody != tt.body {
				t.Fatalf("forwarded body = %q, want it unchanged", out.forwardedBody)
			}
		})
	}
}

func TestServiceNetworkGuardWarnModePassesPolicyDenyButNotLookupFailure(t *testing.T) {
	opts := ResourceLimitGuardOptions{InspectNetwork: func(context.Context, string) (NetworkInspectResult, bool, error) {
		return NetworkInspectResult{Name: "host", Driver: "host"}, true, nil
	}}
	body := `{"TaskTemplate":{"Networks":[{"Target":"abc"}]}}`
	if out := runResourceGuardRequest(t, opts, http.MethodPost, "/services/create", body, "warn"); out.forwarded != 1 {
		t.Fatalf("warn mode forwarded=%d status=%d, want pass-through", out.forwarded, out.status)
	}
	opts.InspectNetwork = func(context.Context, string) (NetworkInspectResult, bool, error) {
		return NetworkInspectResult{}, false, errors.New("down")
	}
	if out := runResourceGuardRequest(t, opts, http.MethodPost, "/services/create", body, "warn"); out.status != http.StatusBadGateway || out.forwarded != 0 {
		t.Fatalf("warn mode lookup failure status=%d forwarded=%d, want 502/0", out.status, out.forwarded)
	}
}

type networkRoundTripFunc func(*http.Request) (*http.Response, error)

func (f networkRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNewDockerNetworkInspector(t *testing.T) {
	respond := func(status int, body string) http.RoundTripper {
		return networkRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet || r.URL.Path != "/networks/abc" {
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})
	}
	got, found, err := NewDockerNetworkInspectorWithRoundTripper(respond(200, `{"Name":"host","Driver":"host","Id":"x"}`))(context.Background(), "abc")
	if err != nil || !found || got.Name != "host" || got.Driver != "host" {
		t.Fatalf("got %+v found=%v err=%v", got, found, err)
	}
	if _, found, err := NewDockerNetworkInspectorWithRoundTripper(respond(404, `{"message":"network abc not found"}`))(context.Background(), "abc"); err != nil || found {
		t.Fatalf("404: found=%v err=%v", found, err)
	}
	// The error bodies are valid JSON that decodes without error, so only the
	// status check itself can turn them into failures.
	for _, status := range []int{401, 500, 503} {
		got, found, err := NewDockerNetworkInspectorWithRoundTripper(respond(status, `{"message":"boom"}`))(context.Background(), "abc")
		if err == nil || found || got != (NetworkInspectResult{}) {
			t.Fatalf("status %d: got %+v found=%v err=%v, want an error and no result", status, got, found, err)
		}
		if want := fmt.Sprintf("status %d", status); !strings.Contains(err.Error(), want) {
			t.Fatalf("status %d: err = %v, want it to name %q", status, err, want)
		}
	}
	if _, _, err := NewDockerNetworkInspectorWithRoundTripper(respond(200, `{`))(context.Background(), "abc"); err == nil {
		t.Fatal("bad JSON must be an error")
	}
}
