package filter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

const hostNetworkID = "9f1c5b7d2a0e4c3b8d6a1f2e3c4b5a69"

func TestServiceNetworkGuardResolvesHostNetwork(t *testing.T) {
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
		name         string
		path         string
		body         string
		allowHost    bool
		inspect      NetworkInspectFunc
		wantStatus   int
		wantForwards int
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
		{name: "manual rollback ignores body", path: "/services/svc1/update?version=3&rollback=previous", body: `{"Networks":[{"Target":"` + hostNetworkID + `"}]}`, inspect: nil, wantStatus: guardedRequestAllowedStatus, wantForwards: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := ResourceLimitGuardOptions{InspectNetwork: tt.inspect}
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
	if _, found, err := NewDockerNetworkInspectorWithRoundTripper(respond(404, ``))(context.Background(), "abc"); err != nil || found {
		t.Fatalf("404: found=%v err=%v", found, err)
	}
	if _, _, err := NewDockerNetworkInspectorWithRoundTripper(respond(500, ``))(context.Background(), "abc"); err == nil {
		t.Fatal("500 must be an error")
	}
	if _, _, err := NewDockerNetworkInspectorWithRoundTripper(respond(200, `{`))(context.Background(), "abc"); err == nil {
		t.Fatal("bad JSON must be an error")
	}
}
