package filter

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNetworkInspectCreateAllowsDefaultNetwork(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/v1.53/networks/create", strings.NewReader(`{"Name":"app","Driver":"bridge"}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestNetworkInspectCreateDeniesRiskyFieldsByDefault(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{
			name:       "custom driver",
			body:       `{"Name":"app","Driver":"weave"}`,
			wantReason: `network create denied: driver "weave" is not allowed`,
		},
		{
			name:       "swarm scope",
			body:       `{"Name":"app","Scope":"swarm"}`,
			wantReason: "network create denied: swarm scope is not allowed",
		},
		{
			name:       "ingress",
			body:       `{"Name":"app","Ingress":true}`,
			wantReason: "network create denied: ingress networks are not allowed",
		},
		{
			name:       "attachable",
			body:       `{"Name":"app","Attachable":true}`,
			wantReason: "network create denied: attachable networks are not allowed",
		},
		{
			name:       "config only",
			body:       `{"Name":"app","ConfigOnly":true}`,
			wantReason: "network create denied: config-only networks are not allowed",
		},
		{
			name:       "config from",
			body:       `{"Name":"app","ConfigFrom":{"Network":"base"}}`,
			wantReason: "network create denied: config-from networks are not allowed",
		},
		{
			name:       "custom IPAM driver",
			body:       `{"Name":"app","IPAM":{"Driver":"infoblox"}}`,
			wantReason: `network create denied: IPAM driver "infoblox" is not allowed`,
		},
		{
			name:       "custom IPAM config",
			body:       `{"Name":"app","IPAM":{"Config":[{"Subnet":"172.30.0.0/16"}]}}`,
			wantReason: "network create denied: custom IPAM config is not allowed",
		},
		{
			name:       "IPAM options",
			body:       `{"Name":"app","IPAM":{"Options":{"foo":"bar"}}}`,
			wantReason: "network create denied: IPAM options are not allowed",
		},
		{
			name:       "driver options",
			body:       `{"Name":"app","Options":{"com.docker.network.bridge.name":"br-app"}}`,
			wantReason: "network create denied: driver options are not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/networks/create", strings.NewReader(tt.body))

			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestNetworkInspectCreateAllowsRiskyFieldsWhenConfigured(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{
		AllowCustomDrivers:     true,
		AllowSwarmScope:        true,
		AllowIngress:           true,
		AllowAttachable:        true,
		AllowConfigOnly:        true,
		AllowConfigFrom:        true,
		AllowCustomIPAMDrivers: true,
		AllowCustomIPAMConfig:  true,
		AllowIPAMOptions:       true,
		AllowDriverOptions:     true,
	})
	req := httptest.NewRequest(http.MethodPost, "/networks/create", strings.NewReader(`{
		"Name": "app",
		"Driver": "weave",
		"Scope": "swarm",
		"Ingress": true,
		"Attachable": true,
		"ConfigOnly": true,
		"ConfigFrom": {"Network": "base"},
		"IPAM": {
			"Driver": "infoblox",
			"Config": [{"Subnet": "172.30.0.0/16"}],
			"Options": {"foo": "bar"}
		},
		"Options": {"com.docker.network.bridge.name": "br-app"}
	}`))

	reason, err := policy.inspect(nil, req, "/networks/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestNetworkInspectConnectDeniesEndpointConfigByDefault(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{
			name:       "IPAM IPv4 address",
			body:       `{"Container":"web","EndpointConfig":{"IPAMConfig":{"IPv4Address":"172.30.0.10"}}}`,
			wantReason: "network connect denied: endpoint static IP configuration is not allowed",
		},
		{
			name:       "endpoint IP address",
			body:       `{"Container":"web","EndpointConfig":{"IPAddress":"172.30.0.10"}}`,
			wantReason: "network connect denied: endpoint static IP configuration is not allowed",
		},
		{
			name:       "MAC address",
			body:       `{"Container":"web","EndpointConfig":{"MacAddress":"02:42:ac:1e:00:0a"}}`,
			wantReason: "network connect denied: endpoint MAC address is not allowed",
		},
		{
			name:       "aliases",
			body:       `{"Container":"web","EndpointConfig":{"Aliases":["db"]}}`,
			wantReason: "network connect denied: endpoint aliases are not allowed",
		},
		{
			name:       "driver options",
			body:       `{"Container":"web","EndpointConfig":{"DriverOpts":{"foo":"bar"}}}`,
			wantReason: "network connect denied: endpoint driver options are not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/networks/app/connect", strings.NewReader(tt.body))

			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestNetworkInspectConnectAllowsEndpointConfigWhenConfigured(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{AllowEndpointConfig: true})
	req := httptest.NewRequest(http.MethodPost, "/v1.53/networks/app/connect", strings.NewReader(`{
		"Container": "web",
		"EndpointConfig": {
			"IPAMConfig": {"IPv4Address": "172.30.0.10"},
			"MacAddress": "02:42:ac:1e:00:0a",
			"Aliases": ["db"],
			"DriverOpts": {"foo": "bar"}
		}
	}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestNetworkInspectDisconnectDeniesForceByDefault(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/networks/app/disconnect", strings.NewReader(`{"Container":"web","Force":true}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "network disconnect denied: force disconnect is not allowed" {
		t.Fatalf("inspect() reason = %q, want force denial", reason)
	}
}

func TestNetworkInspectDisconnectAllowsForceWhenConfigured(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{AllowDisconnectForce: true})
	req := httptest.NewRequest(http.MethodPost, "/networks/app/disconnect", strings.NewReader(`{"Container":"web","Force":true}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestNetworkInspectMalformedJSONPreservesBody(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/networks/create", bytes.NewBufferString("{"))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}

	body, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		t.Fatalf("ReadAll() error = %v", readErr)
	}
	if string(body) != "{" {
		t.Fatalf("reset body = %q, want %q", string(body), "{")
	}
}

func TestNetworkInspectOversizedBodyRejected(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/networks/create", bytes.NewReader(bytes.Repeat([]byte{'x'}, maxNetworkBodyBytes+1)))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
	rejection, ok := requestRejectionFromError(err)
	if !ok {
		t.Fatalf("inspect() error = %v, want request rejection", err)
	}
	if rejection.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("rejection status = %d, want %d", rejection.status, http.StatusRequestEntityTooLarge)
	}
	if !strings.HasPrefix(rejection.reason, "network denied: request body exceeds") {
		t.Fatalf("rejection reason = %q, want oversize denial", rejection.reason)
	}
}

func TestNetworkInspectWrapsBodyReadError(t *testing.T) {
	sentinel := errors.New("read failed")
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/networks/create", nil)
	req.Body = &networkReadErrorReadCloser{readErr: sentinel}

	reason, err := policy.inspect(nil, req, "/networks/create")
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("inspect() error = %v, want wrapped %v", err, sentinel)
	}
	if !strings.Contains(err.Error(), "read body") {
		t.Fatalf("inspect() error = %q, want read body context", err)
	}
}

func TestNetworkInspectMalformedJSONWithLogger(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	var logs bytes.Buffer
	req := httptest.NewRequest(http.MethodPost, "/networks/create", strings.NewReader("{bad json}"))

	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	reason, err := policy.inspect(logger, req, "/networks/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty (deferred)", reason)
	}
	if logs.Len() == 0 {
		t.Fatal("log buffer is empty, want malformed JSON debug log")
	}
}

type networkReadErrorReadCloser struct {
	readErr error
}

func (r *networkReadErrorReadCloser) Read([]byte) (int, error) {
	return 0, r.readErr
}

func (r *networkReadErrorReadCloser) Close() error {
	return nil
}
