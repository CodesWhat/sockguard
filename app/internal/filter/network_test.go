package filter

import (
	"bytes"
	"errors"
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
			name:       "links",
			body:       `{"Container":"web","EndpointConfig":{"Links":["db:database"]}}`,
			wantReason: "network connect denied: endpoint links are not allowed",
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

// TestNetworkInspectConnectAllowsAliasesByDefault proves Aliases are never
// gated, even without allow_endpoint_config. Docker Compose sets
// Aliases: [serviceName] on every endpoint it creates, so an aliases-only
// connect (the shape a multi-network Compose recreate sends for its
// secondary networks) must pass under the default policy.
func TestNetworkInspectConnectAllowsAliasesByDefault(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/networks/app/connect", strings.NewReader(`{"Container":"web","EndpointConfig":{"Aliases":["db","database"]}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

// TestNetworkInspectConnectDeniesStaticIPAlongsideAliases proves Aliases
// riding alongside a genuinely gated field (static IP) does not mask that
// field's denial — the aliases exemption only lifts the aliases check
// itself, not the whole endpoint config.
func TestNetworkInspectConnectDeniesStaticIPAlongsideAliases(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/networks/app/connect", strings.NewReader(`{"Container":"web","EndpointConfig":{"Aliases":["db"],"IPAMConfig":{"IPv4Address":"172.30.0.10"}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	const wantReason = "network connect denied: endpoint static IP configuration is not allowed"
	if reason != wantReason {
		t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
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
	// Malformed JSON must be denied (fail-closed).
	const wantReason = "network create denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
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
	// Malformed JSON must be denied (fail-closed).
	const wantReason = "network create denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("reason = %q, want %q", reason, wantReason)
	}
	if logs.Len() == 0 {
		t.Fatal("log buffer is empty, want malformed JSON debug log")
	}
}

func TestNetworkInspectSkipsNonWriteRequestsAndNilBody(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})

	tests := []struct {
		name           string
		req            *http.Request
		normalizedPath string
	}{
		{name: "nil request", req: nil, normalizedPath: "/networks/create"},
		{name: "wrong method", req: httptest.NewRequest(http.MethodGet, "/networks/create", strings.NewReader(`{"Driver":"weave"}`)), normalizedPath: "/networks/create"},
		{name: "wrong path", req: httptest.NewRequest(http.MethodPost, "/networks/app", strings.NewReader(`{"Driver":"weave"}`)), normalizedPath: "/networks/app"},
		{name: "nil body", req: func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "/networks/create", nil)
			req.Body = nil
			return req
		}(), normalizedPath: "/networks/create"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, err := policy.inspect(nil, tt.req, tt.normalizedPath)
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "" {
				t.Fatalf("reason = %q, want empty", reason)
			}
		})
	}
}

func TestNetworkInspectEmptyBodyReturnsEmpty(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/networks/create", strings.NewReader(""))

	reason, err := policy.inspect(nil, req, "/networks/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestNetworkInspectConnectMalformedJSONDefers(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/networks/app/connect", strings.NewReader("{bad json"))

	reason, err := policy.inspect(nil, req, "/networks/app/connect")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	// Malformed JSON must be denied (fail-closed).
	const wantReason = "network connect denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("reason = %q, want %q", reason, wantReason)
	}
}

func TestNetworkInspectDisconnectMalformedJSONDefers(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/networks/app/disconnect", strings.NewReader("{bad json"))

	reason, err := policy.inspect(nil, req, "/networks/app/disconnect")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	// Malformed JSON must be denied (fail-closed).
	const wantReason = "network disconnect denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("reason = %q, want %q", reason, wantReason)
	}
}

func TestNetworkInspectConnectAllowsEmptyEndpointConfig(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/networks/app/connect", strings.NewReader(`{"EndpointConfig":{}}`))

	reason, err := policy.inspect(nil, req, "/networks/app/connect")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestNetworkInspectCreateAllowsBuiltinIPAMDrivers(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})

	for _, driver := range []string{"default", "NULL"} {
		t.Run(driver, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/networks/create", strings.NewReader(`{"IPAM":{"Driver":"`+driver+`"}}`))

			reason, err := policy.inspect(nil, req, "/networks/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "" {
				t.Fatalf("reason = %q, want empty", reason)
			}
		})
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

func TestNetworkInspectCreateEnableIPv4(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		opts       NetworkOptions
		wantReason string
	}{
		{
			name: "unset defaults to allowed",
			body: `{"Name":"app"}`,
		},
		{
			name: "explicit true allowed",
			body: `{"Name":"app","EnableIPv4":true}`,
		},
		{
			name:       "explicit false denied by default",
			body:       `{"Name":"app","EnableIPv4":false}`,
			wantReason: "network create denied: disabling IPv4 (EnableIPv4: false) is not allowed",
		},
		{
			name: "explicit false allowed when configured",
			body: `{"Name":"app","EnableIPv4":false}`,
			opts: NetworkOptions{AllowDisableIPv4: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newNetworkPolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPost, "/networks/create", strings.NewReader(tt.body))

			reason, err := policy.inspect(nil, req, "/networks/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestNetworkInspectConnectGwPriority(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		allow      bool
		wantReason string
	}{
		{
			name: "zero GwPriority allowed by default",
			body: `{"EndpointConfig":{"GwPriority":0}}`,
		},
		{
			name:       "non-zero GwPriority denied by default",
			body:       `{"EndpointConfig":{"GwPriority":10}}`,
			wantReason: "network connect denied: endpoint gateway priority is not allowed",
		},
		{
			name:  "non-zero GwPriority allowed under allow_endpoint_config",
			body:  `{"EndpointConfig":{"GwPriority":10}}`,
			allow: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newNetworkPolicy(NetworkOptions{AllowEndpointConfig: tt.allow})
			req := httptest.NewRequest(http.MethodPost, "/networks/app/connect", strings.NewReader(tt.body))

			reason, err := policy.inspect(nil, req, "/networks/app/connect")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestNetworkInspectConnectGranularEndpointConfig proves each #186 granular
// gate independently admits its own field while every other field stays
// denied — the point of narrowing allow_endpoint_config into per-field
// controls in the first place.
func TestNetworkInspectConnectGranularEndpointConfig(t *testing.T) {
	tests := []struct {
		name       string
		granular   EndpointConfigOptions
		body       string
		wantReason string
	}{
		{
			name:       "static IP denied with no granular allow",
			granular:   EndpointConfigOptions{},
			body:       `{"EndpointConfig":{"IPAMConfig":{"IPv4Address":"172.30.0.10"}}}`,
			wantReason: "network connect denied: endpoint static IP configuration is not allowed",
		},
		{
			name:     "static IP allowed by AllowStaticAddressing alone",
			granular: EndpointConfigOptions{AllowStaticAddressing: true},
			body:     `{"EndpointConfig":{"IPAMConfig":{"IPv4Address":"172.30.0.10"}}}`,
		},
		{
			name:       "static IP still denied when only link-local is allowed",
			granular:   EndpointConfigOptions{AllowLinkLocalIPs: true},
			body:       `{"EndpointConfig":{"IPAMConfig":{"IPv4Address":"172.30.0.10"}}}`,
			wantReason: "network connect denied: endpoint static IP configuration is not allowed",
		},
		{
			name:       "link-local IPs denied with no granular allow",
			granular:   EndpointConfigOptions{},
			body:       `{"EndpointConfig":{"IPAMConfig":{"LinkLocalIPs":["169.254.1.1"]}}}`,
			wantReason: "network connect denied: endpoint link-local IP addresses are not allowed",
		},
		{
			name:     "link-local IPs allowed by AllowLinkLocalIPs alone",
			granular: EndpointConfigOptions{AllowLinkLocalIPs: true},
			body:     `{"EndpointConfig":{"IPAMConfig":{"LinkLocalIPs":["169.254.1.1"]}}}`,
		},
		{
			name:       "link-local IPs still denied when only static addressing is allowed",
			granular:   EndpointConfigOptions{AllowStaticAddressing: true},
			body:       `{"EndpointConfig":{"IPAMConfig":{"LinkLocalIPs":["169.254.1.1"]}}}`,
			wantReason: "network connect denied: endpoint link-local IP addresses are not allowed",
		},
		{
			name:       "MAC address denied with no granular allow",
			granular:   EndpointConfigOptions{},
			body:       `{"EndpointConfig":{"MacAddress":"02:42:ac:1e:00:0a"}}`,
			wantReason: "network connect denied: endpoint MAC address is not allowed",
		},
		{
			name:     "MAC address allowed by AllowMACPinning alone",
			granular: EndpointConfigOptions{AllowMACPinning: true},
			body:     `{"EndpointConfig":{"MacAddress":"02:42:ac:1e:00:0a"}}`,
		},
		{
			name:       "GwPriority denied with no granular allow",
			granular:   EndpointConfigOptions{},
			body:       `{"EndpointConfig":{"GwPriority":10}}`,
			wantReason: "network connect denied: endpoint gateway priority is not allowed",
		},
		{
			name:     "GwPriority allowed by AllowGwPriority alone",
			granular: EndpointConfigOptions{AllowGwPriority: true},
			body:     `{"EndpointConfig":{"GwPriority":10}}`,
		},
		{
			name:     "aliases allowed when granular is entirely zero-valued (default)",
			granular: EndpointConfigOptions{},
			body:     `{"EndpointConfig":{"Aliases":["web"]}}`,
		},
		{
			name:       "aliases denied when DenyAliases is explicitly set",
			granular:   EndpointConfigOptions{DenyAliases: true},
			body:       `{"EndpointConfig":{"Aliases":["web"]}}`,
			wantReason: "network connect denied: endpoint aliases are not allowed",
		},
		{
			name:       "links have no granular escape hatch — always denied under granular mode",
			granular:   EndpointConfigOptions{AllowStaticAddressing: true, AllowLinkLocalIPs: true, AllowMACPinning: true, AllowGwPriority: true},
			body:       `{"EndpointConfig":{"Links":["db:database"]}}`,
			wantReason: "network connect denied: endpoint links are not allowed",
		},
		{
			name:       "driver options have no granular escape hatch — always denied under granular mode",
			granular:   EndpointConfigOptions{AllowStaticAddressing: true, AllowLinkLocalIPs: true, AllowMACPinning: true, AllowGwPriority: true},
			body:       `{"EndpointConfig":{"DriverOpts":{"foo":"bar"}}}`,
			wantReason: "network connect denied: endpoint driver options are not allowed",
		},
		{
			name:     "every granular field allowed together admits every gated field",
			granular: EndpointConfigOptions{AllowStaticAddressing: true, AllowLinkLocalIPs: true, AllowMACPinning: true, AllowGwPriority: true},
			body: `{"EndpointConfig":{
				"IPAMConfig":{"IPv4Address":"172.30.0.10","LinkLocalIPs":["169.254.1.1"]},
				"MacAddress":"02:42:ac:1e:00:0a",
				"GwPriority":10
			}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newNetworkPolicy(NetworkOptions{EndpointConfig: tt.granular})
			req := httptest.NewRequest(http.MethodPost, "/networks/app/connect", strings.NewReader(tt.body))

			reason, err := policy.inspect(nil, req, "/networks/app/connect")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestNetworkInspectConnectAllowEndpointConfigTakesPrecedenceOverGranular
// proves the legacy whole-object AllowEndpointConfig wins over the granular
// block, admitting even a field the granular options would deny — matching
// the precedence documented on denyEndpointConfigReason and enforced at
// config-load time by validateNetworkEndpointConfig (the two are mutually
// exclusive in practice; this proves the runtime precedence in case they
// were ever both non-zero regardless).
func TestNetworkInspectConnectAllowEndpointConfigTakesPrecedenceOverGranular(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{
		AllowEndpointConfig: true,
		EndpointConfig:      EndpointConfigOptions{DenyAliases: true},
	})
	body := `{"EndpointConfig":{"IPAMConfig":{"IPv4Address":"172.30.0.10"},"MacAddress":"02:42:ac:1e:00:0a","Aliases":["web"],"GwPriority":10}}`
	req := httptest.NewRequest(http.MethodPost, "/networks/app/connect", strings.NewReader(body))

	reason, err := policy.inspect(nil, req, "/networks/app/connect")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty (AllowEndpointConfig should win)", reason)
	}
}

// FuzzNetworkConnectEndpointConfigGates fuzzes the #186 granular
// endpoint-config gates (TestNetworkInspectConnectGranularEndpointConfig's
// table, generalized) through the full inspect() entrypoint: for every
// mutation-generated combination of granular EndpointConfigOptions and
// network-connect body, it asserts the core fail-closed invariant a disabled
// gate must uphold — if the decoded endpoint sets a field whose gate is off
// (and the legacy AllowEndpointConfig escape hatch is also off), inspect()
// must produce a non-empty denial reason for that field. Links and
// DriverOpts have no granular gate at all, so they must always be denied
// once AllowEndpointConfig is off, regardless of the other granular flags.
func FuzzNetworkConnectEndpointConfigGates(f *testing.F) {
	f.Add(false, false, false, false, false, true, []byte(`{"EndpointConfig":{"IPAMConfig":{"IPv4Address":"172.30.0.10"}}}`))
	f.Add(false, false, false, false, false, true, []byte(`{"EndpointConfig":{"IPAMConfig":{"LinkLocalIPs":["169.254.1.1"]}}}`))
	f.Add(false, false, false, false, false, true, []byte(`{"EndpointConfig":{"MacAddress":"02:42:ac:1e:00:0a"}}`))
	f.Add(false, false, false, false, false, true, []byte(`{"EndpointConfig":{"GwPriority":10}}`))
	f.Add(false, false, false, false, false, false, []byte(`{"EndpointConfig":{"Aliases":["web"]}}`))
	f.Add(false, true, true, true, true, true, []byte(`{"EndpointConfig":{"Links":["db:database"]}}`))
	f.Add(false, true, true, true, true, true, []byte(`{"EndpointConfig":{"DriverOpts":{"foo":"bar"}}}`))
	f.Add(true, false, false, false, false, true, []byte(`{"EndpointConfig":{"MacAddress":"02:42:ac:1e:00:0a"}}`))

	f.Fuzz(func(t *testing.T, allowEndpointConfig, allowStatic, allowLinkLocal, allowMAC, allowGw, allowAliases bool, body []byte) {
		body = truncateParserFuzzBytes(body, maxNetworkInspectorFuzzBytes)

		granular := EndpointConfigOptions{
			AllowStaticAddressing: allowStatic,
			AllowLinkLocalIPs:     allowLinkLocal,
			AllowMACPinning:       allowMAC,
			AllowGwPriority:       allowGw,
			DenyAliases:           !allowAliases,
		}
		policy := newNetworkPolicy(NetworkOptions{
			AllowEndpointConfig: allowEndpointConfig,
			EndpointConfig:      granular,
		})

		req := newJSONInspectorFuzzRequest(http.MethodPost, "/networks/app/connect", "", body)
		reason, err := policy.inspect(nil, req, "/networks/app/connect")
		drainFuzzRequestBody(req)
		if err != nil {
			return
		}
		// The legacy whole-object flag wins outright (denyEndpointConfigReason's
		// documented precedence) — nothing to assert per-field once it is set.
		if allowEndpointConfig {
			return
		}

		var decoded networkConnectRequest
		if decodePolicySubsetJSON(body, &decoded) != nil || decoded.EndpointConfig == nil {
			// Undecodable or absent EndpointConfig: inspect() either denies with
			// its fixed "could not be inspected" message or has nothing to gate.
			return
		}
		ep := *decoded.EndpointConfig

		if !allowStatic && endpointHasStaticAddressFields(ep) && reason == "" {
			t.Fatalf("static address field present, AllowStaticAddressing=false, AllowEndpointConfig=false, but reason is empty (body=%s)", body)
		}
		if !allowLinkLocal && endpointHasLinkLocalIPs(ep) && reason == "" {
			t.Fatalf("link-local IPs present, AllowLinkLocalIPs=false, AllowEndpointConfig=false, but reason is empty (body=%s)", body)
		}
		if !allowMAC && strings.TrimSpace(ep.MacAddress) != "" && reason == "" {
			t.Fatalf("MAC address present, AllowMACPinning=false, AllowEndpointConfig=false, but reason is empty (body=%s)", body)
		}
		if !allowGw && ep.GwPriority != 0 && reason == "" {
			t.Fatalf("GwPriority present, AllowGwPriority=false, AllowEndpointConfig=false, but reason is empty (body=%s)", body)
		}
		if len(ep.Links) > 0 && reason == "" {
			t.Fatalf("Links present but reason is empty despite Links having no granular gate (body=%s)", body)
		}
		if len(ep.DriverOpts) > 0 && reason == "" {
			t.Fatalf("DriverOpts present but reason is empty despite DriverOpts having no granular gate (body=%s)", body)
		}
		if !allowAliases && len(ep.Aliases) > 0 && reason == "" {
			t.Fatalf("Aliases present, AllowAliases=false, AllowEndpointConfig=false, but reason is empty (body=%s)", body)
		}
	})
}
