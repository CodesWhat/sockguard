package filter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLibpodNetworkUpdateInspect pins allow_dns_servers on Podman's
// netavark-only POST /libpod/networks/{name}/update. Every spelling here is
// one Podman v5.8.1 actually accepts: libpod.UpdateNetwork json.Decodes
// entities.NetworkUpdateOptions, whose tags are the run-together
// `adddnsservers`/`removednsservers` — NOT the snake_case
// `add_dns_servers`/`remove_dns_servers` of the internal
// libnetwork/types.NetworkUpdateOptions that abi.NetworkUpdate copies into
// after the decode.
func TestLibpodNetworkUpdateInspect(t *testing.T) {
	const path = "/libpod/networks/mynet/update"

	tests := []struct {
		name        string
		opts        NetworkOptions
		body        string
		wantDeny    bool
		wantReasonC string
	}{
		{
			name:        "denies adding a DNS server by default",
			opts:        NetworkOptions{},
			body:        `{"adddnsservers":["10.6.6.6"]}`,
			wantDeny:    true,
			wantReasonC: "setting custom DNS servers",
		},
		{
			name:        "denies removing a DNS server by default",
			opts:        NetworkOptions{},
			body:        `{"removednsservers":["1.1.1.1"]}`,
			wantDeny:    true,
			wantReasonC: "removing custom DNS servers",
		},
		{
			name: "allows adding a DNS server when configured",
			opts: NetworkOptions{AllowDNSServers: true},
			body: `{"adddnsservers":["10.6.6.6"]}`,
		},
		{
			name: "allows removing a DNS server when configured",
			opts: NetworkOptions{AllowDNSServers: true},
			body: `{"removednsservers":["1.1.1.1"]}`,
		},
		{
			// encoding/json falls back to a case-insensitive field match, so
			// Podman honors these and so must sockguard.
			name:        "denies the case-folded AddDNSServers spelling Podman accepts",
			opts:        NetworkOptions{},
			body:        `{"AddDNSServers":["10.6.6.6"]}`,
			wantDeny:    true,
			wantReasonC: "setting custom DNS servers",
		},
		{
			name:        "denies the shouted ADDDNSSERVERS spelling Podman accepts",
			opts:        NetworkOptions{},
			body:        `{"ADDDNSSERVERS":["10.6.6.6"]}`,
			wantDeny:    true,
			wantReasonC: "setting custom DNS servers",
		},
		{
			// The snake_case tags belong to the INTERNAL type, which never
			// touches the wire: encoding/json is case-insensitive but not
			// separator-insensitive, so Podman ignores this key entirely and
			// the request changes nothing. Denying it would be wrong.
			name: "ignores the internal snake_case spelling Podman never parses",
			opts: NetworkOptions{},
			body: `{"add_dns_servers":["10.6.6.6"]}`,
		},
		{
			// Podman applies two nil slices and rewrites the same list back.
			name: "allows a body that changes no resolver",
			opts: NetworkOptions{},
			body: `{}`,
		},
		{
			name: "allows explicitly empty resolver arrays",
			opts: NetworkOptions{},
			body: `{"adddnsservers":[],"removednsservers":[]}`,
		},
		{
			name:        "denies a body that cannot be decoded",
			opts:        NetworkOptions{},
			body:        `{"adddnsservers":"10.6.6.6"}`,
			wantDeny:    true,
			wantReasonC: "could not be inspected",
		},
		{
			name:        "denies malformed JSON",
			opts:        NetworkOptions{},
			body:        `{`,
			wantDeny:    true,
			wantReasonC: "could not be inspected",
		},
		{
			name: "allows an empty body, which Podman rejects itself",
			opts: NetworkOptions{},
			body: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newNetworkPolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(tt.body))
			reason, err := policy.inspectLibpod(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspectLibpod() error = %v", err)
			}
			if tt.wantDeny {
				if reason == "" {
					t.Fatalf("inspectLibpod() reason = empty, want a denial containing %q", tt.wantReasonC)
				}
				if !strings.Contains(reason, tt.wantReasonC) {
					t.Fatalf("inspectLibpod() reason = %q, want it to contain %q", reason, tt.wantReasonC)
				}
				if !strings.HasPrefix(reason, "libpod network update denied:") {
					t.Fatalf("inspectLibpod() reason = %q, want the libpod network update subject prefix", reason)
				}
				return
			}
			if reason != "" {
				t.Fatalf("inspectLibpod() reason = %q, want empty", reason)
			}
		})
	}
}

// TestLibpodNetworkCreateDNSServersGate pins the other half of
// allow_dns_servers. types.Network carries network_dns_servers, so create can
// set the same per-network resolvers update mutates; a knob that covered only
// update would name a surface it does not fully govern. The tag here is
// snake_case because create decodes types.Network, unlike update — see
// libpodNetworkUpdateRequest.
func TestLibpodNetworkCreateDNSServersGate(t *testing.T) {
	tests := []struct {
		name     string
		opts     NetworkOptions
		body     string
		wantDeny bool
	}{
		{"denies custom DNS servers by default", NetworkOptions{}, `{"driver":"bridge","network_dns_servers":["10.6.6.6"]}`, true},
		{"allows custom DNS servers when configured", NetworkOptions{AllowDNSServers: true}, `{"driver":"bridge","network_dns_servers":["10.6.6.6"]}`, false},
		{"allows a create that sets no resolvers", NetworkOptions{}, `{"driver":"bridge"}`, false},
		{"allows an explicitly empty resolver list", NetworkOptions{}, `{"driver":"bridge","network_dns_servers":[]}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newNetworkPolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPost, "/libpod/networks/create", strings.NewReader(tt.body))
			reason, err := policy.inspectLibpod(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspectLibpod() error = %v", err)
			}
			if tt.wantDeny {
				if reason != "libpod network create denied: custom DNS servers are not allowed" {
					t.Fatalf("inspectLibpod() reason = %q, want the custom DNS server denial", reason)
				}
				return
			}
			if reason != "" {
				t.Fatalf("inspectLibpod() reason = %q, want empty", reason)
			}
		})
	}
}

// TestLibpodNetworkUpdateVersionedPrefixBehavesIdentically pins that Podman's
// versioned spelling reaches the same verdict, since stripVersionPrefix
// consumes only /vN[.N[.N]]/ and leaves /libpod in place.
func TestLibpodNetworkUpdateVersionedPrefixBehavesIdentically(t *testing.T) {
	for _, raw := range []string{"/v5.0/libpod/networks/mynet/update", "/v5.0.0/libpod/networks/mynet/update"} {
		t.Run(raw, func(t *testing.T) {
			normalized := NormalizePath(raw)
			if !isLibpodNetworkWritePath(normalized) {
				t.Fatalf("isLibpodNetworkWritePath(%q) = false, want true", normalized)
			}
			policy := newNetworkPolicy(NetworkOptions{})
			req := httptest.NewRequest(http.MethodPost, raw, strings.NewReader(`{"adddnsservers":["10.6.6.6"]}`))
			reason, err := policy.inspectLibpod(nil, req, normalized)
			if err != nil {
				t.Fatalf("inspectLibpod() error = %v", err)
			}
			if reason == "" {
				t.Fatal("inspectLibpod() reason = empty, want the DNS server denial")
			}
		})
	}
}

// TestLibpodNetworkUpdateIsWiredIntoTheMiddleware drives the real filter
// chain, so it fails if compileRuntimePolicy's table or
// matchesLibpodNetworkInspection stops routing the update path at the
// inspector — the half a method-level test cannot see.
func TestLibpodNetworkUpdateIsWiredIntoTheMiddleware(t *testing.T) {
	allowAll, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("CompileRule() error = %v", err)
	}

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	handler := MiddlewareWithOptions([]*CompiledRule{allowAll}, testLogger(), Options{
		PolicyConfig: PolicyConfig{
			DenyResponseVerbosity: DenyResponseVerbosityVerbose,
			LibpodNetwork:         NetworkOptions{},
		},
	})(inner)

	tests := []struct {
		name       string
		path       string
		body       string
		wantStatus int
	}{
		{"adding a DNS server is denied", "/libpod/networks/mynet/update", `{"adddnsservers":["10.6.6.6"]}`, http.StatusForbidden},
		{"removing a DNS server is denied", "/libpod/networks/mynet/update", `{"removednsservers":["1.1.1.1"]}`, http.StatusForbidden},
		{"versioned update is denied", "/v5.0/libpod/networks/mynet/update", `{"adddnsservers":["10.6.6.6"]}`, http.StatusForbidden},
		{"create with network_dns_servers is denied", "/libpod/networks/create", `{"driver":"bridge","network_dns_servers":["10.6.6.6"]}`, http.StatusForbidden},
		{"a no-op update reaches upstream", "/libpod/networks/mynet/update", `{}`, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached = false
			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if wantReached := tt.wantStatus == http.StatusOK; reached != wantReached {
				t.Fatalf("upstream reached = %v, want %v", reached, wantReached)
			}
		})
	}
}

// TestDockerNetworkInspectorIgnoresDNSServerFields pins that allow_dns_servers
// stays libpod-only: the Docker-compat inspector must not start denying a
// Docker network create that happens to carry a key by that name, since
// dockerd has no per-network resolver field and would ignore it.
func TestDockerNetworkInspectorIgnoresDNSServerFields(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/networks/create", strings.NewReader(`{"Driver":"bridge","network_dns_servers":["10.6.6.6"],"adddnsservers":["10.6.6.6"]}`))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty — allow_dns_servers has no Docker analog", reason)
	}
}
