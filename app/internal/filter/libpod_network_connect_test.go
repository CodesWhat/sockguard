package filter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// libpodConnectDefaults is the posture every case below is judged against:
// an operator who left request_body.libpod_network at its shipped defaults
// (allow_endpoint_config false, endpoint_config.allow_aliases true,
// allow_disconnect_force false) and expects it to hold on Podman's native
// API surface exactly as request_body.network holds on the Docker-compat one.
func libpodConnectDefaults() NetworkOptions {
	return NetworkOptions{}
}

// TestLibpodNetworkConnectInspect pins the endpoint-config allowlist on
// Podman's native POST /libpod/networks/{name}/connect. Every body spelling
// here is one Podman v5.8.1 actually accepts: its libpod.Connect handler
// decodes entities.NetworkConnectOptions, which is `container` plus an
// embedded, untagged libnetwork/types.PerNetworkOptions — so the endpoint
// fields are top-level and snake_case, and none of Docker's
// {"EndpointConfig":{...}} spelling appears on the wire at all.
func TestLibpodNetworkConnectInspect(t *testing.T) {
	const path = "/libpod/networks/mynet/connect"

	tests := []struct {
		name        string
		opts        NetworkOptions
		body        string
		wantDeny    bool
		wantReasonC string
	}{
		{
			name: "allows a bare connect with no endpoint options",
			opts: libpodConnectDefaults(),
			body: `{"container":"abc123"}`,
		},
		{
			name:        "denies a pinned static IP",
			opts:        libpodConnectDefaults(),
			body:        `{"container":"abc123","static_ips":["10.9.9.9"]}`,
			wantDeny:    true,
			wantReasonC: "static IP configuration",
		},
		{
			name: "allows a pinned static IP when configured",
			opts: NetworkOptions{EndpointConfig: EndpointConfigOptions{AllowStaticAddressing: true}},
			body: `{"container":"abc123","static_ips":["10.9.9.9"]}`,
		},
		{
			name:        "denies a static MAC in colon form",
			opts:        libpodConnectDefaults(),
			body:        `{"container":"abc123","static_mac":"aa:bb:cc:dd:ee:ff"}`,
			wantDeny:    true,
			wantReasonC: "MAC address",
		},
		{
			// types.HardwareAddr.UnmarshalJSON tries net.ParseMAC first and
			// then falls back to a plain []byte decode, so this base64 blob
			// sets the same static MAC on Podman's side. A check that only
			// recognized colon-separated MACs would let it through.
			name:        "denies the base64 static MAC spelling Podman also accepts",
			opts:        libpodConnectDefaults(),
			body:        `{"container":"abc123","static_mac":"qrvM3e7/"}`,
			wantDeny:    true,
			wantReasonC: "MAC address",
		},
		{
			name: "allows a static MAC when configured",
			opts: NetworkOptions{EndpointConfig: EndpointConfigOptions{AllowMACPinning: true}},
			body: `{"container":"abc123","static_mac":"aa:bb:cc:dd:ee:ff"}`,
		},
		{
			// PerNetworkOptions.Options is the libpod analog of Docker
			// EndpointSettings.DriverOpts, which is fail-closed under the
			// granular form: only allow_endpoint_config can admit it. It is
			// also unreachable through the Docker-compat spelling, because
			// Podman's compat.Connect never lowers DriverOpts.
			name:        "denies per-endpoint driver options",
			opts:        libpodConnectDefaults(),
			body:        `{"container":"abc123","options":{"mtu":"1400"}}`,
			wantDeny:    true,
			wantReasonC: "driver options",
		},
		{
			name: "allows per-endpoint driver options under allow_endpoint_config",
			opts: NetworkOptions{AllowEndpointConfig: true},
			body: `{"container":"abc123","options":{"mtu":"1400"}}`,
		},
		{
			// Aliases default to allowed on both surfaces so a Compose-style
			// recreate keeps working — see denyEndpointConfigReason.
			name: "allows aliases by default",
			opts: libpodConnectDefaults(),
			body: `{"container":"abc123","aliases":["web"]}`,
		},
		{
			name:        "denies aliases when allow_aliases is turned off",
			opts:        NetworkOptions{EndpointConfig: EndpointConfigOptions{DenyAliases: true}},
			body:        `{"container":"abc123","aliases":["web"]}`,
			wantDeny:    true,
			wantReasonC: "aliases",
		},
		{
			// interface_name names an interface inside the container's own
			// netns, has no Docker EndpointSettings analog, and is
			// deliberately ungated — see libpodNetworkConnectRequest.
			name: "allows interface_name, which has no Docker analog and no gate",
			opts: libpodConnectDefaults(),
			body: `{"container":"abc123","interface_name":"eth7"}`,
		},
		{
			// encoding/json falls back to a case-insensitive field match, so
			// Podman honors this spelling and so must sockguard.
			name:        "denies the case-folded static_ips spelling Podman accepts",
			opts:        libpodConnectDefaults(),
			body:        `{"container":"abc123","Static_IPs":["10.9.9.9"]}`,
			wantDeny:    true,
			wantReasonC: "static IP configuration",
		},
		{
			// encoding/json takes the LAST value for a repeated key, exactly
			// as Podman's own decode does.
			name:        "denies a repeated static_ips key whose last value pins an address",
			opts:        libpodConnectDefaults(),
			body:        `{"container":"abc123","static_ips":[],"static_ips":["10.9.9.9"]}`,
			wantDeny:    true,
			wantReasonC: "static IP configuration",
		},
		{
			// The libpod inspector must read libpod's shape and only
			// libpod's: a Docker-shaped body carries nothing Podman's
			// handler would act on here.
			name: "ignores Docker's EndpointConfig spelling, which libpod never reads",
			opts: libpodConnectDefaults(),
			body: `{"Container":"abc123","EndpointConfig":{"IPAMConfig":{"IPv4Address":"10.9.9.9"},"MacAddress":"aa:bb:cc:dd:ee:ff"}}`,
		},
		{
			name:        "denies a body that cannot be decoded",
			opts:        libpodConnectDefaults(),
			body:        `{"container":"abc123","static_ips":[[10,9,9,9]]}`,
			wantDeny:    true,
			wantReasonC: "could not be inspected",
		},
		{
			name:        "denies malformed JSON",
			opts:        libpodConnectDefaults(),
			body:        `{`,
			wantDeny:    true,
			wantReasonC: "could not be inspected",
		},
		{
			// Podman json.Decodes straight off r.Body and errors on an empty
			// one, so there is nothing to gate and nothing to leak.
			name: "allows an empty body, which Podman rejects itself",
			opts: libpodConnectDefaults(),
			body: "",
		},
		{
			name: "allows a whitespace-only static IP entry",
			opts: libpodConnectDefaults(),
			body: `{"container":"abc123","static_ips":["  "]}`,
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
				if !strings.HasPrefix(reason, "libpod network connect denied:") {
					t.Fatalf("inspectLibpod() reason = %q, want the libpod network connect subject prefix", reason)
				}
				return
			}
			if reason != "" {
				t.Fatalf("inspectLibpod() reason = %q, want empty", reason)
			}
		})
	}
}

// TestLibpodNetworkDisconnectForceGate pins allow_disconnect_force on
// POST /libpod/networks/{name}/disconnect. Podman registers that route
// directly on the Docker-compat compat.Disconnect handler, which decodes
// docker/api/types/network.DisconnectOptions — so the body really is
// Docker's {"Container","Force"} here, unlike connect.
func TestLibpodNetworkDisconnectForceGate(t *testing.T) {
	const path = "/libpod/networks/mynet/disconnect"

	tests := []struct {
		name     string
		opts     NetworkOptions
		body     string
		wantDeny bool
	}{
		{"denies a force disconnect by default", libpodConnectDefaults(), `{"Container":"abc123","Force":true}`, true},
		{"allows a plain disconnect", libpodConnectDefaults(), `{"Container":"abc123"}`, false},
		{"allows a force disconnect when configured", NetworkOptions{AllowDisconnectForce: true}, `{"Container":"abc123","Force":true}`, false},
		// encoding/json matches an untagged Go field case-insensitively, so
		// Podman honors the lowercase spelling too.
		{"denies the case-folded force spelling Podman accepts", libpodConnectDefaults(), `{"container":"abc123","force":true}`, true},
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
				if reason != "libpod network disconnect denied: force disconnect is not allowed" {
					t.Fatalf("inspectLibpod() reason = %q, want the libpod force-disconnect denial", reason)
				}
				return
			}
			if reason != "" {
				t.Fatalf("inspectLibpod() reason = %q, want empty", reason)
			}
		})
	}
}

// TestLibpodNetworkConnectVersionedPrefixBehavesIdentically pins that
// Podman's versioned spelling reaches the same verdict as the bare one.
// stripVersionPrefix consumes only /vN[.N[.N]]/ and leaves /libpod in place,
// which is exactly the normalization step a path-list-based fix tends to get
// wrong.
func TestLibpodNetworkConnectVersionedPrefixBehavesIdentically(t *testing.T) {
	pairs := []struct {
		name     string
		raw      string
		body     string
		wantDeny bool
	}{
		{"versioned connect denies a static IP", "/v5.0/libpod/networks/mynet/connect", `{"container":"abc","static_ips":["10.9.9.9"]}`, true},
		{"versioned connect allows a bare body", "/v5.0/libpod/networks/mynet/connect", `{"container":"abc"}`, false},
		{"three-part versioned connect denies a static IP", "/v5.0.0/libpod/networks/mynet/connect", `{"container":"abc","static_ips":["10.9.9.9"]}`, true},
		{"versioned disconnect denies force", "/v5.0/libpod/networks/mynet/disconnect", `{"Force":true}`, true},
	}

	for _, tt := range pairs {
		t.Run(tt.name, func(t *testing.T) {
			normalized := NormalizePath(tt.raw)
			if !strings.HasPrefix(normalized, libpodPathPrefix) {
				t.Fatalf("NormalizePath(%q) = %q, want it to keep the /libpod/ prefix", tt.raw, normalized)
			}
			if !isLibpodNetworkWritePath(normalized) {
				t.Fatalf("isLibpodNetworkWritePath(%q) = false, want true", normalized)
			}

			policy := newNetworkPolicy(libpodConnectDefaults())
			req := httptest.NewRequest(http.MethodPost, tt.raw, strings.NewReader(tt.body))
			reason, err := policy.inspectLibpod(nil, req, normalized)
			if err != nil {
				t.Fatalf("inspectLibpod() error = %v", err)
			}
			if tt.wantDeny && reason == "" {
				t.Fatal("inspectLibpod() reason = empty, want a denial")
			}
			if !tt.wantDeny && reason != "" {
				t.Fatalf("inspectLibpod() reason = %q, want empty", reason)
			}
		})
	}
}

// TestNetworkConnectInspectorRoutingIsPathExclusive is the network-connect
// instance of TestInspectorRoutingIsPathExclusive's invariant: one body
// carries a Docker-shaped dangerous value and a libpod-shaped safe one, and
// a second body carries the reverse. A wrong-shape read flips the verdict,
// and each inspector must be a structural no-op on the other family's path.
func TestNetworkConnectInspectorRoutingIsPathExclusive(t *testing.T) {
	const dockerPath = "/networks/mynet/connect"
	const libpodPath = "/libpod/networks/mynet/connect"

	dockerDangerousLibpodSafe := `{"Container":"abc","EndpointConfig":{"MacAddress":"aa:bb:cc:dd:ee:ff"},"container":"abc","static_mac":""}`
	dockerSafeLibpodDangerous := `{"Container":"abc","EndpointConfig":{"Aliases":["web"]},"container":"abc","static_mac":"aa:bb:cc:dd:ee:ff"}`

	policy := newNetworkPolicy(libpodConnectDefaults())

	t.Run("docker inspector reads only EndpointConfig", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, dockerPath, strings.NewReader(dockerDangerousLibpodSafe))
		reason, err := policy.inspect(nil, req, dockerPath)
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if reason == "" {
			t.Fatal("want deny: EndpointConfig.MacAddress is set, got allow — Docker inspector ignored its own shape")
		}

		req2 := httptest.NewRequest(http.MethodPost, dockerPath, strings.NewReader(dockerSafeLibpodDangerous))
		reason2, err := policy.inspect(nil, req2, dockerPath)
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if reason2 != "" {
			t.Fatalf("want allow: got deny %q — Docker inspector leaked libpod's static_mac", reason2)
		}
	})

	t.Run("libpod inspector reads only the top-level libpod fields", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, libpodPath, strings.NewReader(dockerDangerousLibpodSafe))
		reason, err := policy.inspectLibpod(nil, req, libpodPath)
		if err != nil {
			t.Fatalf("inspectLibpod() error = %v", err)
		}
		if reason != "" {
			t.Fatalf("want allow: got deny %q — libpod inspector leaked EndpointConfig.MacAddress", reason)
		}

		req2 := httptest.NewRequest(http.MethodPost, libpodPath, strings.NewReader(dockerSafeLibpodDangerous))
		reason2, err := policy.inspectLibpod(nil, req2, libpodPath)
		if err != nil {
			t.Fatalf("inspectLibpod() error = %v", err)
		}
		if reason2 == "" {
			t.Fatal("want deny: static_mac is set, got allow — libpod inspector ignored its own shape")
		}
	})

	t.Run("docker inspector is a structural no-op on the libpod path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, libpodPath, strings.NewReader(dockerDangerousLibpodSafe))
		reason, err := policy.inspect(nil, req, libpodPath)
		if err != nil || reason != "" {
			t.Fatalf("inspect() = (%q, %v), want (\"\", nil) — Docker inspector must never fire on a libpod path", reason, err)
		}
	})

	t.Run("libpod inspector is a structural no-op on the docker path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, dockerPath, strings.NewReader(dockerSafeLibpodDangerous))
		reason, err := policy.inspectLibpod(nil, req, dockerPath)
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpod() = (%q, %v), want (\"\", nil) — libpod inspector must never fire on the Docker path", reason, err)
		}
	})
}

// TestDockerNetworkConnectUnchangedByLibpodSharing guards the regression
// direction of extracting denyDisconnectReason and isNetworkActionPathUnder:
// the Docker-compat verdicts and denial strings must be byte-identical to
// what they were before the libpod spellings started sharing them.
func TestDockerNetworkConnectUnchangedByLibpodSharing(t *testing.T) {
	tests := []struct {
		name       string
		opts       NetworkOptions
		path       string
		body       string
		wantReason string
	}{
		{"connect still denies a static IP", NetworkOptions{}, "/networks/mynet/connect", `{"EndpointConfig":{"IPAMConfig":{"IPv4Address":"10.9.9.9"}}}`, "network connect denied: endpoint static IP configuration is not allowed"},
		{"connect still denies driver options", NetworkOptions{}, "/networks/mynet/connect", `{"EndpointConfig":{"DriverOpts":{"mtu":"1400"}}}`, "network connect denied: endpoint driver options are not allowed"},
		{"connect still allows aliases", NetworkOptions{}, "/networks/mynet/connect", `{"EndpointConfig":{"Aliases":["web"]}}`, ""},
		{"disconnect still denies force with the same message", NetworkOptions{}, "/networks/mynet/disconnect", `{"Force":true}`, "network disconnect denied: force disconnect is not allowed"},
		{"disconnect still allows force when configured", NetworkOptions{AllowDisconnectForce: true}, "/networks/mynet/disconnect", `{"Force":true}`, ""},
		{"create still denies a custom driver", NetworkOptions{}, "/networks/create", `{"Driver":"weird"}`, `network create denied: driver "weird" is not allowed`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newNetworkPolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))
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

// TestLibpodNetworkConnectIsWiredIntoTheMiddleware drives the real filter
// chain rather than the policy method, so it fails if compileRuntimePolicy's
// table or matchesLibpodNetworkInspection stops routing the libpod
// connect/disconnect paths at the inspector — the half of the gap that a
// method-level test cannot see.
func TestLibpodNetworkConnectIsWiredIntoTheMiddleware(t *testing.T) {
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
		{"libpod connect with a pinned static IP is denied", "/libpod/networks/mynet/connect", `{"container":"abc","static_ips":["10.9.9.9"]}`, http.StatusForbidden},
		{"versioned libpod connect with a pinned MAC is denied", "/v5.0/libpod/networks/mynet/connect", `{"container":"abc","static_mac":"aa:bb:cc:dd:ee:ff"}`, http.StatusForbidden},
		{"libpod connect with per-endpoint driver options is denied", "/libpod/networks/mynet/connect", `{"container":"abc","options":{"mtu":"1400"}}`, http.StatusForbidden},
		{"libpod force disconnect is denied", "/libpod/networks/mynet/disconnect", `{"Force":true}`, http.StatusForbidden},
		{"libpod connect with no endpoint options reaches upstream", "/libpod/networks/mynet/connect", `{"container":"abc"}`, http.StatusOK},
		{"libpod connect with aliases reaches upstream", "/libpod/networks/mynet/connect", `{"container":"abc","aliases":["web"]}`, http.StatusOK},
		{"libpod disconnect without force reaches upstream", "/libpod/networks/mynet/disconnect", `{"Container":"abc"}`, http.StatusOK},
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

// TestLibpodNetworkWritePathCoversTheWholeLibpodNetworkSurface pins the
// membership predicate the middleware and the inspector now share, including
// the near-misses a hand-written path list gets wrong.
func TestLibpodNetworkWritePathCoversTheWholeLibpodNetworkSurface(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/libpod/networks/create", true},
		{"/libpod/networks/mynet/connect", true},
		{"/libpod/networks/mynet/disconnect", true},
		{"/libpod/networks/mynet/update", true},
		{"/libpod/networks/json", false},
		{"/libpod/networks/prune", false},
		{"/libpod/networks/mynet/connect/extra", false},
		{"/libpod/networks//connect", false},
		{"/networks/mynet/connect", false},
		{"/networks/mynet/disconnect", false},
		{"/networks/create", false},
		{"/libpod/networks", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isLibpodNetworkWritePath(tt.path); got != tt.want {
				t.Fatalf("isLibpodNetworkWritePath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
