package filter

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// denied reports whether an inspector refused the request: a deny reason or a
// rejection error. Only ("", nil) lets a body through.
// fuzzLibpodBodyCap keeps mutated bodies small: the 1 MiB limits are exercised
// by TestLibpodCreateInspectorsRejectOverLimitBodies, and megabyte inputs drag
// the fuzzer to a crawl.
const fuzzLibpodBodyCap = 16 << 10

func denied(reason string, err error) bool { return reason != "" || err != nil }

func registryHeaderSeed(payload string) string {
	return base64.URLEncoding.EncodeToString([]byte(payload))
}

// FuzzRegistryAuthHeader drives denyRegistryAuthHeaderReason with arbitrary
// header values and allowlist shapes. The header is attacker controlled, so
// the decoder must never panic.
func FuzzRegistryAuthHeader(f *testing.F) {
	f.Add(registryHeaderSeed(`{"username":"u","password":"p","serveraddress":"registry.example.com"}`), false)
	f.Add(registryHeaderSeed(`{"serveraddress":"https://evil.example.com/v2/"}`), false)
	f.Add(registryHeaderSeed(`{"identitytoken":"abc"}`), true)
	f.Add(registryHeaderSeed(`not json`), false)
	f.Add("!!!not-base64!!!", false)
	f.Add("", false)
	f.Add(strings.Repeat("A", maxRegistryAuthHeaderBytes+1), false)

	f.Fuzz(func(t *testing.T, header string, allowAll bool) {
		allowed := []string{"registry.example.com"}
		reason := denyRegistryAuthHeaderReason(header, allowAll, allowed, "image pull")
		_ = denyRegistryAuthHeaderReason(header, allowAll, nil, "image push")

		trimmed := strings.TrimSpace(header)
		if trimmed == "" {
			if reason != "" {
				t.Fatalf("empty header denied: %q", reason)
			}
			return
		}
		if len(trimmed) > maxRegistryAuthHeaderBytes && reason == "" {
			t.Fatalf("over-limit header (%d bytes) was allowed", len(trimmed))
		}
		decoded, err := decodeRegistryAuthHeaderBytes(trimmed, "X-Registry-Auth", "image pull")
		if err != nil {
			if reason == "" {
				t.Fatalf("undecodable header was allowed: %v", err)
			}
			return
		}
		if len(decoded) > maxRegistryAuthHeaderBytes {
			t.Fatalf("decoded %d bytes, over the %d cap", len(decoded), maxRegistryAuthHeaderBytes)
		}
		// Re-encoding the decoded bytes must decode back to the same bytes.
		if again := base64.StdEncoding.EncodeToString(decoded); len(again) <= maxRegistryAuthHeaderBytes {
			round, err := decodeRegistryAuthHeaderBytes(again, "X-Registry-Auth", "image pull")
			if err != nil || !bytes.Equal(round, decoded) {
				t.Fatalf("round trip changed the payload: %v", err)
			}
		}
		if reason != "" || allowAll {
			return
		}
		// Allowed with an allowlist active: any serveraddress must be listed.
		var auth registryAuthHeader
		if json.Unmarshal(decoded, &auth) != nil {
			t.Fatal("allowed a header whose payload is not JSON")
		}
		if server := strings.TrimSpace(auth.ServerAddress); server != "" {
			host, ok := normalizeRegistryHost(stripRegistryHeaderScheme(server))
			if !ok || host != "registry.example.com" {
				t.Fatalf("allowed serveraddress %q outside the allowlist", server)
			}
		}
	})
}

// FuzzRegistryConfigHeader drives denyRegistryConfigHeaderReason, the
// X-Registry-Config decoder behind POST /build.
func FuzzRegistryConfigHeader(f *testing.F) {
	f.Add(registryHeaderSeed(`{"registry.example.com":{"username":"u","password":"p"}}`))
	f.Add(registryHeaderSeed(`{}`))
	f.Add(registryHeaderSeed(`[1,2,3]`))
	f.Add(registryHeaderSeed(`null`))
	f.Add("%%%")
	f.Add("")
	f.Add(strings.Repeat("B", maxRegistryAuthHeaderBytes+1))

	f.Fuzz(func(t *testing.T, header string) {
		reason := denyRegistryConfigHeaderReason(header, "build")
		trimmed := strings.TrimSpace(header)
		if trimmed == "" {
			return
		}
		if len(trimmed) > maxRegistryAuthHeaderBytes && reason == "" {
			t.Fatalf("over-limit header (%d bytes) was allowed", len(trimmed))
		}
		if reason != "" {
			return
		}
		decoded, err := decodeRegistryAuthHeaderBytes(trimmed, "X-Registry-Config", "build")
		if err != nil || len(decoded) > maxRegistryAuthHeaderBytes {
			t.Fatalf("allowed a header that does not decode within the cap: %v", err)
		}
		var cfg map[string]json.RawMessage
		if json.Unmarshal(decoded, &cfg) != nil {
			t.Fatal("allowed a header whose payload is not a JSON object")
		}
	})
}

func FuzzLibpodPodCreate(f *testing.F) {
	f.Add([]byte(`{"name":"p","infra_image":"registry.example.com/pause:latest"}`))
	f.Add([]byte(`{"netns":{"nsmode":"host"},"pidns":{"nsmode":"host"}}`))
	f.Add([]byte(`{"ipcns":{"nsmode":"path","value":"/proc/1/ns/ipc"},"userns":{"nsmode":"host"},"utsns":{"nsmode":"host"}}`))
	f.Add([]byte(`{"share":["pid","net"],"share_parent":true}`))
	f.Add([]byte(`{"netns":"host"}`))
	f.Add([]byte(`{`))

	policies := []libpodPodCreatePolicy{
		newLibpodPodCreatePolicy(LibpodPodCreateOptions{}),
		newLibpodPodCreatePolicy(LibpodPodCreateOptions{
			AllowHostNetwork: true, AllowHostPID: true, AllowHostIPC: true,
			AllowHostUserNS: true, AllowHostUTS: true, AllowSharedPIDNamespace: true,
		}),
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, fuzzLibpodBodyCap)
		for i, policy := range policies {
			req := newJSONInspectorFuzzRequest(http.MethodPost, "/libpod/pods/create", "", body)
			reason, err := policy.inspect(nil, req, "/libpod/pods/create")
			drainFuzzRequestBody(req)
			if i != 0 {
				continue
			}
			// The zero-option policy must refuse every host namespace.
			var decoded map[string]struct {
				NSMode string `json:"nsmode"`
			}
			if json.Unmarshal(body, &decoded) != nil {
				continue
			}
			for key, ns := range decoded {
				switch strings.ToLower(key) {
				case "netns", "pidns", "ipcns", "userns", "utsns":
					if strings.EqualFold(strings.TrimSpace(ns.NSMode), "host") && !denied(reason, err) {
						t.Fatalf("zero-option policy allowed %s nsmode host: %s", key, body)
					}
				}
			}
		}
	})
}

func FuzzLibpodVolumeCreate(f *testing.F) {
	f.Add([]byte(`{"Name":"cache"}`))
	f.Add([]byte(`{"Driver":"nfs"}`))
	f.Add([]byte(`{"Driver":"local","Options":{"type":"none","o":"bind","device":"/"}}`))
	f.Add([]byte(`{"Options":{"device":"//dev/sda1"}}`))
	f.Add([]byte(`{"Options":"x"}`))
	f.Add([]byte(`{`))

	policies := []volumePolicy{
		newVolumePolicy(VolumeOptions{}),
		newVolumePolicy(VolumeOptions{AllowCustomDrivers: true, AllowDriverOpts: true}),
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, fuzzLibpodBodyCap)
		for i, policy := range policies {
			req := newJSONInspectorFuzzRequest(http.MethodPost, "/libpod/volumes/create", "", body)
			reason, err := policy.inspectLibpod(nil, req, "/libpod/volumes/create")
			drainFuzzRequestBody(req)
			if i != 0 {
				continue
			}
			var decoded struct {
				Driver  string            `json:"Driver"`
				Options map[string]string `json:"Options"`
			}
			if json.Unmarshal(body, &decoded) != nil {
				continue
			}
			driver := strings.TrimSpace(decoded.Driver)
			custom := driver != "" && !strings.EqualFold(driver, "local")
			if (custom || len(decoded.Options) > 0) && !denied(reason, err) {
				t.Fatalf("zero-option policy allowed a custom driver or driver options: %s", body)
			}
		}
	})
}

func FuzzLibpodNetworkCreate(f *testing.F) {
	f.Add([]byte(`{"name":"app-net","driver":"bridge"}`))
	f.Add([]byte(`{"driver":"macvlan","options":{"parent":"eth0"}}`))
	f.Add([]byte(`{"ipam_options":{"driver":"dhcp"},"subnets":[{"subnet":"10.0.0.0/24"}]}`))
	f.Add([]byte(`{"internal":true,"dns_enabled":true,"ipv6_enabled":true}`))
	f.Add([]byte(`{"driver":1}`))
	f.Add([]byte(`{`))

	policies := []networkPolicy{
		newNetworkPolicy(NetworkOptions{}),
		newNetworkPolicy(NetworkOptions{
			AllowCustomDrivers: true, AllowCustomIPAMDrivers: true,
			AllowCustomIPAMConfig: true, AllowIPAMOptions: true, AllowDriverOptions: true,
		}),
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, fuzzLibpodBodyCap)
		for i, policy := range policies {
			req := newJSONInspectorFuzzRequest(http.MethodPost, "/libpod/networks/create", "", body)
			reason, err := policy.inspectLibpodCreate(nil, req, "/libpod/networks/create")
			drainFuzzRequestBody(req)
			if i != 0 {
				continue
			}
			var decoded struct {
				Options          map[string]string `json:"options"`
				IPAMOptions      map[string]string `json:"ipam_options"`
				Subnets          []json.RawMessage `json:"subnets"`
				NetworkInterface string            `json:"network_interface"`
			}
			if json.Unmarshal(body, &decoded) != nil {
				continue
			}
			gated := len(decoded.Options) > 0 || len(decoded.IPAMOptions) > 0 || len(decoded.Subnets) > 0 || strings.TrimSpace(decoded.NetworkInterface) != ""
			if gated && !denied(reason, err) {
				t.Fatalf("zero-option policy allowed a gated field: %s", body)
			}
		}
	})
}

func TestLibpodCreateInspectorsRejectOverLimitBodies(t *testing.T) {
	t.Parallel()
	pod := newLibpodPodCreatePolicy(LibpodPodCreateOptions{})
	volume := newVolumePolicy(VolumeOptions{AllowCustomDrivers: true, AllowDriverOpts: true})
	network := newNetworkPolicy(NetworkOptions{AllowCustomDrivers: true, AllowDriverOptions: true})
	cases := []struct {
		name    string
		path    string
		max     int
		inspect func(*http.Request) (string, error)
	}{
		{"pod", "/libpod/pods/create", maxLibpodPodCreateBodyBytes, func(r *http.Request) (string, error) { return pod.inspect(nil, r, "/libpod/pods/create") }},
		{"volume", "/libpod/volumes/create", maxLibpodVolumeBodyBytes, func(r *http.Request) (string, error) {
			return volume.inspectLibpod(nil, r, "/libpod/volumes/create")
		}},
		{"network", "/libpod/networks/create", maxLibpodNetworkBodyBytes, func(r *http.Request) (string, error) {
			return network.inspectLibpodCreate(nil, r, "/libpod/networks/create")
		}},
	}
	for _, tc := range cases {
		req := newJSONInspectorFuzzRequest(http.MethodPost, tc.path, "", bytes.Repeat([]byte("a"), tc.max+1))
		reason, err := tc.inspect(req)
		drainFuzzRequestBody(req)
		if !denied(reason, err) {
			t.Fatalf("%s: an over-limit body was allowed", tc.name)
		}
	}
}
