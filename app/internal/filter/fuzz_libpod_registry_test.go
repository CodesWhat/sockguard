package filter

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

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
		_ = denyRegistryAuthHeaderReason(header, allowAll, []string{"registry.example.com"}, "image pull")
		_ = denyRegistryAuthHeaderReason(header, allowAll, nil, "image push")
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
		_ = denyRegistryConfigHeaderReason(header, "build")
	})
}

func FuzzLibpodPodCreate(f *testing.F) {
	f.Add([]byte(`{"name":"p","infra_image":"registry.example.com/pause:latest"}`))
	f.Add([]byte(`{"netns":{"nsmode":"host"},"pidns":{"nsmode":"host"}}`))
	f.Add([]byte(`{"ipcns":{"nsmode":"path","value":"/proc/1/ns/ipc"},"userns":{"nsmode":"host"},"utsns":{"nsmode":"host"}}`))
	f.Add([]byte(`{"share":["pid","net"],"share_parent":true}`))
	f.Add([]byte(`{"netns":"host"}`))
	f.Add([]byte(`{`))
	f.Add(bytes.Repeat([]byte("a"), maxLibpodPodCreateBodyBytes+1))

	policies := []libpodPodCreatePolicy{
		newLibpodPodCreatePolicy(LibpodPodCreateOptions{}),
		newLibpodPodCreatePolicy(LibpodPodCreateOptions{
			AllowHostNetwork: true, AllowHostPID: true, AllowHostIPC: true,
			AllowHostUserNS: true, AllowHostUTS: true, AllowSharedPIDNamespace: true,
		}),
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, maxLibpodPodCreateBodyBytes+1024)
		for _, policy := range policies {
			req := newJSONInspectorFuzzRequest(http.MethodPost, "/libpod/pods/create", "", body)
			_, _ = policy.inspect(nil, req, "/libpod/pods/create")
			drainFuzzRequestBody(req)
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
	f.Add(bytes.Repeat([]byte("a"), maxLibpodVolumeBodyBytes+1))

	policies := []volumePolicy{
		newVolumePolicy(VolumeOptions{}),
		newVolumePolicy(VolumeOptions{AllowCustomDrivers: true, AllowDriverOpts: true}),
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, maxLibpodVolumeBodyBytes+1024)
		for _, policy := range policies {
			req := newJSONInspectorFuzzRequest(http.MethodPost, "/libpod/volumes/create", "", body)
			_, _ = policy.inspectLibpod(nil, req, "/libpod/volumes/create")
			drainFuzzRequestBody(req)
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
	f.Add(bytes.Repeat([]byte("a"), maxLibpodNetworkBodyBytes+1))

	policies := []networkPolicy{
		newNetworkPolicy(NetworkOptions{}),
		newNetworkPolicy(NetworkOptions{
			AllowCustomDrivers: true, AllowCustomIPAMDrivers: true,
			AllowCustomIPAMConfig: true, AllowIPAMOptions: true, AllowDriverOptions: true,
		}),
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, maxLibpodNetworkBodyBytes+1024)
		for _, policy := range policies {
			req := newJSONInspectorFuzzRequest(http.MethodPost, "/libpod/networks/create", "", body)
			_, _ = policy.inspectLibpodCreate(nil, req, "/libpod/networks/create")
			drainFuzzRequestBody(req)
		}
	})
}
