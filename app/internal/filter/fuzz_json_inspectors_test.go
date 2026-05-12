package filter

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

const (
	maxJSONInspectorFuzzBytes    = maxServiceBodyBytes + 1024
	maxSwarmInspectorFuzzBytes   = maxSwarmBodyBytes + 1024
	maxPluginInspectorFuzzBytes  = maxPluginConfigBytes + (8 << 10)
	maxNetworkInspectorFuzzBytes = maxNetworkBodyBytes + 1024
)

func FuzzVolume(f *testing.F) {
	f.Add([]byte(`{"Name":"cache"}`))
	f.Add([]byte(`{"Driver":"nfs"}`))
	f.Add([]byte(`{"DriverOpts":{"device":"/srv/data"}}`))
	f.Add([]byte(`{`))
	f.Add(bytes.Repeat([]byte("a"), maxVolumeBodyBytes+1))

	policy := newVolumePolicy(VolumeOptions{
		AllowCustomDrivers: true,
		AllowDriverOpts:    true,
	})

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, maxJSONInspectorFuzzBytes)

		req := newJSONInspectorFuzzRequest(http.MethodPost, "/volumes/create", "", body)
		_, _ = policy.inspect(nil, req, "/volumes/create")
		drainFuzzRequestBody(req)
	})
}

func FuzzSecret(f *testing.F) {
	f.Add([]byte(`{"Name":"db-password","Data":"c2VjcmV0"}`))
	f.Add([]byte(`{"Driver":"vault"}`))
	f.Add([]byte(`{"Templating":{"Name":"golang-template"}}`))
	f.Add([]byte(`{`))
	f.Add(bytes.Repeat([]byte("a"), maxSecretBodyBytes+1))

	policy := newSecretPolicy(SecretOptions{
		AllowCustomDrivers:   true,
		AllowTemplateDrivers: true,
	})

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, maxJSONInspectorFuzzBytes)

		req := newJSONInspectorFuzzRequest(http.MethodPost, "/secrets/create", "", body)
		_, _ = policy.inspect(nil, req, "/secrets/create")
		drainFuzzRequestBody(req)
	})
}

func FuzzConfigWrite(f *testing.F) {
	f.Add([]byte(`{"Name":"app-config","Data":"Y29uZmln"}`))
	f.Add([]byte(`{"Driver":"vault"}`))
	f.Add([]byte(`{"TemplateDriver":"sprig"}`))
	f.Add([]byte(`{`))
	f.Add(bytes.Repeat([]byte("a"), maxConfigWriteBodyBytes+1))

	policy := newConfigPolicy(ConfigOptions{
		AllowCustomDrivers:   true,
		AllowTemplateDrivers: true,
	})

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, maxJSONInspectorFuzzBytes)

		req := newJSONInspectorFuzzRequest(http.MethodPost, "/configs/create", "", body)
		_, _ = policy.inspect(nil, req, "/configs/create")
		drainFuzzRequestBody(req)
	})
}

func FuzzService(f *testing.F) {
	f.Add("/services/create", []byte(`{"TaskTemplate":{"ContainerSpec":{"Image":"busybox","Mounts":[{"Type":"bind","Source":"/allowed"}]}}}`))
	f.Add("/services/svc-1/update", []byte(`{"TaskTemplate":{"ContainerSpec":{"Image":"registry.example.com/acme/web:latest","Mounts":[{"Type":"bind","Source":"/allowed"}]}},"Networks":[{"Target":"host"}]}`))
	f.Add("/v1.54/services/create", []byte(`{`))
	f.Add("/services/create", bytes.Repeat([]byte("a"), maxServiceBodyBytes+1))

	policy := newServicePolicy(ServiceOptions{
		AllowedBindMounts: []string{"/allowed"},
		AllowOfficial:     true,
		AllowedRegistries: []string{"registry.example.com"},
	})

	f.Fuzz(func(t *testing.T, path string, body []byte) {
		body = truncateParserFuzzBytes(body, maxJSONInspectorFuzzBytes)

		req := newJSONInspectorFuzzRequest(http.MethodPost, path, "", body)
		_, _ = policy.inspect(nil, req, NormalizePath(path))
		drainFuzzRequestBody(req)
	})
}

func FuzzSwarm(f *testing.F) {
	f.Add("/swarm/init", "", []byte(`{"ForceNewCluster":true,"Spec":{"CAConfig":{"ExternalCAs":[{}]}}}`))
	f.Add("/swarm/join", "", []byte(`{"RemoteAddrs":["manager.internal:2377","other.internal:2377"]}`))
	f.Add("/swarm/update", "rotateWorkerToken=1&rotateManagerUnlockKey=1", []byte(`{"CAConfig":{"SigningCAKey":"pem"},"EncryptionConfig":{"AutoLockManagers":true}}`))
	f.Add("/v1.54/swarm/update", "", []byte(`{`))
	f.Add("/swarm/init", "", bytes.Repeat([]byte("a"), maxSwarmBodyBytes+1))

	policy := newSwarmPolicy(SwarmOptions{
		AllowForceNewCluster:   true,
		AllowExternalCA:        true,
		AllowedJoinRemoteAddrs: []string{"manager.internal:2377"},
		AllowTokenRotation:     true,
		AllowSigningCAUpdate:   true,
	})

	f.Fuzz(func(t *testing.T, path, rawQuery string, body []byte) {
		body = truncateParserFuzzBytes(body, maxSwarmInspectorFuzzBytes)

		req := newJSONInspectorFuzzRequest(http.MethodPost, path, rawQuery, body)
		_, _ = policy.inspect(nil, req, NormalizePath(path))
		drainFuzzRequestBody(req)
	})
}

func FuzzPlugin(f *testing.F) {
	f.Add("/plugins/pull", "remote=registry.example.com%2Facme%2Fplugin%3A1.0", []byte(`[{"Name":"network","Value":["bridge"]}]`))
	f.Add("/plugins/acme/upgrade", "remote=registry.example.com%2Facme%2Fplugin%3A1.0", []byte(`[{"Name":"mount","Value":["/allowed"]}]`))
	f.Add("/plugins/acme/set", "", []byte(`["mybind.source=/allowed","mydevice.path=/dev/allowed","DEBUG=1"]`))
	f.Add("/plugins/create", "name=acme%2Fplugin", mustPluginCreateContextPayload(f, `{"Mounts":[{"Source":"/allowed"}],"Linux":{"Capabilities":["NET_ADMIN"],"Devices":[{"Path":"/dev/allowed"}]}}`, false))
	f.Add("/plugins/create", "name=acme%2Fplugin", mustPluginCreateContextPayload(f, `{`, true))

	policy := newPluginPolicy(PluginOptions{
		AllowedBindMounts:     []string{"/allowed"},
		AllowedDevices:        []string{"/dev/allowed"},
		AllowedCapabilities:   []string{"NET_ADMIN"},
		AllowedRegistries:     []string{"registry.example.com"},
		AllowOfficial:         true,
		AllowedSetEnvPrefixes: []string{"DEBUG="},
	})

	f.Fuzz(func(t *testing.T, path, rawQuery string, body []byte) {
		body = truncateParserFuzzBytes(body, maxPluginInspectorFuzzBytes)

		req := newJSONInspectorFuzzRequest(http.MethodPost, path, rawQuery, body)
		_, _ = policy.inspect(nil, req, NormalizePath(path))
		drainFuzzRequestBody(req)
	})
}

func FuzzNetwork(f *testing.F) {
	f.Add("/networks/create", []byte(`{"Driver":"bridge","Name":"app-net"}`))
	f.Add("/networks/create", []byte(`{"Driver":"custom","Scope":"swarm","Ingress":true,"Attachable":true,"ConfigOnly":true,"ConfigFrom":{"Network":"base"},"IPAM":{"Driver":"custom","Config":[{}],"Options":{"foo":"bar"}},"Options":{"opt":"val"}}`))
	f.Add("/networks/net-1/connect", []byte(`{"EndpointConfig":{"IPAMConfig":{"IPv4Address":"10.0.0.5"},"MacAddress":"02:42:ac:11:00:05","Aliases":["web"],"DriverOpts":{"x":"y"}}}`))
	f.Add("/networks/net-1/disconnect", []byte(`{"Force":true}`))
	f.Add("/networks/create", []byte(`{`))
	f.Add("/v1.54/networks/create", bytes.Repeat([]byte("a"), maxNetworkBodyBytes+1))

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
		AllowEndpointConfig:    true,
		AllowDisconnectForce:   true,
	})

	f.Fuzz(func(t *testing.T, path string, body []byte) {
		body = truncateParserFuzzBytes(body, maxNetworkInspectorFuzzBytes)

		req := newJSONInspectorFuzzRequest(http.MethodPost, path, "", body)
		_, _ = policy.inspect(nil, req, NormalizePath(path))
		drainFuzzRequestBody(req)
	})
}

func newJSONInspectorFuzzRequest(method, path, rawQuery string, body []byte) *http.Request {
	req := httptest.NewRequest(method, "http://sockguard.test/", bytes.NewReader(body))
	req.URL = &url.URL{Path: path, RawQuery: rawQuery}
	return req
}

func drainFuzzRequestBody(req *http.Request) {
	if req == nil || req.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, req.Body)
	_ = req.Body.Close()
}
