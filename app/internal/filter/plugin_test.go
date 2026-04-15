package filter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewPluginPolicyNormalizesAllowlists(t *testing.T) {
	policy := newPluginPolicy(PluginOptions{
		AllowedBindMounts:   []string{"", "relative", "/safe", "/safe/", "/safe/../safe"},
		AllowedDevices:      []string{"", "/dev/null", "/dev/null/", "/dev/../null"},
		AllowedCapabilities: []string{"", "net_admin", "NET_ADMIN", "SYS_ADMIN"},
		AllowedRegistries:   []string{"", "Registry.Example.com", "registry.example.com"},
	})

	if got, want := policy.allowedBindMounts, []string{"/safe"}; !slicesEqual(got, want) {
		t.Fatalf("allowedBindMounts = %v, want %v", got, want)
	}
	if got, want := policy.allowedDevices, []string{"/dev/null", "/null"}; !slicesEqual(got, want) {
		t.Fatalf("allowedDevices = %v, want %v", got, want)
	}
	if got, want := policy.allowedCapabilities, []string{"NET_ADMIN", "SYS_ADMIN"}; !slicesEqual(got, want) {
		t.Fatalf("allowedCapabilities = %v, want %v", got, want)
	}
	if got, want := policy.imagePolicy.allowedRegistries, []string{"registry.example.com"}; !slicesEqual(got, want) {
		t.Fatalf("allowedRegistries = %v, want %v", got, want)
	}
}

func TestPluginPolicyInspectPullDeniesUnallowlistedRegistry(t *testing.T) {
	policy := newPluginPolicy(PluginOptions{
		AllowedRegistries: []string{"registry.example.com"},
	})

	req := httptest.NewRequest(http.MethodPost, "/plugins/pull?remote=evil.example.com/acme/plugin:1.0&name=acme/plugin", bytes.NewBufferString(`[{"Name":"network","Value":["bridge"]}]`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != `plugin pull denied: registry "evil.example.com" is not allowlisted` {
		t.Fatalf("reason = %q", reason)
	}
}

func TestPluginPolicyInspectUpgradeUsesRemoteAndPrivileges(t *testing.T) {
	policy := newPluginPolicy(PluginOptions{
		AllowHostNetwork:  false,
		AllowOfficial:     false,
		AllowedRegistries: []string{"registry.example.com"},
	})

	req := httptest.NewRequest(http.MethodPost, "/plugins/acme/upgrade?remote=registry.example.com/acme/plugin:1.0", bytes.NewBufferString(`[{"Name":"network","Value":["host"]}]`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "plugin upgrade denied: host network is not allowed" {
		t.Fatalf("reason = %q", reason)
	}

	body, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		t.Fatalf("ReadAll() error = %v", readErr)
	}
	if string(body) != `[{"Name":"network","Value":["host"]}]` {
		t.Fatalf("body = %q", string(body))
	}
}

func TestPluginPolicyInspectSetDeniesDisallowedMountAndDevice(t *testing.T) {
	policy := newPluginPolicy(PluginOptions{
		AllowedBindMounts:     []string{"/allowed"},
		AllowedDevices:        []string{"/dev/allowed"},
		AllowedSetEnvPrefixes: []string{"DEBUG="},
	})

	req := httptest.NewRequest(http.MethodPost, "/plugins/acme/set", bytes.NewBufferString(`["mybind.source=/denied","mydevice.path=/dev/denied"]`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != `plugin set denied: bind mount source "/denied" is not allowlisted` {
		t.Fatalf("reason = %q", reason)
	}
}

func TestPluginPolicyInspectSetAllowsBodyAndPreservesIt(t *testing.T) {
	policy := newPluginPolicy(PluginOptions{
		AllowedBindMounts:     []string{"/allowed"},
		AllowedDevices:        []string{"/dev/allowed"},
		AllowedSetEnvPrefixes: []string{"DEBUG="},
	})

	payload := []byte(`["mybind.source=/allowed","mydevice.path=/dev/allowed","DEBUG=1"]`)
	req := httptest.NewRequest(http.MethodPost, "/plugins/acme/set", bytes.NewReader(payload))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow", reason)
	}

	body, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		t.Fatalf("ReadAll() error = %v", readErr)
	}
	if string(body) != string(payload) {
		t.Fatalf("body = %q, want %q", string(body), string(payload))
	}
}

func TestPluginPolicyInspectSetDeniesUnallowlistedSettingPrefix(t *testing.T) {
	policy := newPluginPolicy(PluginOptions{
		AllowedSetEnvPrefixes: []string{"DEBUG="},
	})

	req := httptest.NewRequest(http.MethodPost, "/plugins/acme/set", bytes.NewBufferString(`["HTTP_PROXY=http://proxy.internal:3128"]`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != `plugin set denied: setting "HTTP_PROXY=http://proxy.internal:3128" is not allowlisted` {
		t.Fatalf("reason = %q", reason)
	}
}

func TestPluginPolicyInspectSetDeniesNonAssignmentSetting(t *testing.T) {
	policy := newPluginPolicy(PluginOptions{
		AllowedSetEnvPrefixes: []string{"DEBUG="},
	})

	req := httptest.NewRequest(http.MethodPost, "/plugins/acme/set", bytes.NewBufferString(`["not-an-assignment"]`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != `plugin set denied: setting "not-an-assignment" is not an allowed assignment` {
		t.Fatalf("reason = %q", reason)
	}
}

func TestPluginPolicyInspectCreateDeniesHostNetwork(t *testing.T) {
	policy := newPluginPolicy(PluginOptions{
		AllowedBindMounts:   []string{"/allowed"},
		AllowedDevices:      []string{"/dev/allowed"},
		AllowedCapabilities: []string{"NET_ADMIN"},
	})

	payload := mustPluginCreateContextTar(t, pluginCreateConfig{
		Network: struct {
			Type string `json:"Type"`
		}{Type: "host"},
		PropagatedMount: "/allowed",
		Mounts: []struct {
			Source string `json:"Source"`
		}{{Source: "/allowed"}},
		Linux: struct {
			Capabilities    []string `json:"Capabilities"`
			AllowAllDevices bool     `json:"AllowAllDevices"`
			Devices         []struct {
				Path string `json:"Path"`
			} `json:"Devices"`
		}{
			Capabilities: []string{"NET_ADMIN"},
			Devices: []struct {
				Path string `json:"Path"`
			}{{Path: "/dev/allowed"}},
		},
	}, false)

	req := httptest.NewRequest(http.MethodPost, "/plugins/create?name=acme/plugin", bytes.NewReader(payload))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "plugin create denied: host network is not allowed" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestPluginPolicyInspectCreateDeniesDangerousFields(t *testing.T) {
	policy := newPluginPolicy(PluginOptions{
		AllowedBindMounts:   []string{"/allowed"},
		AllowedDevices:      []string{"/dev/allowed"},
		AllowedCapabilities: []string{"NET_ADMIN"},
	})

	tests := []struct {
		name   string
		config string
		want   string
	}{
		{
			name:   "host ipc",
			config: `{"IpcHost":true}`,
			want:   "plugin create denied: host IPC namespace is not allowed",
		},
		{
			name:   "host pid",
			config: `{"PidHost":true}`,
			want:   "plugin create denied: host PID namespace is not allowed",
		},
		{
			name:   "bind mount",
			config: `{"Mounts":[{"Source":"/denied"}]}`,
			want:   `plugin create denied: bind mount source "/denied" is not allowlisted`,
		},
		{
			name:   "propagated mount",
			config: `{"PropagatedMount":"/denied"}`,
			want:   `plugin create denied: bind mount source "/denied" is not allowlisted`,
		},
		{
			name:   "allow all devices",
			config: `{"Linux":{"AllowAllDevices":true}}`,
			want:   "plugin create denied: allow-all-devices is not allowed",
		},
		{
			name:   "device path",
			config: `{"Linux":{"Devices":[{"Path":"/dev/denied"}]}}`,
			want:   `plugin create denied: device path "/dev/denied" is not allowlisted`,
		},
		{
			name:   "capability",
			config: `{"Linux":{"Capabilities":["SYS_ADMIN"]}}`,
			want:   `plugin create denied: capability "SYS_ADMIN" is not allowlisted`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := mustPluginCreateContextPayload(t, tt.config, false)
			req := httptest.NewRequest(http.MethodPost, "/plugins/create?name=acme/plugin", bytes.NewReader(payload))

			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.want {
				t.Fatalf("reason = %q, want %q", reason, tt.want)
			}
		})
	}
}

func TestPluginPolicyInspectCreateAllowsAndPreservesBody(t *testing.T) {
	policy := newPluginPolicy(PluginOptions{
		AllowHostNetwork:     false,
		AllowIPCHost:         false,
		AllowPIDHost:         false,
		AllowedBindMounts:    []string{"/allowed"},
		AllowedDevices:       []string{"/dev/allowed"},
		AllowAllCapabilities: false,
		AllowedCapabilities:  []string{"NET_ADMIN"},
	})

	payload := mustPluginCreateContextTar(t, pluginCreateConfig{
		PropagatedMount: "/allowed",
		Mounts: []struct {
			Source string `json:"Source"`
		}{{Source: "/allowed"}},
		Linux: struct {
			Capabilities    []string `json:"Capabilities"`
			AllowAllDevices bool     `json:"AllowAllDevices"`
			Devices         []struct {
				Path string `json:"Path"`
			} `json:"Devices"`
		}{
			Capabilities: []string{"NET_ADMIN"},
			Devices: []struct {
				Path string `json:"Path"`
			}{{Path: "/dev/allowed"}},
		},
	}, true)

	req := httptest.NewRequest(http.MethodPost, "/v1.54/plugins/create?name=acme/plugin", bytes.NewReader(payload))
	t.Cleanup(func() { _ = req.Body.Close() })
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow", reason)
	}

	body, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		t.Fatalf("ReadAll() error = %v", readErr)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("body mismatch after inspect")
	}
}

func TestPluginPolicyInspectCreateDefersMalformedConfigJSON(t *testing.T) {
	policy := newPluginPolicy(PluginOptions{})
	payload := mustPluginCreateContextTarBytes(t, []pluginTarEntry{
		{name: "config.json", body: []byte("{")},
		{name: "rootfs/", typ: tar.TypeDir},
	}, false)

	req := httptest.NewRequest(http.MethodPost, "/plugins/create?name=acme/plugin", bytes.NewReader(payload))
	t.Cleanup(func() { _ = req.Body.Close() })
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow", reason)
	}
}

func TestParsePluginSetting(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		wantKind pluginSettingType
		want     string
		wantOK   bool
	}{
		{name: "mount source", key: "mymount.source", value: "/safe/../safe", wantKind: pluginSettingMount, want: "/safe", wantOK: true},
		{name: "device path", key: "mydevice.path", value: "/dev/null", wantKind: pluginSettingDevice, want: "/dev/null", wantOK: true},
		{name: "uppercase env ignored", key: "DEBUG", value: "1", wantKind: pluginSettingUnknown, wantOK: false},
		{name: "device shorthand", key: "foo", value: "/dev/ttyS0", wantKind: pluginSettingDevice, want: "/dev/ttyS0", wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, got, ok := parsePluginSetting(tt.key, tt.value)
			if kind != tt.wantKind {
				t.Fatalf("kind = %v, want %v", kind, tt.wantKind)
			}
			if got != tt.want {
				t.Fatalf("value = %q, want %q", got, tt.want)
			}
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

type pluginTarEntry struct {
	name string
	body []byte
	typ  byte
	mode int64
}

func mustPluginCreateContextTar(t *testing.T, cfg pluginCreateConfig, gzipEncoded bool) []byte {
	t.Helper()
	configBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return mustPluginCreateContextTarBytes(t, []pluginTarEntry{
		{name: "rootfs/", typ: tar.TypeDir, mode: 0o755},
		{name: "config.json", body: configBytes, typ: tar.TypeReg, mode: 0o644},
	}, gzipEncoded)
}

func mustPluginCreateContextPayload(t *testing.T, configJSON string, gzipEncoded bool) []byte {
	t.Helper()
	return mustPluginCreateContextTarBytes(t, []pluginTarEntry{
		{name: "rootfs/", typ: tar.TypeDir, mode: 0o755},
		{name: "config.json", body: []byte(configJSON), typ: tar.TypeReg, mode: 0o644},
	}, gzipEncoded)
}

func mustPluginCreateContextTarBytes(t *testing.T, entries []pluginTarEntry, gzipEncoded bool) []byte {
	t.Helper()

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, entry := range entries {
		hdr := &tar.Header{
			Name:     entry.name,
			Mode:     0o644,
			Size:     int64(len(entry.body)),
			Typeflag: tar.TypeReg,
		}
		if entry.typ != 0 {
			hdr.Typeflag = entry.typ
		}
		if entry.mode != 0 {
			hdr.Mode = entry.mode
		}
		if hdr.Typeflag == tar.TypeDir {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%q): %v", entry.name, err)
		}
		if len(entry.body) > 0 {
			if _, err := tw.Write(entry.body); err != nil {
				t.Fatalf("Write(%q): %v", entry.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}

	if !gzipEncoded {
		return tarBuf.Bytes()
	}

	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	if _, err := gzw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return gzBuf.Bytes()
}

func slicesEqual[T comparable](got, want []T) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
