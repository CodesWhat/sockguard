package filter

import (
	"encoding/json"
	"testing"
)

func TestMiddlewareContainerCreateLegacyTmpfs(t *testing.T) {
	for _, tt := range []struct {
		options string
		denied  bool
	}{
		{"exec", true}, {"dev", true}, {"suid", true}, {"rw,size=64m,exec", true},
		{"noexec,exec", true}, {"exec,noexec", false},
		{"nodev,dev", true}, {"dev,nodev", false},
		{"nosuid,suid", true}, {"suid,nosuid", false},
		{"", false}, {"defaults", false},
		{"rw,noexec,nodev,nosuid,size=64m,mode=1770,uid=1000,gid=1000", false},
		{"mpol=bind:0", false}, {"custom=exec", false}, {"mpol=exec:dev", false},
		{"EXEC, dev,exec;suid", false},
	} {
		for _, allow := range []bool{false, true} {
			name := tt.options
			if allow {
				name += "/opt-in"
			}
			t.Run(name, func(t *testing.T) {
				value, err := json.Marshal(tt.options)
				if err != nil {
					t.Fatal(err)
				}
				body := `{"HostConfig":{"Tmpfs":{"/Run":"noexec","/run":` + string(value) + `}}}`
				assertFilterCreateRoundTrip(t, "/v1.46/containers/create", body, PolicyConfig{ContainerCreate: ContainerCreateOptions{AllowTmpfsPrivilegedOptions: allow}}, tt.denied && !allow)
			})
		}
	}
	for _, tt := range []struct {
		name, body string
		denied     bool
	}{
		{"absent", `{"HostConfig":{}}`, false},
		{"null", `{"HostConfig":{"Tmpfs":null}}`, false},
		{"empty", `{"HostConfig":{"Tmpfs":{}}}`, false},
		{"bad map", `{"HostConfig":{"Tmpfs":true}}`, true},
		{"bad value", `{"HostConfig":{"Tmpfs":{"/scratch":[]}}}`, true},
		{"structured", `{"HostConfig":{"Mounts":[{"Type":"tmpfs","TmpfsOptions":{"Options":[["exec"]]}}]}}`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertFilterCreateRoundTrip(t, "/v1.46/containers/create", tt.body, PolicyConfig{}, tt.denied)
		})
	}
}

// Podman's compat create splits each Tmpfs entry at the first ":" of the map
// key, so options can ride in the key as well as the value.
func TestMiddlewareContainerCreateLegacyTmpfsKeyOptions(t *testing.T) {
	for _, tt := range []struct {
		key, value string
		denied     bool
	}{
		{"/scratch:exec", "", true},
		{"/scratch:dev", "", true},
		{"/scratch:suid", "", true},
		{"/scratch:rw,size=64m,exec", "", true},
		{"/scratch:noexec,exec", "", true},
		{"/scratch:exec,noexec", "", false},
		{"/scratch:nodev,dev", "", true},
		{"/scratch:dev,nodev", "", false},
		{"/scratch:nosuid,suid", "", true},
		{"/scratch:suid,nosuid", "", false},
		{"/scratch:exec", "noexec", true},
		{"/scratch:noexec", "exec", true},
		{"/scratch:rw", "exec", true},
		{"/scratch:rw", "size=64m", false},
		{"/scratch:", "", false},
		{"/scratch:", "exec", true},
		{"/scratch", "", false},
		{"/scratch", "noexec", false},
		{"/scratch:defaults", "", false},
		{"/scratch:rw,noexec,nodev,nosuid,size=64m,mode=1770", "", false},
		{"/scratch:mpol=bind:0", "", false},
		{"/scratch:custom=exec", "", false},
		{"/scratch:EXEC, dev,exec;suid", "", false},
	} {
		for _, allow := range []bool{false, true} {
			name := tt.key + "|" + tt.value
			if allow {
				name += "/opt-in"
			}
			t.Run(name, func(t *testing.T) {
				key, err := json.Marshal(tt.key)
				if err != nil {
					t.Fatal(err)
				}
				value, err := json.Marshal(tt.value)
				if err != nil {
					t.Fatal(err)
				}
				body := `{"HostConfig":{"Tmpfs":{` + string(key) + `:` + string(value) + `}}}`
				assertFilterCreateRoundTrip(t, "/v1.46/containers/create", body, PolicyConfig{ContainerCreate: ContainerCreateOptions{AllowTmpfsPrivilegedOptions: allow}}, tt.denied && !allow)
			})
		}
	}

	t.Run("exact reported body", func(t *testing.T) {
		body := `{"HostConfig":{"Tmpfs":{"/scratch:exec":""}}}`
		assertFilterCreateRoundTrip(t, "/v1.46/containers/create", body, PolicyConfig{}, true)
		assertFilterCreateRoundTrip(t, "/v1.46/containers/create", body, PolicyConfig{ContainerCreate: ContainerCreateOptions{AllowTmpfsPrivilegedOptions: true}}, false)
	})
}
