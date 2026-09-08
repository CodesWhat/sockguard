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
