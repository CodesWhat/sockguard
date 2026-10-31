package filter

import "testing"

func TestNativeMountTypesCannotBypassHostPathPolicy(t *testing.T) {
	for _, path := range []string{"/libpod/containers/create", "/v5.0.0/libpod/containers/create"} {
		for _, tc := range []struct {
			name, mount string
			denied      bool
		}{
			{"none recursive bind", `{"type":"none","source":"/etc","destination":"/h","options":["rbind"]}`, true},
			{"virtual type bind", `{"type":"tmpfs","source":"/etc","destination":"/h","options":["bind"]}`, true},
			{"raw overlay", `{"type":"overlay","source":"overlay","destination":"/h","options":["lowerdir=/etc"]}`, true},
			{"device filesystem", `{"type":"ext4","source":"/dev/sda","destination":"/h"}`, true},
			{"unknown filesystem", `{"type":"newfs","source":"/etc","destination":"/h"}`, true},
			{"allowlisted bind", `{"type":"none","source":"/srv/data","destination":"/h","options":["rbind"]}`, false},
			{"virtual tmpfs", `{"type":"tmpfs","source":"tmpfs","destination":"/h"}`, false},
			{"virtual proc", `{"type":"proc","source":"proc","destination":"/p"}`, false},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				cfg := PolicyConfig{LibpodContainerCreate: LibpodContainerCreateOptions{AllowedBindMounts: []string{"/srv/data"}}}
				assertFilterCreateRoundTrip(t, path, `{"systemd":"false","mounts":[`+tc.mount+`]}`, cfg, tc.denied)
			})
		}
	}
}

func TestMountSourceMutationDeniedByDefault(t *testing.T) {
	for _, body := range []string{
		`{"HostConfig":{"Binds":["/srv/data:/d:U"]}}`,
		`{"HostConfig":{"Binds":["/srv/data:/d:ro,z"]}}`,
		`{"HostConfig":{"Binds":["volume:/d:Z"]}}`,
		`{"Volumes":{"/srv/data:/d:U":{}}}`,
	} {
		assertFilterCreateRoundTrip(t, "/v1.47/containers/create", body, PolicyConfig{ContainerCreate: ContainerCreateOptions{AllowedBindMounts: []string{"/srv/data"}}}, true)
	}
	for _, fields := range []string{
		`"mounts":[{"type":"bind","source":"/srv/data","destination":"/d","options":["U"]}]`,
		`"mounts":[{"type":"none","source":"/srv/data","destination":"/d","options":["rbind","z"]}]`,
		`"mounts":[{"type":"tmpfs","source":"/srv/data","destination":"/d","options":["Z"]}]`,
		`"overlay_volumes":[{"source":"/srv/data","destination":"/d","options":["U"]}]`,
		`"volumes":[{"Name":"data","Dest":"/d","Options":["U"]}]`,
	} {
		assertFilterCreateRoundTrip(t, "/v5.0.0/libpod/containers/create", `{"systemd":"false",`+fields+`}`, PolicyConfig{LibpodContainerCreate: LibpodContainerCreateOptions{AllowedBindMounts: []string{"/srv/data"}}}, true)
	}
	assertFilterCreateRoundTrip(t, "/libpod/containers/create", `{"systemd":"false","mounts":[{"type":"tmpfs","source":"tmpfs","destination":"/d","options":["U"]}]}`, PolicyConfig{}, false)
}
