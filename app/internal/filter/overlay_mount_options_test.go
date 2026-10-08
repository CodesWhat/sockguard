package filter

import "testing"

// TestDenyOverlayDirOptionReason pins which mount options are read as an
// overlay upper or work directory, and what each has to be. The matcher is
// Podman's (getOverlayUpperAndWorkDir, libpod/container_internal_common.go:153-180):
// a case-sensitive "upperdir" or "workdir" prefix, with the value taken from
// after the first "=".
func TestDenyOverlayDirOptionReason(t *testing.T) {
	allowed := []string{"/srv/roots"}
	tests := []struct {
		name       string
		option     string
		allowed    []string
		wantReason string
	}{
		{name: "overlay flag alone", option: "O", allowed: allowed},
		{name: "read-only", option: "ro", allowed: allowed},
		{name: "relabel", option: "z", allowed: allowed},
		{name: "chown", option: "U", allowed: allowed},
		{name: "nocopy", option: "nocopy", allowed: allowed},
		{name: "idmap with a value", option: "idmap=uids=0-1-10", allowed: allowed},
		{name: "empty option", option: "", allowed: allowed},
		// Podman's prefix test is case-sensitive and untrimmed, so these are
		// options it never reads as a directory.
		{name: "upper-case key is not Podman's option", option: "UPPERDIR=/etc", allowed: allowed},
		{name: "leading space is not Podman's option", option: " upperdir=/etc", allowed: allowed},
		{name: "prefixed key is not Podman's option", option: "xupperdir=/etc", allowed: allowed},
		{name: "volume-opt carrying the word is not Podman's option", option: "volume-opt=upperdir=/etc", allowed: allowed},

		{name: "upperdir under the allowlist", option: "upperdir=/srv/roots/upper", allowed: allowed},
		{name: "workdir under the allowlist", option: "workdir=/srv/roots/work", allowed: allowed},
		{name: "upperdir that is an allowlist entry", option: "upperdir=/srv/roots", allowed: allowed},
		{name: "upperdir that cleans to an allowlisted path", option: "upperdir=/srv/roots/a/../upper", allowed: allowed},
		{name: "upperdir with / allowlisted", option: "upperdir=/etc", allowed: []string{"/"}},

		{
			name:       "upperdir off the allowlist",
			option:     "upperdir=/etc",
			allowed:    allowed,
			wantReason: `create denied: overlay option "upperdir=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "workdir off the allowlist",
			option:     "workdir=/mnt",
			allowed:    allowed,
			wantReason: `create denied: overlay option "workdir=/mnt" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "upperdir with nothing allowlisted",
			option:     "upperdir=/srv/roots/upper",
			wantReason: `create denied: overlay option "upperdir=/srv/roots/upper" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			// Podman matches the prefix, so a longer key names a directory too.
			name:       "upperdir with a suffixed key",
			option:     "upperdirX=/etc",
			allowed:    allowed,
			wantReason: `create denied: overlay option "upperdirX=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "workdir with a suffixed key",
			option:     "workdir2=/mnt",
			allowed:    allowed,
			wantReason: `create denied: overlay option "workdir2=/mnt" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			// The value is everything after the first "=", so a second one is
			// part of the path.
			name:       "upperdir whose value holds another equals sign",
			option:     "upperdir=/etc=x",
			allowed:    allowed,
			wantReason: `create denied: overlay option "upperdir=/etc=x" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "upperdir that climbs out of the allowlist",
			option:     "upperdir=/srv/roots/../../etc",
			allowed:    allowed,
			wantReason: `create denied: overlay option "upperdir=/srv/roots/../../etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			// buildah joins a relative value under the container's own overlay
			// directory, so "../" walks out of it.
			name:       "relative upperdir",
			option:     "upperdir=../../../../../../etc",
			allowed:    []string{"/"},
			wantReason: `create denied: overlay option "upperdir=../../../../../../etc" does not name an absolute path`,
		},
		{
			name:       "relative workdir",
			option:     "workdir=work",
			allowed:    []string{"/"},
			wantReason: `create denied: overlay option "workdir=work" does not name an absolute path`,
		},
		{
			name:       "empty upperdir",
			option:     "upperdir=",
			allowed:    []string{"/"},
			wantReason: `create denied: overlay option "upperdir=" does not name an absolute path`,
		},
		{
			name:       "upperdir with no value",
			option:     "upperdir",
			allowed:    []string{"/"},
			wantReason: `create denied: overlay option "upperdir" does not name an absolute path`,
		},
		{
			// A comma starts a new overlay option, and a second lowerdir
			// replaces the first.
			name:       "upperdir carrying a comma",
			option:     "upperdir=/srv/roots/upper,lowerdir=/etc",
			allowed:    allowed,
			wantReason: `create denied: overlay option "upperdir=/srv/roots/upper,lowerdir=/etc" contains a comma or backslash`,
		},
		{
			// The kernel strips the backslash, so this resolves to /etc while
			// it cleans to a path under /srv/roots.
			name:       "upperdir carrying a backslash",
			option:     `upperdir=/srv/roots/..\/etc`,
			allowed:    allowed,
			wantReason: `create denied: overlay option "upperdir=/srv/roots/..\\/etc" contains a comma or backslash`,
		},
		{
			name:       "workdir carrying a comma with / allowlisted",
			option:     "workdir=/a,b",
			allowed:    []string{"/"},
			wantReason: `create denied: overlay option "workdir=/a,b" contains a comma or backslash`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := denyOverlayDirOptionReason(tt.option, tt.allowed, "create"); got != tt.wantReason {
				t.Fatalf("denyOverlayDirOptionReason(%q) = %q, want %q", tt.option, got, tt.wantReason)
			}
		})
	}
}

// TestDenyOverlayDirOptionsReasonChecksEveryOption proves a list can't hide a
// directory behind a later one. Podman keeps the last upperdir it reads, but
// every one is checked here.
func TestDenyOverlayDirOptionsReasonChecksEveryOption(t *testing.T) {
	allowed := []string{"/srv/roots"}
	options := []string{"O", "upperdir=/etc", "upperdir=/srv/roots/upper", "workdir=/srv/roots/work"}
	want := `create denied: overlay option "upperdir=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`
	if got := denyOverlayDirOptionsReason(options, allowed, "create"); got != want {
		t.Fatalf("denyOverlayDirOptionsReason() = %q, want %q", got, want)
	}
	if got := denyOverlayDirOptionsReason([]string{"O", "upperdir=/srv/roots/upper", "workdir=/srv/roots/work"}, allowed, "create"); got != "" {
		t.Fatalf("denyOverlayDirOptionsReason() = %q, want every allowlisted directory to pass", got)
	}
	if got := denyOverlayDirOptionsReason(nil, nil, "create"); got != "" {
		t.Fatalf("denyOverlayDirOptionsReason(nil) = %q, want empty", got)
	}
}

// TestContainerCreateBindOverlayOptions sends Docker-compatible creates whose
// HostConfig.Binds entries carry Podman's overlay options. A Podman upstream
// parses each entry as a "-v" argument
// (pkg/api/handlers/compat/containers_create.go:516-517), so its third field
// reaches the same overlay code a native create's options do. dockerd refuses
// these options itself, so nothing here changes what works on Docker.
func TestContainerCreateBindOverlayOptions(t *testing.T) {
	tests := []struct {
		name       string
		allowed    []string
		binds      string
		wantReason string
	}{
		// Ordinary binds and named volumes, with the options Docker and
		// Podman both take, are untouched.
		{name: "named volume with no options", binds: `"myvol:/d"`},
		{name: "named volume read-only", binds: `"myvol:/d:ro"`},
		{name: "named volume with nocopy and relabel", binds: `"myvol:/d:nocopy,z"`},
		{name: "named volume with chown", binds: `"myvol:/d:U"`},
		{name: "anonymous volume", binds: `"/d"`},
		{name: "named volume called workdir", binds: `"workdir:/work"`},
		{name: "named volume called upperdir-data", binds: `"upperdir-data:/d:rw"`},
		{name: "named volume mounted at a path called workdir", binds: `"myvol:/workdir:ro"`},
		{name: "allowlisted host path read-only", allowed: []string{"/srv/data"}, binds: `"/srv/data:/d:ro"`},
		{name: "allowlisted host path with propagation", allowed: []string{"/srv/data"}, binds: `"/srv/data:/d:rshared,Z"`},
		{name: "allowlisted host path whose name holds a comma", allowed: []string{"/srv/data"}, binds: `"/srv/data/a,b:/d:ro"`},

		// A plain overlay, and one whose directories are allowlisted.
		{name: "named volume overlay", binds: `"myvol:/d:O"`},
		{name: "allowlisted host path overlay", allowed: []string{"/srv/data"}, binds: `"/srv/data:/d:O"`},
		{
			name:    "named volume overlay with allowlisted directories",
			allowed: []string{"/srv/roots"},
			binds:   `"myvol:/d:O,upperdir=/srv/roots/upper,workdir=/srv/roots/work"`,
		},
		{
			name:    "host path overlay with allowlisted directories",
			allowed: []string{"/srv"},
			binds:   `"/srv/data:/d:O,upperdir=/srv/roots/upper,workdir=/srv/roots/work"`,
		},

		{
			name:       "named volume overlay with its upper directory in /etc",
			allowed:    []string{"/srv/roots"},
			binds:      `"myvol:/d:O,upperdir=/etc,workdir=/mnt"`,
			wantReason: `container create denied: overlay option "upperdir=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "named volume overlay with nothing allowlisted",
			binds:      `"myvol:/d:O,upperdir=/etc,workdir=/mnt"`,
			wantReason: `container create denied: overlay option "upperdir=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "host path overlay with its upper directory in /etc",
			allowed:    []string{"/srv/data"},
			binds:      `"/srv/data:/d:O,upperdir=/etc,workdir=/mnt"`,
			wantReason: `container create denied: overlay option "upperdir=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "overlay with only its work directory off the allowlist",
			allowed:    []string{"/srv/roots"},
			binds:      `"myvol:/d:O,upperdir=/srv/roots/upper,workdir=/mnt"`,
			wantReason: `container create denied: overlay option "workdir=/mnt" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "overlay directories ahead of the overlay flag",
			allowed:    []string{"/srv/roots"},
			binds:      `"myvol:/d:upperdir=/etc,workdir=/mnt,O"`,
			wantReason: `container create denied: overlay option "upperdir=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "overlay with a suffixed upperdir key",
			allowed:    []string{"/srv/roots"},
			binds:      `"myvol:/d:O,upperdirX=/etc,workdir=/srv/roots/work"`,
			wantReason: `container create denied: overlay option "upperdirX=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "overlay with a relative upper directory",
			allowed:    []string{"/"},
			binds:      `"myvol:/d:O,upperdir=../../../etc,workdir=../../../mnt"`,
			wantReason: `container create denied: overlay option "upperdir=../../../etc" does not name an absolute path`,
		},
		{
			name:       "overlay with a backslash in its upper directory",
			allowed:    []string{"/srv/roots"},
			binds:      `"myvol:/d:O,upperdir=/srv/roots/..\\/etc,workdir=/srv/roots/work"`,
			wantReason: `container create denied: overlay option "upperdir=/srv/roots/..\\/etc" contains a comma or backslash`,
		},
		{
			// An entry with a fourth field is one Podman re-splits when it
			// resolves Windows paths, so every field after the second is read.
			name:       "overlay directories in a fourth field",
			allowed:    []string{"/srv/roots"},
			binds:      `"C:/src:/d:O,upperdir=/etc,workdir=/mnt"`,
			wantReason: `container create denied: overlay option "upperdir=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			// The same entry with the directory first, so the field before it
			// ends in ":" and not ",".
			name:       "overlay directory leading a fourth field",
			allowed:    []string{"/srv/roots"},
			binds:      `"C:/src:/d:upperdir=/etc,O,workdir=/srv/roots/work"`,
			wantReason: `container create denied: overlay option "upperdir=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "second bind carries the overlay directories",
			allowed:    []string{"/srv/data"},
			binds:      `"/srv/data:/d:ro","myvol:/e:O,upperdir=/etc,workdir=/mnt"`,
			wantReason: `container create denied: overlay option "upperdir=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			// The source is the overlay's lowerdir, and the comma starts a
			// second one.
			name:       "host path overlay whose source carries a comma",
			allowed:    []string{"/srv/data"},
			binds:      `"/srv/data/a,lowerdir=/etc:/d:O"`,
			wantReason: `container create denied: overlay bind source "/srv/data/a,lowerdir=/etc" contains a comma or backslash`,
		},
		{
			name:       "host path overlay whose source carries a backslash",
			allowed:    []string{"/srv/data"},
			binds:      `"/srv/data/a\\:/d:O"`,
			wantReason: `container create denied: overlay bind source "/srv/data/a\\" contains a comma or backslash`,
		},
		{
			// The source allowlist still answers first.
			name:       "host path overlay off the allowlist",
			allowed:    []string{"/srv/data"},
			binds:      `"/etc:/d:O,upperdir=/srv/data/upper,workdir=/srv/data/work"`,
			wantReason: `container create denied: bind mount source "/etc" is not allowlisted`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newContainerCreatePolicy(ContainerCreateOptions{AllowedBindMounts: tt.allowed})
			body := `{"Image":"alpine","HostConfig":{"Binds":[` + tt.binds + `]}}`
			reason, err := policy.inspect(nil, makeInspectRequest(t, body), "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestContainerCreateVolumesKeysAreBindSpecs sends Docker-compatible creates
// whose Config.Volumes keys are more than a container path. dockerd creates an
// anonymous volume at whatever the key spells (daemon/create_unix.go:45-73 in
// moby 28.5.1). Podman appends the key to the "-v" list Binds feeds
// (pkg/api/handlers/compat/containers_create.go:536-541), so it's a bind mount
// or an overlay there and gets the checks a Binds entry does.
func TestContainerCreateVolumesKeysAreBindSpecs(t *testing.T) {
	tests := []struct {
		name       string
		allowed    []string
		body       string
		wantReason string
	}{
		// What Docker clients send: container paths, with empty values.
		{name: "no Volumes", body: `{"Image":"a"}`},
		{name: "null Volumes", body: `{"Image":"a","Volumes":null}`},
		{name: "empty Volumes", body: `{"Image":"a","Volumes":{}}`},
		{name: "one anonymous volume", body: `{"Image":"a","Volumes":{"/data":{}}}`},
		{name: "several anonymous volumes", body: `{"Image":"a","Volumes":{"/data":{},"/var/lib/mysql":{},"/etc":{}}}`},
		{name: "anonymous volume with a null value", body: `{"Image":"a","Volumes":{"/data":null}}`},
		{name: "Windows container path", body: `{"Image":"a","Volumes":{"C:\\data":{}}}`},
		{name: "key naming a volume", body: `{"Image":"a","Volumes":{"myvol:/d":{}}}`},
		{name: "key naming a volume read-only", body: `{"Image":"a","Volumes":{"myvol:/d:ro":{}}}`},
		{name: "key binding an allowlisted path", allowed: []string{"/srv/data"}, body: `{"Image":"a","Volumes":{"/srv/data:/d":{}}}`},
		{name: "key overlaying a volume", body: `{"Image":"a","Volumes":{"myvol:/d:O":{}}}`},
		{
			name:    "key overlaying a volume onto allowlisted directories",
			allowed: []string{"/srv/roots"},
			body:    `{"Image":"a","Volumes":{"myvol:/d:O,upperdir=/srv/roots/upper,workdir=/srv/roots/work":{}}}`,
		},

		// Container paths with a mode. The first field is the container path,
		// so none of these is a bind source.
		{name: "container path with z", allowed: []string{"/srv/ok"}, body: `{"Image":"a","Volumes":{"/data:z":{}}}`},
		{name: "container path with ro and z", allowed: []string{"/srv/ok"}, body: `{"Image":"a","Volumes":{"/data:ro,z":{}}}`},
		{name: "container path with nocopy", allowed: []string{"/srv/ok"}, body: `{"Image":"a","Volumes":{"/data:nocopy":{}}}`},
		{name: "container path with ro", allowed: []string{"/srv/ok"}, body: `{"Image":"a","Volumes":{"/data:ro":{}}}`},

		{
			name:       "Windows-drive source overlaying with its upper directory in /etc",
			allowed:    []string{"/srv/ok"},
			body:       `{"Image":"a","Volumes":{"C:\\x:/d:O,upperdir=/etc,workdir=/mnt":{}}}`,
			wantReason: `container create denied: overlay option "upperdir=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "key binding /etc with nothing allowlisted",
			body:       `{"Image":"a","Volumes":{"/etc:/h":{}}}`,
			wantReason: `container create denied: bind mount source "/etc" is not allowlisted`,
		},
		{
			name:       "key binding /etc beside an allowlisted bind",
			allowed:    []string{"/srv/data"},
			body:       `{"Image":"a","HostConfig":{"Binds":["/srv/data:/d"]},"Volumes":{"/data":{},"/etc:/h:ro":{}}}`,
			wantReason: `container create denied: bind mount source "/etc" is not allowlisted`,
		},
		{
			name:       "key that climbs out of the allowlist",
			allowed:    []string{"/srv/data"},
			body:       `{"Image":"a","Volumes":{"/srv/data/../../etc:/h":{}}}`,
			wantReason: `container create denied: bind mount source "/etc" is not allowlisted`,
		},
		{
			name:       "key under a lower-case field name",
			body:       `{"Image":"a","volumes":{"/etc:/h":{}}}`,
			wantReason: `container create denied: bind mount source "/etc" is not allowlisted`,
		},
		{
			name:       "key overlaying a volume with its upper directory in /etc",
			allowed:    []string{"/srv/roots"},
			body:       `{"Image":"a","Volumes":{"myvol:/d:O,upperdir=/etc,workdir=/mnt":{}}}`,
			wantReason: `container create denied: overlay option "upperdir=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "key overlaying a host path whose name carries a comma",
			allowed:    []string{"/srv/data"},
			body:       `{"Image":"a","Volumes":{"/srv/data/a,lowerdir=/etc:/d:O":{}}}`,
			wantReason: `container create denied: overlay bind source "/srv/data/a,lowerdir=/etc" contains a comma or backslash`,
		},
		{
			// The keys are sorted, so the denial names the same one each run.
			name:       "two keys off the allowlist",
			body:       `{"Image":"a","Volumes":{"/var/run:/b":{},"/etc:/a":{}}}`,
			wantReason: `container create denied: bind mount source "/etc" is not allowlisted`,
		},
		{
			// Both engines decode the field as map[string]struct{}, so a
			// value that isn't an object fails there too.
			name:       "Volumes that is not a map",
			body:       `{"Image":"a","Volumes":["/etc:/h"]}`,
			wantReason: "container create denied: malformed JSON request body",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newContainerCreatePolicy(ContainerCreateOptions{AllowedBindMounts: tt.allowed})
			// Repeated so a denial that depended on map order would show up.
			for range 20 {
				reason, err := policy.inspect(nil, makeInspectRequest(t, tt.body), "/containers/create")
				if err != nil {
					t.Fatalf("inspect() error = %v", err)
				}
				if reason != tt.wantReason {
					t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
				}
			}
		})
	}
}
