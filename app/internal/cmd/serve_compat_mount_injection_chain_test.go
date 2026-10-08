package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// compatMount is one HostConfig.Mounts entry as the Docker-compatible create
// decodes it, narrowed to the fields a Podman upstream writes into its
// "--mount" string.
type compatMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Target      string `json:"Target"`
	ReadOnly    bool   `json:"ReadOnly"`
	Consistency string `json:"Consistency"`
	BindOptions *struct {
		Propagation string `json:"Propagation"`
	} `json:"BindOptions"`
	VolumeOptions *struct {
		Subpath string `json:"Subpath"`
	} `json:"VolumeOptions"`
}

// compatMountRecord reproduces how Podman 6.1.3's compat handler turns one
// HostConfig.Mounts entry into a host mount. The handler builds a comma-joined
// "--mount" string with addField (compat/containers_create.go:232-266), then
// FindMountType (specgenutilexternal/mount.go) CSV-splits it and
// parseMountOptions (specgenutil/volumes.go) reads the tokens. A comma in
// Type, Source, Target, Consistency, BindOptions.Propagation or
// VolumeOptions.Subpath therefore injects extra fields — a "source=" that
// names a host path, a "U"/"z"/"Z", or a tmpfs "exec"/"suid"/"dev" — which is
// the escape this test pins. The record names the effective host path (a bind
// source made absolute against the daemon's working directory, an empty bind
// source set to the destination) and any escalating option the entry carried.
func compatMountRecord(m compatMount) (string, error) {
	var b strings.Builder
	add := func(name, value string) {
		if value == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(value)
	}
	add("type", m.Type)
	add("source", m.Source)
	add("target", m.Target)
	if m.ReadOnly {
		add("ro", "true")
	}
	add("consistency", m.Consistency)
	switch m.Type {
	case "bind":
		if m.BindOptions != nil {
			add("bind-propagation", m.BindOptions.Propagation)
			add("bind-nonrecursive", "false")
		}
	case "volume":
		if m.VolumeOptions != nil {
			add("subpath", m.VolumeOptions.Subpath)
		}
	}

	records, err := csv.NewReader(strings.NewReader(b.String())).ReadAll()
	if err != nil {
		return "", fmt.Errorf("fill out specgen: %w", err)
	}
	if len(records) != 1 {
		return "", fmt.Errorf("incorrect mount format")
	}

	mountType, found := "", false
	var rest []string
	for _, tok := range records[0] {
		kv := strings.Split(tok, "=")
		if found || len(kv) != 2 || kv[0] != "type" {
			rest = append(rest, tok)
			continue
		}
		mountType, found = kv[1], true
	}
	if !found {
		mountType = "volume"
	}

	var source, dest string
	var opts []string
	for _, tok := range rest {
		name, value, _ := strings.Cut(tok, "=")
		switch name {
		case "src", "source":
			source = value
		case "target", "dst", "dest", "destination":
			dest = value
		case "dev", "suid", "exec", "nodev", "nosuid", "noexec", "ro", "rw", "z", "Z":
			opts = append(opts, name)
		case "U", "chown":
			opts = append(opts, "U")
		}
	}
	slices.Sort(opts)
	suffix := ""
	if len(opts) > 0 {
		suffix = ":" + strings.Join(opts, ",")
	}

	switch mountType {
	case "bind":
		if source == "" {
			source = dest
		}
		if !path.IsAbs(source) {
			source = path.Join(libpodRootfsChainDaemonDir, source)
		}
		return "bind=" + path.Clean(source) + ":" + dest + suffix, nil
	case "tmpfs":
		return "tmpfs=" + dest + suffix, nil
	case "volume":
		// The compat handler calls os.MkdirAll on a volume Source before it
		// parses the entry, so an absolute one creates a host directory.
		mkdir := ""
		if path.IsAbs(source) {
			mkdir = "mkdir=" + path.Clean(source) + " "
		}
		return mkdir + "volume=" + source + ":" + dest + suffix, nil
	default:
		return "", fmt.Errorf("invalid filesystem type %q", mountType)
	}
}

// TestServeChainCompatMountFieldsNeedTheAllowlist sends Docker-compatible
// creates through the production chain to the daemon model that records the
// host paths a Podman upstream would hand the container, and pins the three
// S85 classes:
//
//   - A Binds or Volumes source that starts with "." is a relative host path
//     Podman resolves against the daemon's working directory, not a named
//     volume; it used to be skipped and is now refused.
//   - A HostConfig.Mounts bind with an empty or relative Source binds a host
//     path (Podman sets an empty source to the destination); it used to be
//     skipped and is now refused.
//   - A comma in a Mounts field Podman writes into its "--mount" string
//     (Type, Source, Target, Consistency, BindOptions.Propagation,
//     VolumeOptions.Subpath) injects mount fields past every gate; it is now
//     refused.
//
// Each case was confirmed against a live Podman 6.1.3 before the fix:
// {"Binds":["../../../../etc:/h"]} and {"Volumes":{"../../../../etc:/h":{}}}
// bound host /etc, {"Mounts":[{"Type":"bind","Target":"/etc"}]} bound host
// /etc, {"Mounts":[{"Type":"bind","Target":"/h,source=/etc"}]} bound host
// /etc, and {"Mounts":[{"Type":"tmpfs","Target":"/scratch,exec,suid,dev"}]}
// made an exec/suid/dev tmpfs. dockerd rejects every one of them.
func TestServeChainCompatMountFieldsNeedTheAllowlist(t *testing.T) {
	const compatCreate = "/v1.41/containers/create"
	type request struct{ path, body string }
	mounts := func(entries string) request {
		return request{compatCreate, `{"Image":"alpine","HostConfig":{"Mounts":[` + entries + `]}}`}
	}
	binds := func(entries string) request {
		return request{compatCreate, `{"Image":"alpine","HostConfig":{"Binds":[` + entries + `]}}`}
	}
	volumes := func(keys string) request {
		return request{compatCreate, `{"Image":"alpine","Volumes":{` + keys + `}}`}
	}
	created := func(where ...string) []string {
		out := make([]string, 0, len(where))
		for _, w := range where {
			out = append(out, "container: "+w)
		}
		return out
	}
	type gates = config.RequestBodyConfig
	allowSrv := func(body *gates) { body.ContainerCreate.AllowedBindMounts = []string{"/srv/roots"} }
	const (
		denied   = "container create denied: "
		injected = " contains a comma a Podman upstream reads as a mount field separator"
	)

	tests := []struct {
		name        string
		configure   func(*gates)
		send        request
		wantStatus  int
		wantReason  string
		wantCreated []string
	}{
		// Controls that must keep reaching the daemon.
		{
			name:        "compat bind mount from an allowlisted source reaches the daemon",
			configure:   allowSrv,
			send:        mounts(`{"Type":"bind","Source":"/srv/roots/d","Target":"/d"}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("bind=/srv/roots/d:/d"),
		},
		{
			name:        "compat tmpfs mount with no injected options reaches the daemon",
			send:        mounts(`{"Type":"tmpfs","Target":"/scratch"}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("tmpfs=/scratch"),
		},
		{
			name:        "compat named volume reaches the daemon",
			send:        mounts(`{"Type":"volume","Source":"myvol","Target":"/d"}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("volume=myvol:/d"),
		},

		// S85 (b): a Mounts bind whose source is empty or relative.
		{
			name:       "compat bind mount with no source binds the destination and is refused",
			send:       mounts(`{"Type":"bind","Target":"/etc"}`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `bind mount source "" is not an absolute path`,
		},
		{
			name:       "compat bind mount with a relative source is refused",
			send:       mounts(`{"Type":"bind","Source":"../../../../etc","Target":"/h"}`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `bind mount source "../../../../etc" is not an absolute path`,
		},
		{
			name:       "compat bind mount with a relative source is refused with an allowlist",
			configure:  allowSrv,
			send:       mounts(`{"Type":"bind","Source":"etc","Target":"/h"}`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `bind mount source "etc" is not an absolute path`,
		},

		// S85 (a): a Binds or Volumes source starting with ".".
		{
			name:       "compat Binds entry with a dot-dot source is refused",
			send:       binds(`"../../../../etc:/h"`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `bind mount source "../../../../etc" is not an absolute path`,
		},
		{
			name:       "compat Binds entry with a dot source is refused",
			send:       binds(`".:/h"`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `bind mount source "." is not an absolute path`,
		},
		{
			name:       "compat Volumes key with a dot-dot source is refused",
			send:       volumes(`"../../../../etc:/h":{}`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `bind mount source "../../../../etc" is not an absolute path`,
		},
		{
			name:        "compat Binds named volume still reaches the daemon",
			send:        binds(`"myvol:/d"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("volume=myvol:/d"),
		},

		// Windows-hosted Podman machine: a drive-letter or backslash source is
		// re-joined into a host path.
		{
			name:       "compat Binds drive root is refused",
			send:       binds(`"c:/:/h"`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `bind mount source "c" is a Windows drive letter path`,
		},
		{
			name:       "compat Binds drive traversal is refused",
			send:       binds(`"c:/../../etc:/h"`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `bind mount source "c" is a Windows drive letter path`,
		},
		{
			name:       "compat Binds UNC style source is refused",
			send:       binds(`"\\\\.\\..\\..\\etc:/h"`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `bind mount source "\\\\.\\..\\..\\etc" is a backslash path`,
		},
		{
			name:       "compat Volumes key with a drive traversal is refused",
			send:       volumes(`"c:/../../etc:/h":{}`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `bind mount source "c" is a Windows drive letter path`,
		},
		{
			name:        "compat Binds one-letter named volume reaches the daemon",
			send:        binds(`"c:/h"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("volume=c:/h"),
		},
		{
			name:        "compat Binds one-letter named volume with an option reaches the daemon",
			send:        binds(`"c:/h:ro"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("volume=c:/h"),
		},

		// A volume-type Source that is an absolute path makes Podman create a
		// host directory.
		{
			name:       "compat Mounts volume with an absolute source is refused",
			send:       mounts(`{"Type":"volume","Source":"/etc/x","Target":"/h"}`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `volume mount source "/etc/x" is an absolute path`,
		},

		// S85 (c): a comma in a Mounts field Podman writes into its "--mount"
		// string injects additional mount fields.
		{
			name:       "compat Mounts comma in Target injects a source",
			send:       mounts(`{"Type":"bind","Target":"/h,source=/etc"}`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `mount target "/h,source=/etc"` + injected,
		},
		{
			name:       "compat Mounts comma in an allowlisted bind Source injects an option",
			configure:  allowSrv,
			send:       mounts(`{"Type":"bind","Source":"/srv/roots/d,U","Target":"/h"}`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `mount source "/srv/roots/d,U"` + injected,
		},
		{
			name:       "compat Mounts comma in Consistency injects a source",
			send:       mounts(`{"Type":"bind","Target":"/h","Consistency":"x,source=/etc"}`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `mount consistency "x,source=/etc"` + injected,
		},
		{
			name:       "compat Mounts comma in BindOptions.Propagation injects a source",
			send:       mounts(`{"Type":"bind","Target":"/h","BindOptions":{"Propagation":"rprivate,source=/etc"}}`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `mount bind propagation "rprivate,source=/etc"` + injected,
		},
		{
			name:       "compat Mounts tmpfs comma in Target injects privileged options",
			send:       mounts(`{"Type":"tmpfs","Target":"/scratch,exec,suid,dev"}`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `mount target "/scratch,exec,suid,dev"` + injected,
		},
		{
			name:       "compat Mounts comma in VolumeOptions.Subpath injects an option",
			send:       mounts(`{"Type":"volume","Source":"myvol","Target":"/h","VolumeOptions":{"Subpath":"x,U"}}`),
			wantStatus: http.StatusForbidden,
			wantReason: denied + `mount subpath "x,U"` + injected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newLibpodRootfsChainDaemon()
			addr := newEngineChain(t, "compatmount", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				if tt.configure != nil {
					tt.configure(&cfg.RequestBody)
				}
			})

			status, body := sendNamespaceChainRequest(t, "http://"+addr+tt.send.path, tt.send.body)
			if got := daemon.seen(); !slices.Equal(got, tt.wantCreated) {
				t.Errorf("daemon created %q, want %q", got, tt.wantCreated)
			}
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
			if tt.wantReason != "" {
				var denial struct {
					Reason string `json:"reason"`
				}
				if err := json.Unmarshal(body, &denial); err != nil || denial.Reason != tt.wantReason {
					t.Errorf("body = %s, want reason %q", body, tt.wantReason)
				}
			}
		})
	}
}
