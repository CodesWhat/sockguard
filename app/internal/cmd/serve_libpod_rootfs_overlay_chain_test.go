package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/config"
)

// libpodRootfsChainDaemon is the host-filesystem part of a Podman 5.8.6
// SpecGenerator, behind POST /vX/libpod/containers/create, recording the
// host paths each create it accepted would hand the container.
//
// POST /vX/libpod/containers/create decodes a SpecGenerator with
// encoding/json (pkg/api/handlers/libpod/containers_create.go:65), so a key
// matches its field in any letter case. generate.MakeContainer then uses each
// field:
//
//   - rootfs (ContainerStorageConfig.Rootfs, specgen.go:263) becomes the
//     container's root filesystem, mounted straight off the daemon host with
//     no modification (libpod.WithRootFS at container_create.go:159 and 616,
//     mounted at container_internal.go:1750). rootfs_overlay and
//     rootfs_mapping only change how that one path is mounted.
//   - overlay_volumes[].source (OverlayVolume.Source, volumes.go:40) is a host
//     path overlay-mounted at the entry's destination
//     (libpod.WithOverlayVolumes at container_create.go:494, mounted at
//     container_internal_common.go:481).
//   - init_path (ContainerStorageConfig.InitPath, specgen.go:291), when the
//     create also sets init, is a host binary bind-mounted read-only at
//     /run/podman-init and run as the container's PID 1
//     (storage.go:134 and 387-392).
//   - conmon_pid_file (ContainerBasicConfig.ConmonPidFile, specgen.go:105) is a
//     host path conmon writes its PID to, as the daemon's user, unless it sits
//     under the storage run root (libpod.WithConmonPidFile at
//     container_create.go:602, used at oci_conmon_common.go:1045; cleared only
//     under RunRoot at runtime_ctr.go:104).
//
// None of the four is a namespace, a mount[] entry or a device[] entry, so
// before this change not one reached a sockguard gate: the native inspector
// never modeled the fields, so allowed_bind_mounts, allow_all_devices and the
// rest never saw them. rootfs and overlay_volumes sidestepped
// allowed_bind_mounts outright, which is the claim this test pins.
type libpodRootfsChainDaemon struct {
	mu      sync.Mutex
	created []string
}

func newLibpodRootfsChainDaemon() *libpodRootfsChainDaemon {
	return &libpodRootfsChainDaemon{}
}

func (d *libpodRootfsChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	versioned := normPath != r.URL.Path
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
		return
	case r.Method == http.MethodPost && normPath == "/libpod/containers/create" && versioned:
		if err := d.createLibpodContainer(r.Body); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"cause": err.Error(), "message": err.Error()})
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "c1"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *libpodRootfsChainDaemon) createLibpodContainer(body io.Reader) error {
	var spec struct {
		Rootfs         string `json:"rootfs"`
		OverlayVolumes []struct {
			Source      string `json:"source"`
			Destination string `json:"destination"`
		} `json:"overlay_volumes"`
		InitPath      string `json:"init_path"`
		ConmonPidFile string `json:"conmon_pid_file"`
	}
	if err := json.NewDecoder(body).Decode(&spec); err != nil {
		return fmt.Errorf("decode(): %w", err)
	}
	var parts []string
	if spec.Rootfs != "" {
		parts = append(parts, "rootfs="+spec.Rootfs)
	}
	for _, v := range spec.OverlayVolumes {
		parts = append(parts, "overlay="+v.Source+":"+v.Destination)
	}
	if spec.InitPath != "" {
		parts = append(parts, "init_path="+spec.InitPath)
	}
	if spec.ConmonPidFile != "" {
		parts = append(parts, "conmon_pid_file="+spec.ConmonPidFile)
	}
	where := "no host paths"
	if len(parts) > 0 {
		where = strings.Join(parts, " ")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.created = append(d.created, "container: "+where)
	return nil
}

func (d *libpodRootfsChainDaemon) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.created)
}

// TestServeChainLibpodRootfsAndOverlayNeedTheBindMountAllowlist sends native
// Podman container creates through the production chain to a daemon that
// records the host paths each create would hand the container, and asserts
// that rootfs, overlay_volumes sources and init_path are held to
// allowed_bind_mounts and conmon_pid_file is refused outright.
//
// Before the gate, a create with default libpod_container_create options and
// {"rootfs":"/"} reached the daemon and ran a container whose root filesystem
// was the host's /, and {"overlay_volumes":[{"source":"/"}]} mounted the
// host's / inside it, both past allowed_bind_mounts. Each host-path field now
// needs an allowed_bind_mounts entry that covers it, the way mounts[] bind
// sources already do, and conmon_pid_file is refused whenever it's set.
func TestServeChainLibpodRootfsAndOverlayNeedTheBindMountAllowlist(t *testing.T) {
	const libpodCreate = "/v5.8.6/libpod/containers/create"
	type request struct{ body string }
	// Every body carries systemd:"false" so the systemd gate, which denies by
	// default, doesn't answer first (see basic_create.json).
	libpod := func(fields string) request {
		return request{`{"systemd":"false",` + fields + `}`}
	}
	created := func(where ...string) []string {
		out := make([]string, 0, len(where))
		for _, w := range where {
			out = append(out, "container: "+w)
		}
		return out
	}
	type gates = config.RequestBodyConfig
	allowRoot := func(body *gates) { body.LibpodContainerCreate.AllowedBindMounts = []string{"/"} }
	allowSrv := func(body *gates) { body.LibpodContainerCreate.AllowedBindMounts = []string{"/srv/roots"} }

	tests := []struct {
		name        string
		configure   func(*gates)
		send        request
		wantStatus  int
		wantReason  string
		wantCreated []string
	}{
		// Baseline: an image-based create with no host-path field reaches the
		// daemon with every default option, and must keep doing so.
		{
			name:        "libpod image create reaches the daemon",
			send:        libpod(`"image":"alpine"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("no host paths"),
		},

		// rootfs, every default option.
		{
			name:       "libpod rootfs / is refused by default",
			send:       libpod(`"rootfs":"/"`),
			wantStatus: http.StatusForbidden,
			wantReason: `libpod container create denied: rootfs path "/" is not allowlisted (add it to allowed_bind_mounts)`,
		},
		{
			name:        "libpod rootfs / with / allowlisted reaches the daemon",
			configure:   allowRoot,
			send:        libpod(`"rootfs":"/"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("rootfs=/"),
		},
		{
			name:        "libpod rootfs under an allowlisted prefix reaches the daemon",
			configure:   allowSrv,
			send:        libpod(`"rootfs":"/srv/roots/app"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("rootfs=/srv/roots/app"),
		},
		{
			name:       "libpod rootfs outside the allowlisted prefix is refused",
			configure:  allowSrv,
			send:       libpod(`"rootfs":"/etc"`),
			wantStatus: http.StatusForbidden,
			wantReason: `libpod container create denied: rootfs path "/etc" is not allowlisted (add it to allowed_bind_mounts)`,
		},
		{
			// encoding/json matches the key in any case, so the gate must read
			// it the same way the daemon decodes it.
			name:       "libpod rootfs under an upper-case key is refused",
			send:       libpod(`"Rootfs":"/"`),
			wantStatus: http.StatusForbidden,
			wantReason: `libpod container create denied: rootfs path "/" is not allowlisted (add it to allowed_bind_mounts)`,
		},
		{
			// A relative rootfs never normalizes to an allowlisted absolute
			// path, so it's refused whatever the allowlist holds.
			name:       "libpod relative rootfs is refused even with / allowlisted",
			configure:  allowRoot,
			send:       libpod(`"rootfs":"roots/app"`),
			wantStatus: http.StatusForbidden,
			wantReason: `libpod container create denied: rootfs path "roots/app" is not allowlisted (add it to allowed_bind_mounts)`,
		},
		{
			// A wrong-shaped rootfs fails the decode, so the create is refused.
			name:       "libpod rootfs as an object is malformed",
			send:       libpod(`"rootfs":{"path":"/"}`),
			wantStatus: http.StatusForbidden,
			wantReason: "libpod container create denied: malformed JSON request body",
		},

		// overlay_volumes, every default option.
		{
			name:       "libpod overlay volume from / is refused by default",
			send:       libpod(`"image":"alpine","overlay_volumes":[{"source":"/","destination":"/host"}]`),
			wantStatus: http.StatusForbidden,
			wantReason: `libpod container create denied: overlay volume source "/" is not allowlisted (add it to allowed_bind_mounts)`,
		},
		{
			name:        "libpod overlay volume from an allowlisted source reaches the daemon",
			configure:   allowSrv,
			send:        libpod(`"image":"alpine","overlay_volumes":[{"source":"/srv/roots/data","destination":"/data"}]`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("overlay=/srv/roots/data:/data"),
		},
		{
			name:       "libpod overlay volume with one source off the allowlist is refused",
			configure:  allowSrv,
			send:       libpod(`"image":"alpine","overlay_volumes":[{"source":"/srv/roots/data","destination":"/data"},{"source":"/etc","destination":"/host-etc"}]`),
			wantStatus: http.StatusForbidden,
			wantReason: `libpod container create denied: overlay volume source "/etc" is not allowlisted (add it to allowed_bind_mounts)`,
		},
		{
			name:       "libpod overlay volume with an empty source is refused",
			configure:  allowRoot,
			send:       libpod(`"image":"alpine","overlay_volumes":[{"destination":"/data"}]`),
			wantStatus: http.StatusForbidden,
			wantReason: `libpod container create denied: overlay volume source "" is not allowlisted (add it to allowed_bind_mounts)`,
		},

		// init_path, held to the same allowlist (it's a host binary the
		// container executes as PID 1).
		{
			name:       "libpod init_path is refused by default",
			send:       libpod(`"image":"alpine","init":true,"init_path":"/usr/libexec/podman/catatonit"`),
			wantStatus: http.StatusForbidden,
			wantReason: `libpod container create denied: init_path "/usr/libexec/podman/catatonit" is not allowlisted (add it to allowed_bind_mounts)`,
		},
		{
			name:        "libpod init_path under an allowlisted prefix reaches the daemon",
			configure:   func(body *gates) { body.LibpodContainerCreate.AllowedBindMounts = []string{"/usr/libexec"} },
			send:        libpod(`"image":"alpine","init":true,"init_path":"/usr/libexec/podman/catatonit"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("init_path=/usr/libexec/podman/catatonit"),
		},

		// conmon_pid_file is a host write path with no bind-mount meaning, so
		// it's refused outright.
		{
			name:       "libpod conmon_pid_file is refused",
			send:       libpod(`"image":"alpine","conmon_pid_file":"/run/malicious/conmon.pid"`),
			wantStatus: http.StatusForbidden,
			wantReason: "libpod container create denied: setting conmon_pid_file is not allowed",
		},
		{
			// The allowlist is for paths the container reads; it doesn't open
			// the host write path.
			name:       "libpod conmon_pid_file is refused even with / allowlisted",
			configure:  allowRoot,
			send:       libpod(`"image":"alpine","conmon_pid_file":"/run/malicious/conmon.pid"`),
			wantStatus: http.StatusForbidden,
			wantReason: "libpod container create denied: setting conmon_pid_file is not allowed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newLibpodRootfsChainDaemon()
			addr := newEngineChain(t, "rootfs", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				if tt.configure != nil {
					tt.configure(&cfg.RequestBody)
				}
			})

			status, body := sendNamespaceChainRequest(t, "http://"+addr+libpodCreate, tt.send.body)
			if got := daemon.seen(); !slices.Equal(got, tt.wantCreated) {
				t.Errorf("daemon created %q, want %q", got, tt.wantCreated)
			}
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
			if tt.wantStatus == http.StatusForbidden && tt.wantReason == "" {
				t.Fatal("a denied case must name the reason it is denied for")
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
