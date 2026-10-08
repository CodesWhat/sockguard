package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/config"
)

// libpodRootfsChainDaemon is the host-filesystem part of a Podman 5.8.6
// SpecGenerator, behind POST /vX/libpod/containers/create, and of the "-v"
// parsing behind the Docker-compatible POST /containers/create, recording the
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
//     mounted at container_internal.go:1750). rootfs_mapping only changes how
//     that one path is mounted. rootfs_overlay also writes the path into an
//     overlay option string as its lowerdir (container_internal.go:1792).
//   - overlay_volumes[].source (OverlayVolume.Source, volumes.go:40) is a host
//     path overlay-mounted at the entry's destination
//     (libpod.WithOverlayVolumes at container_create.go:494, mounted at
//     container_internal_common.go:481).
//   - overlay_volumes[].options, and volumes[].Options once one of them is
//     "O", name the overlay's upper and work directory. Any option starting
//     with "upperdir" or "workdir" counts and the value is what follows the
//     first "=" (getOverlayUpperAndWorkDir at
//     container_internal_common.go:153-180, called at 467 and 327). buildah
//     1.43.2 uses an absolute value as written and joins a relative one under
//     the container's overlay directory (pkg/overlay/overlay_linux.go:44-52),
//     then builds "lowerdir=<source>,upperdir=<dir>,workdir=<dir>,private"
//     with only ":" escaped (line 67).
//   - mounts[] entries of type "bind" have their source made absolute against
//     the daemon's working directory (filepath.Abs at
//     pkg/specgen/generate/storage.go:203-208). Every other type's source is
//     left as sent.
//   - init_path (ContainerStorageConfig.InitPath, specgen.go:291), when the
//     create also sets init, is a host binary bind-mounted read-only at
//     /run/podman-init and run as the container's PID 1
//     (storage.go:134 and 387-392).
//   - conmon_pid_file (ContainerBasicConfig.ConmonPidFile, specgen.go:105) is a
//     host path conmon writes its PID to, as the daemon's user
//     (libpod.WithConmonPidFile at container_create.go:602, used at
//     oci_conmon_common.go:1045). A create only fills in a default when the
//     field is empty (runtime_ctr.go:486-487), so any path sent is kept.
//
// POST /containers/create hands each HostConfig.Binds entry to the same "-v"
// parser the CLI uses (pkg/api/handlers/compat/containers_create.go:516-517,
// GenVolumeMounts at pkg/specgen/volumes.go:89-231): source, destination and
// options split on ":", the options split on ",", and a source that doesn't
// start with "/" or "." is a named volume. With "O" among the options the
// entry is an overlay and the same upper and work directory options apply.
// Each Config.Volumes key goes into that list as well
// (containers_create.go:536-541), so a key is a whole "-v" argument to Podman
// where dockerd only ever reads it as a container path.
//
// None of these is a namespace or a devices[] entry, and before this change
// only an absolute mounts[] bind source and an absolute Binds source reached a
// sockguard gate. The rest sidestepped allowed_bind_mounts outright, which is
// the claim this test pins.
type libpodRootfsChainDaemon struct {
	mu      sync.Mutex
	created []string
}

// libpodRootfsChainDaemonDir is the working directory the daemon resolves a
// relative bind source against. Packaged Podman units leave it at "/".
const libpodRootfsChainDaemonDir = "/"

func newLibpodRootfsChainDaemon() *libpodRootfsChainDaemon {
	return &libpodRootfsChainDaemon{}
}

func (d *libpodRootfsChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	versioned := normPath != r.URL.Path
	w.Header().Set("Content-Type", "application/json")
	var create func(io.Reader) error
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
		return
	case r.Method == http.MethodPost && normPath == "/libpod/containers/create" && versioned:
		create = d.createLibpodContainer
	case r.Method == http.MethodPost && normPath == "/containers/create":
		create = d.createCompatContainer
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err := create(r.Body); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"cause": err.Error(), "message": err.Error()})
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"Id": "c1"})
}

// libpodChainOverlayDirs is getOverlayUpperAndWorkDir
// (container_internal_common.go:153-180) followed by the way buildah places
// what it returns (pkg/overlay/overlay_linux.go:44-52). It reports the upper
// and work directory an option list puts on the host, as " upper=<dir>
// work=<dir>", or "" when the overlay keeps both in the container's own
// directory.
func libpodChainOverlayDirs(options []string) (string, error) {
	upper, work := "", ""
	for _, o := range options {
		if strings.HasPrefix(o, "upperdir") {
			if _, value, ok := strings.Cut(o, "="); ok {
				if value == "" {
					return "", fmt.Errorf("cannot accept empty value for upperdir")
				}
				upper = value
			}
		}
		if strings.HasPrefix(o, "workdir") {
			if _, value, ok := strings.Cut(o, "="); ok {
				if value == "" {
					return "", fmt.Errorf("cannot accept empty value for workdir")
				}
				work = value
			}
		}
	}
	if (upper == "") != (work == "") {
		return "", fmt.Errorf("must specify both upperdir and workdir")
	}
	if upper == "" {
		return "", nil
	}
	const contentDir = "/var/lib/containers/storage/overlay-containers/c1/userdata/overlay/1"
	place := func(dir string) string {
		if path.IsAbs(dir) {
			return dir
		}
		return path.Join(contentDir, dir)
	}
	return " upper=" + place(upper) + " work=" + place(work), nil
}

func (d *libpodRootfsChainDaemon) createLibpodContainer(body io.Reader) error {
	var spec struct {
		Rootfs         string `json:"rootfs"`
		RootfsOverlay  *bool  `json:"rootfs_overlay"`
		OverlayVolumes []struct {
			Source      string   `json:"source"`
			Destination string   `json:"destination"`
			Options     []string `json:"options"`
		} `json:"overlay_volumes"`
		// NamedVolume carries no JSON tags (pkg/specgen/volumes.go:17-32).
		Volumes []struct {
			Name    string
			Dest    string
			Options []string
		} `json:"volumes"`
		Mounts []struct {
			Type        string `json:"type"`
			Source      string `json:"source"`
			Destination string `json:"destination"`
		} `json:"mounts"`
		InitPath      string `json:"init_path"`
		ConmonPidFile string `json:"conmon_pid_file"`
	}
	if err := json.NewDecoder(body).Decode(&spec); err != nil {
		return fmt.Errorf("decode(): %w", err)
	}
	var parts []string
	if spec.Rootfs != "" {
		if spec.RootfsOverlay != nil && *spec.RootfsOverlay {
			parts = append(parts, "rootfs-lowerdir="+spec.Rootfs)
		} else {
			parts = append(parts, "rootfs="+spec.Rootfs)
		}
	}
	for _, m := range spec.Mounts {
		if m.Type != "bind" {
			parts = append(parts, m.Type+"="+m.Source+":"+m.Destination)
			continue
		}
		source := m.Source
		if !path.IsAbs(source) {
			source = path.Join(libpodRootfsChainDaemonDir, source)
		}
		parts = append(parts, "bind="+path.Clean(source)+":"+m.Destination)
	}
	for _, v := range spec.OverlayVolumes {
		dirs, err := libpodChainOverlayDirs(v.Options)
		if err != nil {
			return err
		}
		parts = append(parts, "overlay="+v.Source+":"+v.Destination+dirs)
	}
	for _, v := range spec.Volumes {
		dirs := ""
		if slices.Contains(v.Options, "O") {
			var err error
			if dirs, err = libpodChainOverlayDirs(v.Options); err != nil {
				return err
			}
			dirs = " overlay" + dirs
		}
		parts = append(parts, "volume="+v.Name+":"+v.Dest+dirs)
	}
	if spec.InitPath != "" {
		parts = append(parts, "init_path="+spec.InitPath)
	}
	if spec.ConmonPidFile != "" {
		parts = append(parts, "conmon_pid_file="+spec.ConmonPidFile)
	}
	d.record(parts)
	return nil
}

// createCompatContainer is the volume half of the compat handler. Every
// HostConfig.Binds entry, and then every Config.Volumes key that isn't already
// a destination, is appended to one "-v" list
// (pkg/api/handlers/compat/containers_create.go:516-541), and each entry of
// that list goes through GenVolumeMounts (pkg/specgen/volumes.go:89-231).
func (d *libpodRootfsChainDaemon) createCompatContainer(body io.Reader) error {
	var cc struct {
		Volumes    map[string]struct{}
		HostConfig struct {
			Binds  []string
			Mounts []compatMount
		}
	}
	if err := json.NewDecoder(body).Decode(&cc); err != nil {
		return fmt.Errorf("decode(): %w", err)
	}
	var parts []string
	// HostConfig.Mounts are processed first by the compat handler: each is
	// rebuilt into one comma-joined "--mount" string and re-parsed
	// (compat/containers_create.go:230-266, specgenutil/volumes.go). See
	// compatMountRecord.
	for _, m := range cc.HostConfig.Mounts {
		record, err := compatMountRecord(m)
		if err != nil {
			return err
		}
		parts = append(parts, record)
	}
	specs := slices.Clone(cc.HostConfig.Binds)
	destinations := map[string]bool{}
	for _, bind := range cc.HostConfig.Binds {
		if split := strings.Split(bind, ":"); len(split) == 1 {
			destinations[bind] = true
		} else {
			destinations[split[1]] = true
		}
	}
	for _, key := range slices.Sorted(maps.Keys(cc.Volumes)) {
		if !destinations[key] {
			specs = append(specs, key)
		}
	}
	for _, spec := range specs {
		split := strings.Split(spec, ":")
		// A Podman machine hosted on Windows (wsl, hyperv) re-joins a leading
		// drive letter into the host path ("c:/x:/h" is the source "c:/x").
		// The re-join only applies to a drive-letter shaped spec, so "c:/h"
		// and "c:/h:ro" stay a one-letter named volume.
		if len(split[0]) == 1 && ((len(split) == 3 && strings.HasPrefix(split[2], "/")) || len(split) >= 4) {
			split = append([]string{split[0] + ":" + split[1]}, split[2:]...)
			parts = append(parts, "winpath="+split[0])
		}
		if len(split) > 3 {
			return fmt.Errorf("%v: incorrect volume format, should be [host-dir:]ctr-dir[:option]", spec)
		}
		if len(split) == 1 {
			parts = append(parts, "anonymous="+spec)
			continue
		}
		source, dest := split[0], split[1]
		var options []string
		if len(split) == 3 {
			options = strings.Split(split[2], ",")
		}
		kind := "volume"
		if strings.HasPrefix(source, "/") || strings.HasPrefix(source, ".") {
			kind = "bind"
		}
		dirs := ""
		if slices.Contains(options, "O") {
			var err error
			if dirs, err = libpodChainOverlayDirs(options); err != nil {
				return err
			}
			if kind == "bind" {
				kind = "overlay"
			} else {
				dirs = " overlay" + dirs
			}
		}
		parts = append(parts, kind+"="+source+":"+dest+dirs)
	}
	d.record(parts)
	return nil
}

func (d *libpodRootfsChainDaemon) record(parts []string) {
	where := "no host paths"
	if len(parts) > 0 {
		where = strings.Join(parts, " ")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.created = append(d.created, "container: "+where)
}

func (d *libpodRootfsChainDaemon) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.created)
}

// TestServeChainLibpodRootfsAndOverlayNeedTheBindMountAllowlist sends native
// Podman container creates through the production chain to a daemon that
// records the host paths each create would hand the container, and asserts
// that rootfs, overlay_volumes sources, overlay upper and work directories and
// init_path are held to allowed_bind_mounts, that a bind source has to be an
// absolute path, and that conmon_pid_file is refused outright.
//
// Before the gate, a create with default libpod_container_create options and
// {"rootfs":"/"} reached the daemon and ran a container whose root filesystem
// was the host's /, and {"overlay_volumes":[{"source":"/"}]} mounted the
// host's / inside it, both past allowed_bind_mounts. Each host-path field now
// needs an allowed_bind_mounts entry that covers it, the way mounts[] bind
// sources already do, and conmon_pid_file is refused whenever it's set.
//
// The overlay directories have the same exposure on the Docker-compatible
// create, where a Podman upstream reads them out of a HostConfig.Binds entry,
// so those go through the same chain against the compat block's allowlist.
func TestServeChainLibpodRootfsAndOverlayNeedTheBindMountAllowlist(t *testing.T) {
	const (
		libpodCreate = "/v5.8.6/libpod/containers/create"
		compatCreate = "/v1.41/containers/create"
	)
	type request struct{ path, body string }
	// Every body carries systemd:"false" so the systemd gate, which denies by
	// default, doesn't answer first (see basic_create.json).
	libpod := func(fields string) request {
		return request{libpodCreate, `{"systemd":"false",` + fields + `}`}
	}
	compat := func(binds string) request {
		return request{compatCreate, `{"Image":"alpine","HostConfig":{"Binds":[` + binds + `]}}`}
	}
	compatVolumes := func(volumes string) request {
		return request{compatCreate, `{"Image":"alpine","Volumes":{` + volumes + `}}`}
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
	compatSrv := func(body *gates) { body.ContainerCreate.AllowedBindMounts = []string{"/srv/roots"} }
	const (
		upperEtcDenied    = `overlay option "upperdir=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`
		libpodDenied      = "libpod container create denied: "
		compatDenied      = "container create denied: "
		overlayOntoEtc    = `"O","upperdir=/etc","workdir=/mnt"`
		overlayOntoSrv    = `"O","upperdir=/srv/roots/upper","workdir=/srv/roots/work"`
		overlayDirsOnSrv  = " upper=/srv/roots/upper work=/srv/roots/work"
		overlaySourceOnly = `{"source":"/srv/roots/d","destination":"/d"`
	)

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

		// Overlay upper and work directories in overlay_volumes options. The
		// source is allowlisted in every case, so only the options decide.
		{
			name:        "libpod overlay volume with the overlay flag alone reaches the daemon",
			configure:   allowSrv,
			send:        libpod(`"image":"alpine","overlay_volumes":[` + overlaySourceOnly + `,"options":["O"]}]`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("overlay=/srv/roots/d:/d"),
		},
		{
			name:        "libpod overlay volume with allowlisted upper and work directories reaches the daemon",
			configure:   allowSrv,
			send:        libpod(`"image":"alpine","overlay_volumes":[` + overlaySourceOnly + `,"options":[` + overlayOntoSrv + `]}]`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("overlay=/srv/roots/d:/d" + overlayDirsOnSrv),
		},
		{
			name:       "libpod overlay volume with its upper directory in /etc is refused",
			configure:  allowSrv,
			send:       libpod(`"image":"alpine","overlay_volumes":[` + overlaySourceOnly + `,"options":[` + overlayOntoEtc + `]}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + upperEtcDenied,
		},
		{
			// Podman matches the option by prefix.
			name:       "libpod overlay volume with a suffixed upperdir key is refused",
			configure:  allowSrv,
			send:       libpod(`"image":"alpine","overlay_volumes":[` + overlaySourceOnly + `,"options":["upperdirX=/etc","workdirX=/mnt"]}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `overlay option "upperdirX=/etc" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			// buildah joins a relative directory under the container's own
			// overlay directory, and "../" walks back out of it.
			name:       "libpod overlay volume with a relative upper directory is refused even with / allowlisted",
			configure:  allowRoot,
			send:       libpod(`"image":"alpine","overlay_volumes":[` + overlaySourceOnly + `,"options":["upperdir=../../../../../../../../etc","workdir=../../../../../../../../mnt"]}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `overlay option "upperdir=../../../../../../../../etc" does not name an absolute path`,
		},
		{
			name:       "libpod overlay volume with an empty upper directory is refused",
			configure:  allowRoot,
			send:       libpod(`"image":"alpine","overlay_volumes":[` + overlaySourceOnly + `,"options":["upperdir=","workdir=/srv/roots/work"]}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `overlay option "upperdir=" does not name an absolute path`,
		},
		{
			name:       "libpod overlay volume whose upper directory carries a comma is refused",
			configure:  allowSrv,
			send:       libpod(`"image":"alpine","overlay_volumes":[` + overlaySourceOnly + `,"options":["upperdir=/srv/roots/upper,lowerdir=/etc","workdir=/srv/roots/work"]}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `overlay option "upperdir=/srv/roots/upper,lowerdir=/etc" contains a comma or backslash`,
		},
		{
			// The kernel strips the backslash, so this is /etc to the mount
			// and a path under /srv/roots to a cleaned comparison.
			name:       "libpod overlay volume whose upper directory carries a backslash is refused",
			configure:  allowSrv,
			send:       libpod(`"image":"alpine","overlay_volumes":[` + overlaySourceOnly + `,"options":["upperdir=/srv/roots/..\\/etc","workdir=/srv/roots/work"]}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `overlay option "upperdir=/srv/roots/..\\/etc" contains a comma or backslash`,
		},

		// The overlay's lowerdir: an overlay_volumes source, and rootfs with
		// rootfs_overlay.
		{
			name:       "libpod overlay volume whose source carries a comma is refused",
			configure:  allowSrv,
			send:       libpod(`"image":"alpine","overlay_volumes":[{"source":"/srv/roots/d,lowerdir=/etc","destination":"/d"}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `overlay volume source "/srv/roots/d,lowerdir=/etc" contains a comma or backslash`,
		},
		{
			name:       "libpod overlay volume whose source carries a backslash is refused",
			configure:  allowSrv,
			send:       libpod(`"image":"alpine","overlay_volumes":[{"source":"/srv/roots/d\\:/etc","destination":"/d"}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `overlay volume source "/srv/roots/d\\:/etc" contains a comma or backslash`,
		},
		{
			name:       "libpod overlay rootfs carrying a comma is refused",
			configure:  allowSrv,
			send:       libpod(`"rootfs":"/srv/roots/app,lowerdir=/etc","rootfs_overlay":true`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `rootfs path "/srv/roots/app,lowerdir=/etc" contains a comma or backslash, which rootfs_overlay can't mount safely`,
		},
		{
			name:       "libpod overlay rootfs carrying a backslash is refused",
			configure:  allowSrv,
			send:       libpod(`"rootfs":"/srv/roots/app\\:/etc","rootfs_overlay":true`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `rootfs path "/srv/roots/app\\:/etc" contains a comma or backslash, which rootfs_overlay can't mount safely`,
		},
		{
			name:        "libpod overlay rootfs with an ordinary path reaches the daemon",
			configure:   allowSrv,
			send:        libpod(`"rootfs":"/srv/roots/app","rootfs_overlay":true`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("rootfs-lowerdir=/srv/roots/app"),
		},
		{
			// Without the overlay the path never meets an option string.
			name:        "libpod plain rootfs carrying a comma reaches the daemon",
			configure:   allowSrv,
			send:        libpod(`"rootfs":"/srv/roots/app,v2"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("rootfs=/srv/roots/app,v2"),
		},

		// Named volumes. The volume isn't a host path and needs no allowlist
		// entry, but an overlay's upper and work directory are.
		{
			name:        "libpod named volume with ordinary options reaches the daemon",
			send:        libpod(`"image":"alpine","volumes":[{"Name":"v","Dest":"/d","Options":["ro","z","U","nocopy"]}]`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("volume=v:/d"),
		},
		{
			name:        "libpod named volume with no options reaches the daemon",
			send:        libpod(`"image":"alpine","volumes":[{"Name":"v","Dest":"/d","Options":null,"SubPath":"","IsAnonymous":false}]`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("volume=v:/d"),
		},
		{
			name:        "libpod named volume overlay reaches the daemon",
			send:        libpod(`"image":"alpine","volumes":[{"Name":"v","Dest":"/d","Options":["O"]}]`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("volume=v:/d overlay"),
		},
		{
			name:        "libpod named volume overlay with allowlisted upper and work directories reaches the daemon",
			configure:   allowSrv,
			send:        libpod(`"image":"alpine","volumes":[{"Name":"v","Dest":"/d","Options":[` + overlayOntoSrv + `]}]`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("volume=v:/d overlay" + overlayDirsOnSrv),
		},
		{
			name:       "libpod named volume overlay with its upper directory in /etc is refused",
			configure:  allowSrv,
			send:       libpod(`"image":"alpine","volumes":[{"Name":"v","Dest":"/d","Options":[` + overlayOntoEtc + `]}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + upperEtcDenied,
		},
		{
			name:       "libpod named volume overlay is refused by default",
			send:       libpod(`"image":"alpine","volumes":[{"Name":"v","Dest":"/d","Options":[` + overlayOntoSrv + `]}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `overlay option "upperdir=/srv/roots/upper" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:       "libpod named volume overlay under lower-case keys is refused",
			configure:  allowSrv,
			send:       libpod(`"image":"alpine","volumes":[{"name":"v","dest":"/d","options":[` + overlayOntoEtc + `]}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + upperEtcDenied,
		},

		// mounts[] bind sources. Podman resolves a relative one against its
		// own working directory, which is / for a packaged unit.
		{
			name:        "libpod bind mount from an allowlisted source reaches the daemon",
			configure:   allowSrv,
			send:        libpod(`"image":"alpine","mounts":[{"type":"bind","source":"/srv/roots/d","destination":"/d"}]`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("bind=/srv/roots/d:/d"),
		},
		{
			name:       "libpod bind mount from a relative source is refused by default",
			send:       libpod(`"image":"alpine","mounts":[{"type":"bind","source":"../../../../etc","destination":"/h"}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `bind mount source "../../../../etc" is not an absolute path`,
		},
		{
			name:       "libpod bind mount from a relative source is refused with an allowlist",
			configure:  allowSrv,
			send:       libpod(`"image":"alpine","mounts":[{"type":"bind","source":"etc","destination":"/h"}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `bind mount source "etc" is not an absolute path`,
		},
		{
			name:       "libpod bind mount with an empty source is refused",
			send:       libpod(`"image":"alpine","mounts":[{"type":"bind","source":"","destination":"/h"}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `bind mount source "" is not an absolute path`,
		},
		{
			name:       "libpod bind mount with no source is refused",
			send:       libpod(`"image":"alpine","mounts":[{"type":"bind","destination":"/h"}]`),
			wantStatus: http.StatusForbidden,
			wantReason: libpodDenied + `bind mount source "" is not an absolute path`,
		},
		{
			name:        "libpod tmpfs mount reaches the daemon",
			send:        libpod(`"image":"alpine","mounts":[{"type":"tmpfs","source":"tmpfs","destination":"/tmp/x"}]`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("tmpfs=tmpfs:/tmp/x"),
		},

		// The Docker-compatible create on the same Podman. Its Binds entries
		// are "-v" arguments, so the third field carries the same options.
		{
			name:        "compat named volume with ordinary options reaches the daemon",
			send:        compat(`"myvol:/d:ro,z","cache:/c:nocopy"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("volume=myvol:/d volume=cache:/c"),
		},
		{
			name:        "compat named volume overlay reaches the daemon",
			send:        compat(`"myvol:/d:O"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("volume=myvol:/d overlay"),
		},
		{
			name:        "compat named volume overlay with allowlisted upper and work directories reaches the daemon",
			configure:   compatSrv,
			send:        compat(`"myvol:/d:O,upperdir=/srv/roots/upper,workdir=/srv/roots/work"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("volume=myvol:/d overlay" + overlayDirsOnSrv),
		},
		{
			name:       "compat named volume overlay with its upper directory in /etc is refused by default",
			send:       compat(`"myvol:/d:O,upperdir=/etc,workdir=/mnt"`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied + upperEtcDenied,
		},
		{
			name:       "compat named volume overlay with its upper directory in /etc is refused with an allowlist",
			configure:  compatSrv,
			send:       compat(`"myvol:/d:O,upperdir=/etc,workdir=/mnt"`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied + upperEtcDenied,
		},
		{
			// The native block's allowlist is for the native create. It
			// doesn't open the compat route.
			name:       "compat named volume overlay with only the libpod allowlist is refused",
			configure:  allowSrv,
			send:       compat(`"myvol:/d:O,upperdir=/srv/roots/upper,workdir=/srv/roots/work"`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied + `overlay option "upperdir=/srv/roots/upper" is not allowlisted (add its directory to allowed_bind_mounts)`,
		},
		{
			name:        "compat host path overlay from an allowlisted source reaches the daemon",
			configure:   compatSrv,
			send:        compat(`"/srv/roots/d:/d:O"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("overlay=/srv/roots/d:/d"),
		},
		{
			name:       "compat host path overlay with its upper directory in /etc is refused",
			configure:  compatSrv,
			send:       compat(`"/srv/roots/d:/d:O,upperdir=/etc,workdir=/mnt"`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied + upperEtcDenied,
		},
		{
			name:       "compat host path overlay with a relative upper directory is refused",
			configure:  compatSrv,
			send:       compat(`"/srv/roots/d:/d:O,upperdir=../../../../../../../../etc,workdir=../../../../../../../../mnt"`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied + `overlay option "upperdir=../../../../../../../../etc" does not name an absolute path`,
		},
		{
			name:       "compat host path overlay whose source carries a comma is refused",
			configure:  compatSrv,
			send:       compat(`"/srv/roots/d,lowerdir=/etc:/d:O"`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied + `overlay bind source "/srv/roots/d,lowerdir=/etc" contains a comma or backslash`,
		},

		// Config.Volumes keys. dockerd reads a key as a container path. Podman
		// reads it as a "-v" argument, so it gets the checks a Binds entry does.
		{
			name:        "compat anonymous volume reaches the daemon",
			send:        compatVolumes(`"/data":{}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("anonymous=/data"),
		},
		{
			// docker-py list-form volumes with a mode: the key is a container
			// path plus a mode, and the bind rides in HostConfig.Binds.
			name:        "compat docker-py Volumes key with a mode reaches the daemon",
			configure:   func(body *gates) { body.ContainerCreate.AllowedBindMounts = []string{"/srv/ok"} },
			send:        request{compatCreate, `{"Image":"alpine","Volumes":{"/data:z":{}},"HostConfig":{"Binds":["/srv/ok:/data:z"]}}`},
			wantStatus:  http.StatusCreated,
			wantCreated: created("bind=/srv/ok:/data bind=/data:z"),
		},
		{
			name:       "compat Volumes key that binds /etc is refused by default",
			send:       compatVolumes(`"/etc:/h":{}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied + `bind mount source "/etc" is not allowlisted`,
		},
		{
			name:       "compat Volumes key that binds /etc is refused with an allowlist",
			configure:  compatSrv,
			send:       compatVolumes(`"/data":{},"/etc:/h:ro":{}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied + `bind mount source "/etc" is not allowlisted`,
		},
		{
			name:        "compat Volumes key that binds an allowlisted path reaches the daemon",
			configure:   compatSrv,
			send:        compatVolumes(`"/srv/roots/d:/d":{}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("bind=/srv/roots/d:/d"),
		},
		{
			name:        "compat Volumes key naming a volume reaches the daemon",
			send:        compatVolumes(`"myvol:/d:ro":{}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("volume=myvol:/d"),
		},
		{
			name:       "compat Volumes key overlay with its upper directory in /etc is refused",
			configure:  compatSrv,
			send:       compatVolumes(`"myvol:/d:O,upperdir=/etc,workdir=/mnt":{}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied + upperEtcDenied,
		},
		{
			name:       "compat Volumes key under a lower-case field name is refused",
			send:       request{compatCreate, `{"Image":"alpine","volumes":{"/etc:/h":{}}}`},
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied + `bind mount source "/etc" is not allowlisted`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newLibpodRootfsChainDaemon()
			addr := newEngineChain(t, "rootfs", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
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
