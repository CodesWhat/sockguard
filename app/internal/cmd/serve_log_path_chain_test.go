package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/apipath"
	"github.com/codeswhat/sockguard/v2/app/internal/config"
	"github.com/codeswhat/sockguard/v2/app/internal/testhelp"
)

// logPathChainDaemon is the log half of a Podman container create: the host
// paths a create names for the daemon to write logs to, on both routes. It
// records what each create it accepted would have Podman write, read from
// Podman 6.1.3 and checked against 5.8.6, where the same code sits a few
// lines away.
//
// POST /containers/create has no log path field. HostConfig.LogConfig is a
// driver name and a string map, and the compat handler turns the map into
// "--log-opt" arguments: stringMaptoArray writes each entry as key + "=" +
// value (pkg/api/handlers/compat/containers_create.go:144-150, called at
// :457). FillOutSpecGen then cuts each argument at its first "=" and switches
// on the lowered name (pkg/specgenutil/specgen.go:848-875):
//
//   - "path" sets LogConfiguration.Path.
//   - "driver" sets LogConfiguration.Driver, over HostConfig.LogConfig.Type.
//   - "max-size" is parsed as a size, and "label" (6.x) as a journald label.
//   - anything else lands in LogConfiguration.Options, where only "tag" is
//     read again.
//
// The name is lowered, so "Path" and "PATH" are the path too. The cut is at
// the first "=" of the joined argument, so a key that already holds one
// carries its own value: {"path=/var/log/x": "y"} is the argument
// "path=/var/log/x=y", name "path", value "/var/log/x=y".
//
// POST /vX/libpod/containers/create decodes a SpecGenerator, where the path
// is a field of its own: log_configuration.path (pkg/specgen/specgen.go:25).
// log_configuration.options is not read for a path there. The lowering
// switch above is CLI-side code the native handler never runs, and
// MakeContainer reads only "tag" out of the options
// (pkg/specgen/generate/container_create.go:575).
//
// Either way a non-empty path reaches libpod.WithLogPath
// (container_create.go:569-570), whatever the driver. It makes a directory
// named for the container under the path when the path is a directory, and
// otherwise keeps the path as the log file (libpod/options.go:1016-1032).
// conmon then writes the container's output there under the k8s-file and
// json-file drivers, and when no driver was named and the daemon's default is
// one of those (libpod/oci_conmon_common.go:1334-1354).
//
// The native create has a second log destination. healthLogDestination
// (ContainerHealthCheckConfig, specgen.go:614) is "local" unless the body
// sets it (pkg/api/handlers/libpod/containers_create.go:57). "local" and
// "events_logger" keep healthcheck results in the container's own state, and
// any other value has to be a directory on the daemon host
// (libpod/define/healthchecks.go:295-314), where each healthcheck run writes
// <dir>/<container id>-healthcheck.log (libpod/healthcheck.go:416-428). The
// compat create pins it to "local" (compat/containers_create.go:444).
type logPathChainDaemon struct {
	mu      sync.Mutex
	created []string
}

func (d *logPathChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

// logPathChainDrivers are the drivers libpod.WithLogDriver accepts
// (libpod/options.go:995-1012). Any other name fails the create.
var logPathChainDrivers = []string{"journald", "k8s-file", "json-file", "none", "passthrough", "passthrough-tty"}

func (d *logPathChainDaemon) createCompatContainer(body io.Reader) error {
	var cc struct {
		HostConfig struct {
			LogConfig struct {
				Type   string
				Config map[string]string
			}
		}
	}
	if err := json.NewDecoder(body).Decode(&cc); err != nil {
		return fmt.Errorf("decode(): %w", err)
	}
	driver, logPath := cc.HostConfig.LogConfig.Type, ""
	// stringMaptoArray ranges over the map, so Podman reads the options in
	// whatever order Go hands them out and the last "path" it meets wins. A
	// client can resend until the order suits it. Sorted here so a body with
	// two spellings always records the same one.
	for _, key := range slices.Sorted(maps.Keys(cc.HostConfig.LogConfig.Config)) {
		option := key + "=" + cc.HostConfig.LogConfig.Config[key]
		name, value, _ := strings.Cut(option, "=")
		switch strings.ToLower(name) {
		case "driver":
			driver = value
		case "path":
			logPath = value
		}
	}
	return d.record(driver, logPath, "local")
}

func (d *logPathChainDaemon) createLibpodContainer(body io.Reader) error {
	spec := struct {
		LogConfiguration *struct {
			Driver  string            `json:"driver"`
			Path    string            `json:"path"`
			Size    int64             `json:"size"`
			Options map[string]string `json:"options"`
		} `json:"log_configuration"`
		HealthLogDestination string `json:"healthLogDestination"`
	}{HealthLogDestination: "local"}
	if err := json.NewDecoder(body).Decode(&spec); err != nil {
		return fmt.Errorf("decode(): %w", err)
	}
	driver, logPath := "", ""
	if spec.LogConfiguration != nil {
		driver, logPath = spec.LogConfiguration.Driver, spec.LogConfiguration.Path
	}
	return d.record(driver, logPath, spec.HealthLogDestination)
}

// record is what MakeContainer does with the three values once either route
// has filled them in. Every directory the model is handed exists.
func (d *logPathChainDaemon) record(driver, logPath, healthLog string) error {
	var parts []string
	if logPath != "" {
		parts = append(parts, "log="+logPath)
	}
	if driver != "" {
		if !slices.Contains(logPathChainDrivers, driver) {
			return fmt.Errorf("invalid log driver: invalid argument")
		}
		parts = append(parts, "driver="+driver)
	}
	if healthLog != "local" && healthLog != "events_logger" {
		parts = append(parts, "healthlog="+healthLog)
	}
	where := "daemon's own log paths"
	if len(parts) > 0 {
		where = strings.Join(parts, " ")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.created = append(d.created, "container: "+where)
	return nil
}

func (d *logPathChainDaemon) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.created)
}

// TestServeChainLogPathNeedsItsOption sends container creates through the
// production chain to a daemon that records where each create would have
// Podman write logs, and pins that a path the client chose doesn't reach it
// unless allow_log_path is on for that route.
//
// Before the gate every body below reached the daemon. The compat body
// {"HostConfig":{"LogConfig":{"Type":"k8s-file","Config":{"path":"/host/x.log"}}}}
// was confirmed against a live Podman 6.1.3, which wrote the container's
// output to that file on the host. The rest are read from source. dockerd
// has no log path a client can set: json-file and local write under the
// container's own directory and refuse an option they don't know.
//
// allowed_bind_mounts doesn't cover any of this. It lists host paths a
// container may mount, and a log path is one the daemon writes itself.
func TestServeChainLogPathNeedsItsOption(t *testing.T) {
	const (
		libpodCreate = "/v6.1.3/libpod/containers/create"
		compatCreate = "/v1.41/containers/create"
	)
	type request struct{ path, body string }
	compat := func(logConfig string) request {
		return request{compatCreate, `{"Image":"alpine","HostConfig":{"LogConfig":` + logConfig + `}}`}
	}
	// Every native body carries systemd:"false" so the systemd gate, which
	// denies by default, doesn't answer first (see basic_create.json).
	libpod := func(fields string) request {
		return request{libpodCreate, `{"systemd":"false","image":"alpine"` + fields + `}`}
	}
	// captured is a body podman-remote 6.1.3 sent for a log flag, as recorded
	// in internal/filter/testdata/libpod (see the README there). Those carry
	// systemd "true", so each is sent with allow_systemd_mode on.
	captured := func(fixture string) request {
		body, err := os.ReadFile(filepath.Join("..", "filter", "testdata", "libpod", fixture))
		if err != nil {
			t.Fatalf("read fixture %s: %v", fixture, err)
		}
		return request{libpodCreate, string(body)}
	}
	created := func(where string) []string { return []string{"container: " + where} }
	type gates = config.RequestBodyConfig
	compatOn := func(body *gates) { body.ContainerCreate.AllowLogPath = true }
	libpodOn := func(body *gates) { body.LibpodContainerCreate.AllowLogPath = true }
	systemd := func(body *gates) { body.LibpodContainerCreate.AllowSystemdMode = true }
	systemdAndLibpodOn := func(body *gates) {
		body.LibpodContainerCreate.AllowSystemdMode = true
		body.LibpodContainerCreate.AllowLogPath = true
	}
	const (
		ownPaths     = "daemon's own log paths"
		compatDenied = "container create denied: setting a log path in HostConfig.LogConfig.Config is not allowed (set allow_log_path: true)"
		pathDenied   = "libpod container create denied: setting log_configuration.path is not allowed (set allow_log_path: true)"
		healthDenied = `libpod container create denied: setting healthLogDestination to a host directory is not allowed (set allow_log_path: true, or use "local" or "events_logger")`
	)

	tests := []struct {
		name        string
		configure   func(*gates)
		send        request
		wantStatus  int
		wantReason  string
		wantCreated []string
	}{
		// Controls: a create that names no log path keeps reaching the daemon
		// with the option off.
		{
			name:        "compat create with no LogConfig reaches the daemon",
			send:        request{compatCreate, `{"Image":"alpine","HostConfig":{}}`},
			wantStatus:  http.StatusCreated,
			wantCreated: created(ownPaths),
		},
		{
			name:        "compat create with an empty LogConfig reaches the daemon",
			send:        compat(`{"Type":"","Config":null}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created(ownPaths),
		},
		{
			name:        "compat json-file with size options reaches the daemon",
			send:        compat(`{"Type":"json-file","Config":{"max-size":"10m","max-file":"3"}}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("driver=json-file"),
		},
		{
			name:        "compat journald with a tag reaches the daemon",
			send:        compat(`{"Type":"journald","Config":{"tag":"{{.Name}}"}}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("driver=journald"),
		},
		{
			name:        "compat option whose name only contains path reaches the daemon",
			send:        compat(`{"Type":"k8s-file","Config":{"xpath":"/host/x.log","path-style":"/host/y.log","tag":"path=/host/z.log"}}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("driver=k8s-file"),
		},
		{
			// Podman's inspect reports the log file as LogConfig.Path, beside
			// Config, and a client that recreates a container sends it back.
			// The compat create decodes Docker's LogConfig, which has no Path.
			name:        "compat LogConfig.Path beside Config reaches the daemon and is not a path there",
			send:        compat(`{"Type":"json-file","Config":null,"Path":"/var/lib/containers/storage/overlay-containers/c1/userdata/ctr.log","Tag":"","Size":"0B"}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("driver=json-file"),
		},
		{
			name:        "libpod create with no log_configuration reaches the daemon",
			send:        libpod(``),
			wantStatus:  http.StatusCreated,
			wantCreated: created(ownPaths),
		},
		{
			name:        "libpod create with the empty log_configuration podman-remote sends reaches the daemon",
			send:        libpod(`,"log_configuration":{},"healthLogDestination":"local"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created(ownPaths),
		},
		{
			name:        "libpod log_configuration with a driver and a size reaches the daemon",
			send:        libpod(`,"log_configuration":{"driver":"k8s-file","size":10485760}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("driver=k8s-file"),
		},
		{
			// The native handler doesn't read a path out of options.
			name:        "libpod log_configuration options named path reaches the daemon and is not a path there",
			send:        libpod(`,"log_configuration":{"driver":"k8s-file","options":{"path":"/host/x.log","tag":"web"}}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("driver=k8s-file"),
		},
		{
			name:        "libpod healthLogDestination events_logger reaches the daemon",
			send:        libpod(`,"healthLogDestination":"events_logger"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created(ownPaths),
		},

		// Compat: the option Podman reads as the log path, option off.
		{
			name:       "compat k8s-file with a path is refused",
			send:       compat(`{"Type":"k8s-file","Config":{"path":"/host/x.log"}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			name:       "compat path with a capital is refused",
			send:       compat(`{"Type":"k8s-file","Config":{"Path":"/host/x.log"}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			name:       "compat path in capitals is refused",
			send:       compat(`{"Type":"k8s-file","Config":{"PATH":"/host/x.log"}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			name:       "compat path under lowercase struct keys is refused",
			send:       request{compatCreate, `{"image":"alpine","hostconfig":{"logconfig":{"type":"k8s-file","config":{"path":"/host/x.log"}}}}`},
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			name:       "compat path with no driver is refused",
			send:       compat(`{"Config":{"path":"/host/x.log"}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			name:       "compat path under json-file is refused",
			send:       compat(`{"Type":"json-file","Config":{"path":"/host/x.log","max-size":"10m"}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			// conmon doesn't write a file under journald, but WithLogPath has
			// already made a directory when the path names one.
			name:       "compat path under journald is refused",
			send:       compat(`{"Type":"journald","Config":{"path":"/host/logs"}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			name:       "compat path with the driver set from an option is refused",
			send:       compat(`{"Type":"journald","Config":{"driver":"k8s-file","path":"/host/x.log"}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			name:       "compat path carried in the key is refused",
			send:       compat(`{"Type":"k8s-file","Config":{"path=/host/x":"log"}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			name:       "compat capital path carried in the key is refused",
			send:       compat(`{"Type":"k8s-file","Config":{"PATH=/host/x":""}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			name:       "compat path in two spellings is refused",
			send:       compat(`{"Type":"k8s-file","Config":{"PATH":"","path":"/host/x.log"}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			// Refused on the key, not the value: sockguard doesn't have to
			// agree with the daemon about which of two "path" keys it keeps.
			name:       "compat path given twice is refused",
			send:       compat(`{"Type":"k8s-file","Config":{"path":"/host/x.log","path":""}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			name:       "compat path with an empty value is refused",
			send:       compat(`{"Type":"k8s-file","Config":{"path":""}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			name:       "compat path is refused with the native option on",
			configure:  libpodOn,
			send:       compat(`{"Type":"k8s-file","Config":{"path":"/host/x.log"}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},
		{
			name:       "compat path is refused with its directory in allowed_bind_mounts",
			configure:  func(body *gates) { body.ContainerCreate.AllowedBindMounts = []string{"/host"} },
			send:       compat(`{"Type":"k8s-file","Config":{"path":"/host/x.log"}}`),
			wantStatus: http.StatusForbidden,
			wantReason: compatDenied,
		},

		// Compat, option on.
		{
			name:        "compat k8s-file with a path reaches the daemon with allow_log_path",
			configure:   compatOn,
			send:        compat(`{"Type":"k8s-file","Config":{"path":"/host/x.log"}}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("log=/host/x.log driver=k8s-file"),
		},
		{
			name:        "compat path in capitals reaches the daemon with allow_log_path",
			configure:   compatOn,
			send:        compat(`{"Config":{"PATH":"/host/x.log"}}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("log=/host/x.log"),
		},
		{
			name:        "compat path carried in the key reaches the daemon with allow_log_path",
			configure:   compatOn,
			send:        compat(`{"Type":"k8s-file","Config":{"path=/host/x":"log"}}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("log=/host/x=log driver=k8s-file"),
		},
		{
			name:        "compat path with the driver set from an option reaches the daemon with allow_log_path",
			configure:   compatOn,
			send:        compat(`{"Type":"journald","Config":{"driver":"k8s-file","path":"/host/x.log"}}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("log=/host/x.log driver=k8s-file"),
		},

		// Native: log_configuration.path, option off and on.
		{
			name:       "libpod log_configuration.path is refused",
			send:       libpod(`,"log_configuration":{"driver":"k8s-file","path":"/host/x.log"}`),
			wantStatus: http.StatusForbidden,
			wantReason: pathDenied,
		},
		{
			name:       "libpod log_configuration.path with no driver is refused",
			send:       libpod(`,"log_configuration":{"path":"/host/x.log"}`),
			wantStatus: http.StatusForbidden,
			wantReason: pathDenied,
		},
		{
			name:       "libpod log_configuration.path under journald is refused",
			send:       libpod(`,"log_configuration":{"driver":"journald","path":"/host/logs"}`),
			wantStatus: http.StatusForbidden,
			wantReason: pathDenied,
		},
		{
			name:       "libpod log_configuration.path under capitalized keys is refused",
			send:       libpod(`,"LOG_CONFIGURATION":{"Path":"/host/x.log"}`),
			wantStatus: http.StatusForbidden,
			wantReason: pathDenied,
		},
		{
			name:       "libpod log_configuration.path is refused with the compat option on",
			configure:  compatOn,
			send:       libpod(`,"log_configuration":{"path":"/host/x.log"}`),
			wantStatus: http.StatusForbidden,
			wantReason: pathDenied,
		},
		{
			name:       "libpod log_configuration.path is refused with / in allowed_bind_mounts",
			configure:  func(body *gates) { body.LibpodContainerCreate.AllowedBindMounts = []string{"/"} },
			send:       libpod(`,"log_configuration":{"path":"/host/x.log"}`),
			wantStatus: http.StatusForbidden,
			wantReason: pathDenied,
		},
		{
			name:        "libpod log_configuration.path reaches the daemon with allow_log_path",
			configure:   libpodOn,
			send:        libpod(`,"log_configuration":{"driver":"k8s-file","path":"/host/x.log"}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("log=/host/x.log driver=k8s-file"),
		},

		// Native: the healthcheck log directory.
		{
			name:       "libpod healthLogDestination directory is refused",
			send:       libpod(`,"healthLogDestination":"/host/logs"`),
			wantStatus: http.StatusForbidden,
			wantReason: healthDenied,
		},
		{
			name:       "libpod healthLogDestination relative directory is refused",
			send:       libpod(`,"healthLogDestination":"logs"`),
			wantStatus: http.StatusForbidden,
			wantReason: healthDenied,
		},
		{
			// Podman compares the two names exactly, so this is a directory
			// called LOCAL under the daemon's working directory.
			name:       "libpod healthLogDestination local in capitals is refused",
			send:       libpod(`,"healthLogDestination":"LOCAL"`),
			wantStatus: http.StatusForbidden,
			wantReason: healthDenied,
		},
		{
			name:       "libpod healthLogDestination under a lowercase key is refused",
			send:       libpod(`,"healthlogdestination":"/host/logs"`),
			wantStatus: http.StatusForbidden,
			wantReason: healthDenied,
		},
		{
			name:        "libpod healthLogDestination directory reaches the daemon with allow_log_path",
			configure:   libpodOn,
			send:        libpod(`,"healthLogDestination":"/host/logs"`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("healthlog=/host/logs"),
		},

		// What podman-remote puts on the wire for each log flag.
		{
			name:       "podman-remote --log-opt path is refused",
			configure:  systemd,
			send:       captured("log_path.json"),
			wantStatus: http.StatusForbidden,
			wantReason: pathDenied,
		},
		{
			name:        "podman-remote --log-opt path reaches the daemon with allow_log_path",
			configure:   systemdAndLibpodOn,
			send:        captured("log_path.json"),
			wantStatus:  http.StatusCreated,
			wantCreated: created("log=/var/log/sg-ctr.log driver=k8s-file"),
		},
		{
			name:       "podman-remote --health-log-destination is refused",
			configure:  systemd,
			send:       captured("health_log_destination.json"),
			wantStatus: http.StatusForbidden,
			wantReason: healthDenied,
		},
		{
			name:        "podman-remote --health-log-destination reaches the daemon with allow_log_path",
			configure:   systemdAndLibpodOn,
			send:        captured("health_log_destination.json"),
			wantStatus:  http.StatusCreated,
			wantCreated: created("healthlog=/var/log"),
		},
		{
			name:        "podman-remote --log-driver with a tag reaches the daemon",
			configure:   systemd,
			send:        captured("log_driver_options.json"),
			wantStatus:  http.StatusCreated,
			wantCreated: created("driver=journald"),
		},
		{
			name:        "podman-remote create with no log flag reaches the daemon",
			configure:   systemd,
			send:        captured("basic_create.json"),
			wantStatus:  http.StatusCreated,
			wantCreated: created(ownPaths),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &logPathChainDaemon{}
			collector := &testhelp.CollectingHandler{}
			logger := testhelp.NewTeeLogger(slog.NewTextHandler(io.Discard, nil), collector)
			addr := newEngineChainWithLogger(t, "logpath", daemon, logger, func(cfg *config.Config) {
				cfg.Log.AccessLog = true
				cfg.Response.DenyVerbosity = "verbose"
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				if tt.configure != nil {
					tt.configure(&cfg.RequestBody)
				}
			})

			status, body := sendNamespaceChainRequest(t, "http://"+addr+tt.send.path, tt.send.body)
			record := keyRolloutChainRecord(t, collector)
			if got := daemon.seen(); !slices.Equal(got, tt.wantCreated) {
				t.Errorf("daemon created %q, want %q", got, tt.wantCreated)
			}
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
			if tt.wantReason == "" {
				if record.Message != "request" {
					t.Errorf("access log = %s with reason_code %v, want a plain request record", record.Message, record.Attrs["reason_code"])
				}
				return
			}
			var denial struct {
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal(body, &denial); err != nil || denial.Reason != tt.wantReason {
				t.Errorf("body = %s, want reason %q", body, tt.wantReason)
			}
			// The reason code every request-body policy denial carries.
			if record.Message != "request_denied" || record.Attrs["reason_code"] != "request_body_policy_denied" {
				t.Errorf("access log = %s with reason_code %v, want request_denied with request_body_policy_denied", record.Message, record.Attrs["reason_code"])
			}
		})
	}
}
