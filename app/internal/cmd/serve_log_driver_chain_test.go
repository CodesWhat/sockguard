package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// logDriverChainDaemon records which write routes a request reached.
type logDriverChainDaemon struct {
	mu   sync.Mutex
	seen []string
}

func (d *logDriverChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet && normPath == "/version" {
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
		return
	}
	_, _ = io.Copy(io.Discard, r.Body)
	d.mu.Lock()
	d.seen = append(d.seen, r.Method+" "+normPath)
	d.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"Id":"x"}`))
}

func (d *logDriverChainDaemon) reached() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.seen)
}

// TestServeChainLogDriverAllowlist sends creates carrying a log driver or a
// log destination option through the production chain on every surface that
// can set one, with allowed_log_drivers on, and pins that only an allowlisted
// driver with no unlisted destination option reaches the daemon. It also pins
// that the option off changes nothing, and that allow_log_path keeps its own
// gate beside it.
func TestServeChainLogDriverAllowlist(t *testing.T) {
	type gates = config.RequestBodyConfig
	allow := func(body *gates) {
		body.ContainerCreate.AllowedLogDrivers = []string{"json-file"}
		body.LibpodContainerCreate.AllowedLogDrivers = []string{"journald"}
		body.Service.AllowedLogDrivers = []string{"json-file"}
		body.LibpodPlayKube.AllowedLogDrivers = []string{"journald"}
	}
	const (
		compatPath  = "/v1.41/containers/create"
		libpodPath  = "/v6.1.3/libpod/containers/create"
		servicePath = "/v1.41/services/create"
		kubePath    = "/v6.1.3/libpod/play/kube"
	)
	compat := func(logConfig string) string {
		return `{"Image":"alpine","HostConfig":{"LogConfig":` + logConfig + `}}`
	}
	libpod := func(logConfig string) string {
		return `{"systemd":"false","image":"alpine","log_configuration":` + logConfig + `}`
	}
	service := func(logDriver string) string {
		return `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest"},"LogDriver":` + logDriver + `}}`
	}
	const kubeYAML = "apiVersion: v1\nkind: Pod\n"

	tests := []struct {
		name       string
		configure  func(*gates)
		path       string
		body       string
		wantStatus int
		wantSeen   []string
	}{
		{name: "compat: any driver with the option off", path: compatPath, body: compat(`{"Type":"syslog","Config":{"syslog-address":"tcp://evil:514"}}`), wantStatus: http.StatusCreated, wantSeen: []string{"POST /containers/create"}},
		{name: "compat: listed driver", configure: allow, path: compatPath, body: compat(`{"Type":"json-file","Config":{"max-size":"10m"}}`), wantStatus: http.StatusCreated, wantSeen: []string{"POST /containers/create"}},
		{name: "compat: unlisted driver", configure: allow, path: compatPath, body: compat(`{"Type":"syslog"}`), wantStatus: http.StatusForbidden},
		{name: "compat: driver swapped through an option", configure: allow, path: compatPath, body: compat(`{"Type":"json-file","Config":{"Driver":"gelf"}}`), wantStatus: http.StatusForbidden},
		{name: "compat: destination option", configure: allow, path: compatPath, body: compat(`{"Type":"json-file","Config":{"fluentd-address":"tcp://evil:24224"}}`), wantStatus: http.StatusForbidden},
		{name: "compat: log path still needs allow_log_path", configure: func(b *gates) { allow(b) }, path: compatPath, body: compat(`{"Type":"json-file","Config":{"path":"/host/x.log"}}`), wantStatus: http.StatusForbidden},
		{
			name: "compat: allow_log_path does not open an unlisted driver",
			configure: func(b *gates) {
				allow(b)
				b.ContainerCreate.AllowLogPath = true
			},
			path: compatPath, body: compat(`{"Type":"k8s-file","Config":{"path":"/host/x.log"}}`), wantStatus: http.StatusForbidden,
		},
		{
			name: "compat: both gates open",
			configure: func(b *gates) {
				b.ContainerCreate.AllowedLogDrivers = []string{"k8s-file"}
				b.ContainerCreate.AllowLogPath = true
			},
			path: compatPath, body: compat(`{"Type":"k8s-file","Config":{"path":"/host/x.log"}}`), wantStatus: http.StatusCreated, wantSeen: []string{"POST /containers/create"},
		},

		{name: "libpod: any driver with the option off", path: libpodPath, body: libpod(`{"driver":"k8s-file","options":{"gelf-address":"udp://evil:1"}}`), wantStatus: http.StatusCreated, wantSeen: []string{"POST /libpod/containers/create"}},
		{name: "libpod: listed driver", configure: allow, path: libpodPath, body: libpod(`{"driver":"journald","options":{"tag":"web"}}`), wantStatus: http.StatusCreated, wantSeen: []string{"POST /libpod/containers/create"}},
		{name: "libpod: unlisted driver", configure: allow, path: libpodPath, body: libpod(`{"driver":"k8s-file"}`), wantStatus: http.StatusForbidden},
		{name: "libpod: destination option", configure: allow, path: libpodPath, body: libpod(`{"driver":"journald","options":{"loki-url":"https://evil"}}`), wantStatus: http.StatusForbidden},

		{name: "service: any driver with the option off", path: servicePath, body: service(`{"Name":"gelf"}`), wantStatus: http.StatusCreated, wantSeen: []string{"POST /services/create"}},
		{name: "service: listed driver", configure: allow, path: servicePath, body: service(`{"Name":"json-file"}`), wantStatus: http.StatusCreated, wantSeen: []string{"POST /services/create"}},
		{name: "service: unlisted driver", configure: allow, path: servicePath, body: service(`{"Name":"gelf"}`), wantStatus: http.StatusForbidden},
		{name: "service: destination option", configure: allow, path: servicePath, body: service(`{"Name":"json-file","Options":{"splunk-url":"https://evil"}}`), wantStatus: http.StatusForbidden},

		{name: "kube play: any driver with the option off", path: kubePath + "?logDriver=k8s-file", body: kubeYAML, wantStatus: http.StatusCreated, wantSeen: []string{"POST /libpod/play/kube"}},
		{name: "kube play: listed driver", configure: allow, path: kubePath + "?logDriver=journald&logOptions=tag%3Dweb", body: kubeYAML, wantStatus: http.StatusCreated, wantSeen: []string{"POST /libpod/play/kube"}},
		{name: "kube play: no log parameters", configure: allow, path: kubePath + "?start=true", body: kubeYAML, wantStatus: http.StatusCreated, wantSeen: []string{"POST /libpod/play/kube"}},
		{name: "kube play: unlisted driver", configure: allow, path: kubePath + "?logDriver=k8s-file", body: kubeYAML, wantStatus: http.StatusForbidden},
		{name: "kube play: key in capitals", configure: allow, path: kubePath + "?LogDriver=k8s-file", body: kubeYAML, wantStatus: http.StatusForbidden},
		{name: "kube play: destination option", configure: allow, path: kubePath + "?logDriver=journald&logOptions=fluentd-address%3Dtcp%3A%2F%2Fevil%3A1", body: kubeYAML, wantStatus: http.StatusForbidden},
		{name: "kube play alias: unlisted driver", configure: allow, path: "/v6.1.3/libpod/kube/play?logDriver=k8s-file", body: kubeYAML, wantStatus: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &logDriverChainDaemon{}
			addr := newEngineChain(t, "logdriver", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.InsecureAllowBodyBlindWrites = true
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/services/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/play/kube"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/kube/play"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				if tt.configure != nil {
					tt.configure(&cfg.RequestBody)
				}
			})
			status, body := sendNamespaceChainRequest(t, "http://"+addr+tt.path, tt.body)
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
			if got := daemon.reached(); !slices.Equal(got, tt.wantSeen) {
				t.Errorf("daemon saw %q, want %q", got, tt.wantSeen)
			}
		})
	}
}
