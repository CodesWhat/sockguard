package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

const (
	exposureChainProxyID   = "aa11bb22cc33dd44ee55ff6600112233"
	exposureChainBackendID = "bb22cc33dd44ee55ff66001122334455"
)

// exposureChainDaemon answers GET /networks/{ref} the way the daemon resolves a
// reference (name, ID or ID prefix) and records which write routes a request
// reached.
type exposureChainDaemon struct {
	mu   sync.Mutex
	seen []string
}

func (d *exposureChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet && normPath == "/version" {
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
		return
	}
	if ref, ok := strings.CutPrefix(normPath, "/networks/"); r.Method == http.MethodGet && ok {
		name := ""
		switch {
		case ref == "proxy" || strings.HasPrefix(exposureChainProxyID, ref) && len(ref) >= 8:
			name = "proxy"
		case ref == "backend" || strings.HasPrefix(exposureChainBackendID, ref) && len(ref) >= 8:
			name = "backend"
		case ref == "bridge":
			name = "bridge"
		}
		if name == "" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"network not found"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"Name": name, "Driver": "bridge"})
		return
	}
	_, _ = io.Copy(io.Discard, r.Body)
	d.mu.Lock()
	d.seen = append(d.seen, r.Method+" "+normPath)
	d.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"Id":"x"}`))
}

func (d *exposureChainDaemon) reached() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.seen)
}

// TestServeChainNetworkExposure sends creates and connects through the
// production chain with the gates on, for the Traefik-style posture: only the
// proxy network, ports only on 127.0.0.1.
func TestServeChainNetworkExposure(t *testing.T) {
	type gates = config.RequestBodyConfig
	on := func(b *gates) {
		b.ContainerCreate.AllowedNetworks = []string{"proxy"}
		b.ContainerCreate.AllowedPortHostIPs = []string{"127.0.0.1"}
		b.LibpodContainerCreate.AllowedNetworks = []string{"proxy"}
		b.LibpodContainerCreate.DenyPublishedPorts = true
		b.Service.AllowedNetworks = []string{"proxy"}
		b.Service.DenyPublishedPorts = true
	}
	const (
		compatPath  = "/v1.41/containers/create"
		libpodPath  = "/v6.1.3/libpod/containers/create"
		servicePath = "/v1.41/services/create"
	)
	compat := func(mode, ports string) string {
		return `{"Image":"alpine","HostConfig":{"NetworkMode":"` + mode + `"` + ports + `}}`
	}
	bind := func(hostIP string) string {
		return `,"PortBindings":{"80/tcp":[{"HostIp":"` + hostIP + `","HostPort":"8080"}]}`
	}
	service := func(network string) string {
		return `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest"},"Networks":[{"Target":"` + network + `"}]}}`
	}
	created := []string{"POST /containers/create"}
	tests := []struct {
		name       string
		configure  func(*gates)
		path       string
		body       string
		wantStatus int
		wantSeen   []string
	}{
		{name: "compat: gates off", path: compatPath, body: compat("backend", bind("0.0.0.0")), wantStatus: http.StatusCreated, wantSeen: created},
		{name: "compat: proxy network, loopback port", configure: on, path: compatPath, body: compat("proxy", bind("127.0.0.1")), wantStatus: http.StatusCreated, wantSeen: created},
		{name: "compat: proxy network by ID prefix", configure: on, path: compatPath, body: compat(exposureChainProxyID[:12], ""), wantStatus: http.StatusCreated, wantSeen: created},
		{name: "compat: other network", configure: on, path: compatPath, body: compat("backend", ""), wantStatus: http.StatusForbidden},
		{name: "compat: other network by ID", configure: on, path: compatPath, body: compat(exposureChainBackendID, ""), wantStatus: http.StatusForbidden},
		{name: "compat: all-interface port", configure: on, path: compatPath, body: compat("proxy", bind("")), wantStatus: http.StatusForbidden},
		{name: "compat: default bridge", configure: on, path: compatPath, body: compat("default", ""), wantStatus: http.StatusForbidden},
		{name: "compat: joined container namespace", configure: on, path: compatPath, body: compat("container:web", ""), wantStatus: http.StatusForbidden},
		{name: "compat: unknown network", configure: on, path: compatPath, body: compat("nope", ""), wantStatus: http.StatusForbidden},

		{name: "libpod: proxy network", configure: on, path: libpodPath, body: `{"systemd":"false","image":"alpine","networks":{"proxy":{}}}`, wantStatus: http.StatusCreated, wantSeen: []string{"POST /libpod/containers/create"}},
		{name: "libpod: other network", configure: on, path: libpodPath, body: `{"systemd":"false","image":"alpine","networks":{"backend":{}}}`, wantStatus: http.StatusForbidden},
		{name: "libpod: published port", configure: on, path: libpodPath, body: `{"systemd":"false","image":"alpine","networks":{"proxy":{}},"portmappings":[{"host_ip":"127.0.0.1","container_port":80,"host_port":80}]}`, wantStatus: http.StatusForbidden},

		{name: "pod: published port", configure: on, path: "/v6.1.3/libpod/pods/create", body: `{"name":"p1","portmappings":[{"host_ip":"127.0.0.1","container_port":80,"host_port":80}],"networks":{"proxy":{}}}`, wantStatus: http.StatusForbidden},
		{name: "pod: other network", configure: on, path: "/v6.1.3/libpod/pods/create", body: `{"name":"p1","networks":{"backend":{}}}`, wantStatus: http.StatusForbidden},
		{name: "pod: proxy network", configure: on, path: "/v6.1.3/libpod/pods/create", body: `{"name":"p1","networks":{"proxy":{}}}`, wantStatus: http.StatusCreated, wantSeen: []string{"POST /libpod/pods/create"}},
		{name: "kube play refused", configure: on, path: "/v6.1.3/libpod/play/kube", body: "apiVersion: v1\nkind: Pod\n", wantStatus: http.StatusForbidden},
		{name: "kube play alias refused", configure: on, path: "/v6.1.3/libpod/kube/play", body: "apiVersion: v1\nkind: Pod\n", wantStatus: http.StatusForbidden},
		{name: "service: proxy network", configure: on, path: servicePath, body: service("proxy"), wantStatus: http.StatusCreated, wantSeen: []string{"POST /services/create"}},
		{name: "service: other network", configure: on, path: servicePath, body: service("backend"), wantStatus: http.StatusForbidden},
		{name: "service: published port", configure: on, path: servicePath, body: `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest"}},"EndpointSpec":{"Ports":[{"TargetPort":80,"PublishedPort":80}]}}`, wantStatus: http.StatusForbidden},

		{name: "connect: proxy", configure: on, path: "/v1.41/networks/proxy/connect", body: `{"Container":"c1"}`, wantStatus: http.StatusCreated, wantSeen: []string{"POST /networks/proxy/connect"}},
		{name: "connect: other network", configure: on, path: "/v1.41/networks/backend/connect", body: `{"Container":"c1"}`, wantStatus: http.StatusForbidden},
		{name: "connect: other network by ID", configure: on, path: "/v1.41/networks/" + exposureChainBackendID + "/connect", body: `{"Container":"c1"}`, wantStatus: http.StatusForbidden},
		{name: "connect: gates off", path: "/v1.41/networks/backend/connect", body: `{"Container":"c1"}`, wantStatus: http.StatusCreated, wantSeen: []string{"POST /networks/backend/connect"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &exposureChainDaemon{}
			addr := newEngineChain(t, "netexposure", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.InsecureAllowBodyBlindWrites = true
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/services/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/pods/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/play/kube"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/kube/play"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/networks/*/connect"}, Action: "allow"},
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
