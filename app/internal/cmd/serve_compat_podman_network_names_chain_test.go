package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// compatNetworkNamesChainDaemon is a Podman with the networks in networks, each
// mapped to its owner label, behind the Docker-compatible network inspect and
// container create. It records the creates it receives.
type compatNetworkNamesChainDaemon struct {
	networks map[string]string
	mu       sync.Mutex
	created  int
	flavor   bool
}

func (d *compatNetworkNamesChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	norm := apipath.NormalizePath(r.URL.Path)
	switch {
	case r.Method == http.MethodGet && norm == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(d.flavor))
	case r.Method == http.MethodGet && strings.HasPrefix(norm, "/images/"):
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": "sha256:1", "Config": map[string]any{"Labels": map[string]string{}}})
	case r.Method == http.MethodGet && strings.HasPrefix(norm, "/networks/"):
		owner, ok := d.networks[strings.TrimPrefix(norm, "/networks/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		labels := map[string]string{}
		if owner != "" {
			labels["com.sockguard.owner"] = owner
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": "n1", "Labels": labels})
	case r.Method == http.MethodPost && norm == "/containers/create":
		_, _ = io.Copy(io.Discard, r.Body)
		d.mu.Lock()
		d.created++
		d.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"Id":"c1"}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// TestServeChainCompatCreateChecksDockerModeNamesOnPodman sends
// Docker-compatible container creates naming a network the Docker modes would
// have skipped.
//
// Owner isolation skipped the names bridge, host, none, ingress and
// docker_gwbridge on a container create, because on dockerd they're modes or
// Swarm's own networks. Podman reads a NetworkMode other than its own modes
// (bridge, none, host, default, private, pasta, slirp4netns, container:, ns:) as
// a network name, and reads every EndpointsConfig key as one, so there
// ingress and docker_gwbridge are ordinary names anyone can create, and so are
// bridge, host and none as endpoint keys. A create joining another owner's
// network under one of them passed unchecked. On a Podman upstream those
// names are now looked up, and a name nothing holds goes through as before.
func TestServeChainCompatCreateChecksDockerModeNamesOnPodman(t *testing.T) {
	endpoints := func(name string) string {
		return `{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"` + name + `":{}}}}`
	}
	mode := func(name string) string {
		return `{"Image":"alpine","HostConfig":{"NetworkMode":"` + name + `"}}`
	}
	tests := []struct {
		name       string
		podman     bool
		networks   map[string]string
		body       string
		wantStatus int
	}{
		{"endpoint ingress held by another owner", true, map[string]string{"ingress": "team-b"}, endpoints("ingress"), http.StatusForbidden},
		{"endpoint docker_gwbridge held by another owner", true, map[string]string{"docker_gwbridge": "team-b"}, endpoints("docker_gwbridge"), http.StatusForbidden},
		{"endpoint bridge held by another owner", true, map[string]string{"bridge": "team-b"}, endpoints("bridge"), http.StatusForbidden},
		{"endpoint host held by another owner", true, map[string]string{"host": "team-b"}, endpoints("host"), http.StatusForbidden},
		{"endpoint none held by another owner", true, map[string]string{"none": "team-b"}, endpoints("none"), http.StatusForbidden},
		{"network mode ingress held by another owner", true, map[string]string{"ingress": "team-b"}, mode("ingress"), http.StatusForbidden},
		{"network mode docker_gwbridge held by another owner", true, map[string]string{"docker_gwbridge": "team-b"}, mode("docker_gwbridge"), http.StatusForbidden},
		{"endpoint ingress held by the caller", true, map[string]string{"ingress": "team-a"}, endpoints("ingress"), http.StatusCreated},
		{"endpoint ingress nobody holds", true, map[string]string{}, endpoints("ingress"), http.StatusCreated},
		{"endpoint bridge nobody holds", true, map[string]string{}, endpoints("bridge"), http.StatusCreated},
		{"network mode bridge is Podman's own mode", true, map[string]string{"bridge": "team-b"}, mode("bridge"), http.StatusCreated},
		{"network mode default is Podman's own mode", true, map[string]string{"default": "team-b"}, mode("default"), http.StatusCreated},
		{"network mode none is Podman's own mode", true, map[string]string{"none": "team-b"}, mode("none"), http.StatusCreated},
		{"endpoint ingress on dockerd is Swarm's", false, map[string]string{"ingress": "team-b"}, endpoints("ingress"), http.StatusCreated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &compatNetworkNamesChainDaemon{networks: tt.networks, flavor: tt.podman}
			addr := newEngineChain(t, "compat-net-names", daemon, func(cfg *config.Config) {
				cfg.Ownership.Owner = "team-a"
				cfg.Ownership.AllowUnownedImages = true
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			})
			status, body := sendNamespaceChainRequest(t, "http://"+addr+"/v1.45/containers/create", tt.body)
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
			daemon.mu.Lock()
			created := daemon.created
			daemon.mu.Unlock()
			if (created == 1) != (tt.wantStatus == http.StatusCreated) {
				t.Errorf("daemon created %d containers for status %d", created, status)
			}
		})
	}
}
