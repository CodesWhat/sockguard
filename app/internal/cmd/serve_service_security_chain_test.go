package cmd

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

const serviceChainHostNetworkID = "9f1c5b7d2a0e4c3b8d6a1f2e3c4b5a69aa00112233445566778899aabbccddee"

// serviceChainDaemon models the swarm manager: the host network is readable by
// full ID, ID prefix and name, a tenant overlay by name, and everything else is
// unknown. It counts the service writes that reach it.
type serviceChainDaemon struct {
	netLookupFails bool
	reached        atomic.Int32
}

func (d *serviceChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := apipath.NormalizePath(r.URL.Path)
	switch {
	case r.Method == http.MethodGet && path == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(false))
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/networks/"):
		if d.netLookupFails {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch strings.TrimPrefix(path, "/networks/") {
		case "host", serviceChainHostNetworkID, serviceChainHostNetworkID[:12]:
			_ = json.NewEncoder(w).Encode(map[string]string{"Id": serviceChainHostNetworkID, "Name": "host", "Driver": "host"})
		case "app-net":
			_ = json.NewEncoder(w).Encode(map[string]string{"Id": "ffff", "Name": "app-net", "Driver": "overlay"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	case r.Method == http.MethodPost:
		d.reached.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"ID": "svc1"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// portainerPresetChain serves daemon behind the shipped portainer preset.
func portainerPresetChain(t *testing.T, daemon http.Handler, tweak func(*config.Config)) string {
	t.Helper()
	return newEngineChain(t, "svcsec", daemon, func(cfg *config.Config) {
		loaded, err := config.Load(filepath.Join("..", "..", "configs", "portainer.yaml"))
		if err != nil {
			t.Fatalf("load portainer preset: %v", err)
		}
		socket := cfg.Upstream.Socket
		*cfg = *loaded
		cfg.Upstream.Socket = socket
		cfg.Health.Enabled = false
		cfg.Log.AccessLog = false
		cfg.Response.DenyVerbosity = "verbose"
		if tweak != nil {
			tweak(cfg)
		}
	})
}

func postServiceThroughChain(t *testing.T, addr, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var denial struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&denial)
	return resp.StatusCode, denial.Reason
}

// TestServeChainServiceHostNetworkByID pins that the portainer preset's
// service host-network deny holds when the target is the host network's ID,
// an ID prefix or the name, not only the literal "host".
func TestServeChainServiceHostNetworkByID(t *testing.T) {
	svc := func(networks string) string {
		return `{"Name":"web","TaskTemplate":{"ContainerSpec":{"Image":"alpine"},"Networks":[` + networks + `]}}`
	}
	tests := []struct {
		name       string
		path       string
		body       string
		failLookup bool
		wantStatus int
		wantReach  bool
	}{
		{name: "full ID create", path: "/v1.45/services/create", body: svc(`{"Target":"` + serviceChainHostNetworkID + `"}`), wantStatus: http.StatusForbidden},
		{name: "ID prefix create", path: "/v1.45/services/create", body: svc(`{"Target":"` + serviceChainHostNetworkID[:12] + `"}`), wantStatus: http.StatusForbidden},
		{name: "full ID update", path: "/v1.45/services/web/update?version=1", body: svc(`{"Target":"` + serviceChainHostNetworkID + `"}`), wantStatus: http.StatusForbidden},
		{name: "literal host create", path: "/v1.45/services/create", body: svc(`{"Target":"host"}`), wantStatus: http.StatusForbidden},
		{name: "overlay by name reaches the daemon", path: "/v1.45/services/create", body: svc(`{"Target":"app-net"}`), wantStatus: http.StatusCreated, wantReach: true},
		{name: "unknown network reaches the daemon", path: "/v1.45/services/create", body: svc(`{"Target":"nope"}`), wantStatus: http.StatusCreated, wantReach: true},
		{name: "lookup error fails closed", path: "/v1.45/services/create", body: svc(`{"Target":"app-net"}`), failLookup: true, wantStatus: http.StatusBadGateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &serviceChainDaemon{netLookupFails: tt.failLookup}
			addr := portainerPresetChain(t, daemon, nil)
			status, reason := postServiceThroughChain(t, addr, tt.path, tt.body)
			if status != tt.wantStatus || (daemon.reached.Load() > 0) != tt.wantReach {
				t.Fatalf("status = %d reason = %q reached = %d, want %d reach=%t", status, reason, daemon.reached.Load(), tt.wantStatus, tt.wantReach)
			}
		})
	}
}
