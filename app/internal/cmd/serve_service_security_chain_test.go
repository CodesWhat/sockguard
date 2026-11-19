package cmd

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/apipath"
	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

const serviceChainHostNetworkID = "9f1c5b7d2a0e4c3b8d6a1f2e3c4b5a69aa00112233445566778899aabbccddee"

// serviceChainDaemon models the swarm manager: the host network is readable by
// full ID, ID prefix and name, a tenant overlay by name, and everything else is
// unknown. It counts the service writes that reach it.
type serviceChainDaemon struct {
	netLookupFails bool
	// netLookupFailStatus is the status a failing lookup answers with, with a
	// JSON error body. Zero means 500.
	netLookupFailStatus int
	// previousTarget, when set, is the network target of the stored
	// PreviousSpec that GET /services/{id} reports, at version index 1.
	previousTarget string
	// serviceInspectFails makes GET /services/{id} answer 500.
	serviceInspectFails bool
	reached             atomic.Int32
}

func (d *serviceChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := apipath.NormalizePath(r.URL.Path)
	switch {
	case r.Method == http.MethodGet && path == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(false))
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/services/"):
		if d.serviceInspectFails {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"boom"}`))
			return
		}
		doc := map[string]any{"ID": "web", "Version": map[string]int{"Index": 1}, "Spec": map[string]any{}}
		if d.previousTarget != "" {
			doc["PreviousSpec"] = map[string]any{"TaskTemplate": map[string]any{"Networks": []map[string]string{{"Target": d.previousTarget}}}}
		}
		_ = json.NewEncoder(w).Encode(doc)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/networks/"):
		if d.netLookupFails {
			w.WriteHeader(d.netLookupStatus())
			_, _ = w.Write([]byte(`{"message":"boom"}`))
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

func (d *serviceChainDaemon) netLookupStatus() int {
	if d.netLookupFailStatus != 0 {
		return d.netLookupFailStatus
	}
	return http.StatusInternalServerError
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
		failStatus int
		// previous is the stored PreviousSpec network target the daemon reports.
		previous string
		// failInspect makes the service inspect fail.
		failInspect bool
		wantStatus  int
		wantReach   bool
	}{
		{name: "full ID create", path: "/v1.45/services/create", body: svc(`{"Target":"` + serviceChainHostNetworkID + `"}`), wantStatus: http.StatusForbidden},
		{name: "ID prefix create", path: "/v1.45/services/create", body: svc(`{"Target":"` + serviceChainHostNetworkID[:12] + `"}`), wantStatus: http.StatusForbidden},
		{name: "full ID update", path: "/v1.45/services/web/update?version=1", body: svc(`{"Target":"` + serviceChainHostNetworkID + `"}`), wantStatus: http.StatusForbidden},
		{name: "create with rollback=previous full ID", path: "/v1.45/services/create?rollback=previous", body: svc(`{"Target":"` + serviceChainHostNetworkID + `"}`), wantStatus: http.StatusForbidden},
		{name: "manual rollback to a PreviousSpec on the host network ID", path: "/v1.45/services/web/update?version=1&rollback=previous", body: `{}`, previous: serviceChainHostNetworkID, wantStatus: http.StatusForbidden},
		{name: "manual rollback to a PreviousSpec on an overlay reaches the daemon", path: "/v1.45/services/web/update?version=1&rollback=previous", body: `{}`, previous: "app-net", wantStatus: http.StatusCreated, wantReach: true},
		{name: "manual rollback fails closed when the service inspect fails", path: "/v1.45/services/web/update?version=1&rollback=previous", body: `{}`, failInspect: true, wantStatus: http.StatusBadGateway},
		{name: "manual rollback fails closed when the network lookup fails", path: "/v1.45/services/web/update?version=1&rollback=previous", body: `{}`, previous: "app-net", failLookup: true, wantStatus: http.StatusBadGateway},
		{name: "literal host create", path: "/v1.45/services/create", body: svc(`{"Target":"host"}`), wantStatus: http.StatusForbidden},
		{name: "overlay by name reaches the daemon", path: "/v1.45/services/create", body: svc(`{"Target":"app-net"}`), wantStatus: http.StatusCreated, wantReach: true},
		{name: "unknown network reaches the daemon", path: "/v1.45/services/create", body: svc(`{"Target":"nope"}`), wantStatus: http.StatusCreated, wantReach: true},
		{name: "lookup error fails closed", path: "/v1.45/services/create", body: svc(`{"Target":"app-net"}`), failLookup: true, wantStatus: http.StatusBadGateway},
		{name: "lookup 503 fails closed", path: "/v1.45/services/create", body: svc(`{"Target":"app-net"}`), failLookup: true, failStatus: http.StatusServiceUnavailable, wantStatus: http.StatusBadGateway},
		{name: "lookup 401 fails closed", path: "/v1.45/services/create", body: svc(`{"Target":"app-net"}`), failLookup: true, failStatus: http.StatusUnauthorized, wantStatus: http.StatusBadGateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &serviceChainDaemon{netLookupFails: tt.failLookup, netLookupFailStatus: tt.failStatus, previousTarget: tt.previous, serviceInspectFails: tt.failInspect}
			addr := portainerPresetChain(t, daemon, nil)
			status, reason := postServiceThroughChain(t, addr, tt.path, tt.body)
			if status != tt.wantStatus || (daemon.reached.Load() > 0) != tt.wantReach {
				t.Fatalf("status = %d reason = %q reached = %d, want %d reach=%t", status, reason, daemon.reached.Load(), tt.wantStatus, tt.wantReach)
			}
		})
	}
}

// TestServeChainServiceMountTemplates pins that the portainer preset refuses
// SwarmKit template expressions that would expand into a host path after the
// request was judged, while a templated volume name still reaches the daemon.
func TestServeChainServiceMountTemplates(t *testing.T) {
	svc := func(mount string) string {
		return `{"Name":"web","TaskTemplate":{"ContainerSpec":{"Image":"alpine","Mounts":[` + mount + `]}}}`
	}
	nfsVolume := func(options string) string {
		return `{"Type":"volume","Source":"data","Target":"/d","VolumeOptions":{"DriverConfig":{"Name":"local","Options":` + options + `}}}`
	}
	const (
		create = "/v1.45/services/create"
		update = "/v1.45/services/web/update?version=1"
	)
	tests := []struct {
		name       string
		path       string
		body       string
		wantReason string // empty means it reaches the daemon
	}{
		{name: "bind source template", path: create, body: svc(`{"Type":"bind","Source":"{{print \"/\"}}","Target":"/h"}`), wantReason: "template expressions"},
		{name: "allowlisted prefix expanding to root", path: create, body: svc(`{"Type":"bind","Source":"/srv/data/{{\"..\"}}/{{\"..\"}}","Target":"/h"}`), wantReason: "template expressions"},
		{name: "allowlisted prefix expanding to root on update", path: update, body: svc(`{"Type":"bind","Source":"/srv/data/{{\"..\"}}/{{\"..\"}}","Target":"/h"}`), wantReason: "template expressions"},
		{name: "nfs o template hides a bind of root", path: create, body: svc(nfsVolume(`{"type":"nfs","o":"{{\"bind\"}}","device":"/"}`)), wantReason: "template expressions"},
		{name: "relative bind source", path: create, body: svc(`{"Type":"bind","Source":"etc","Target":"/h"}`), wantReason: "absolute path"},
		{name: "allowlisted bind reaches the daemon", path: create, body: svc(`{"Type":"bind","Source":"/srv/data/app","Target":"/h"}`)},
		{name: "templated volume name reaches the daemon", path: create, body: svc(`{"Type":"volume","Source":"{{.Service.Name}}-{{.Task.Slot}}","Target":"/d"}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &serviceChainDaemon{}
			addr := portainerPresetChain(t, daemon, func(cfg *config.Config) {
				cfg.RequestBody.Service.AllowAllRegistries = true
				cfg.RequestBody.Service.AllowedBindMounts = []string{"/srv/data"}
			})
			status, reason := postServiceThroughChain(t, addr, tt.path, tt.body)
			if tt.wantReason == "" {
				if status != http.StatusCreated || daemon.reached.Load() != 1 {
					t.Fatalf("status = %d reason = %q reached = %d, want 201 reaching the daemon", status, reason, daemon.reached.Load())
				}
				return
			}
			if status != http.StatusForbidden || !strings.Contains(reason, tt.wantReason) || daemon.reached.Load() != 0 {
				t.Fatalf("status = %d reason = %q reached = %d, want 403 containing %q", status, reason, daemon.reached.Load(), tt.wantReason)
			}
		})
	}
}
