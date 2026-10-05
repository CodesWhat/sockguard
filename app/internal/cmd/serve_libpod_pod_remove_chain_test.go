package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/apipath"
	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

// libpodPodTeardown is one request the Podman-shaped daemon below acted on:
// a pod removal, or a kube down of the YAML in body.
type libpodPodTeardown struct {
	route string
	name  string
	force bool
	body  string
}

// libpodPodRemoveChainDaemon is Podman's DELETE /vX/libpod/pods/{name} and
// its kube down, DELETE /vX/libpod/play/kube and /vX/libpod/kube/play, and
// records what each request tore down.
//
// Podman 5.8.6 registers all three only under a version prefix
// (pkg/api/server/register_pods.go:106, register_kube.go:180-181). The pod
// handler decodes `force` and a uint `timeout` with the libpod decoder
// (pkg/api/handlers/libpod/pods.go:240-254), and kube down decodes `force`
// and reads the YAML from the body (pkg/api/handlers/libpod/kube.go:220-235,
// play.go:13). A value either can't decode is a 400.
//
// owners answers the owner lookup GET /libpod/pods/{name}/json that owner
// isolation makes: the value is the owner label each pod carries.
type libpodPodRemoveChainDaemon struct {
	owners map[string]string

	mu        sync.Mutex
	teardowns []libpodPodTeardown
}

func (d *libpodPodRemoveChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	versioned := normPath != r.URL.Path
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
	case r.Method == http.MethodGet && strings.HasPrefix(normPath, "/libpod/pods/") && strings.HasSuffix(normPath, "/json"):
		name := strings.TrimSuffix(strings.TrimPrefix(normPath, "/libpod/pods/"), "/json")
		owner, ok := d.owners[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id":     name,
			"Name":   name,
			"Labels": map[string]string{"com.sockguard.owner": owner},
		})
	case r.Method == http.MethodDelete && strings.HasPrefix(normPath, "/libpod/pods/") && versioned:
		name := strings.TrimPrefix(normPath, "/libpod/pods/")
		if name == "" || strings.Contains(name, "/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		force, ok := podmanLibpodSchemaBool(r.URL.Query(), "force")
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if timeout := podmanSchemaScalar(r.URL.Query(), "timeout"); timeout != "" {
			if _, err := strconv.ParseUint(timeout, 10, 0); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		d.record(libpodPodTeardown{route: "pod rm", name: name, force: force})
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": name, "RemovedCtrs": map[string]any{}})
	case r.Method == http.MethodDelete && (normPath == "/libpod/play/kube" || normPath == "/libpod/kube/play") && versioned:
		force, ok := podmanLibpodSchemaBool(r.URL.Query(), "force")
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		d.record(libpodPodTeardown{route: normPath, force: force, body: string(body)})
		_ = json.NewEncoder(w).Encode(map[string]any{})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *libpodPodRemoveChainDaemon) record(teardown libpodPodTeardown) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.teardowns = append(d.teardowns, teardown)
}

func (d *libpodPodRemoveChainDaemon) seen() []libpodPodTeardown {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.teardowns)
}

const libpodKubeDownChainYAML = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n"

func sendLibpodPodRemoveChainRequest(t *testing.T, target, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", target, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

// TestServeChainLibpodPodRemoveAppliesTheRemoveGates sends Podman's native pod
// removal and kube down through the production chain to a daemon that decodes
// them the way Podman does, and asserts on what it tore down.
//
// Neither route was inspected, so a rule that allowed them reached the daemon
// with allow_force and allow_remove_volumes off. Without `force`, a pod
// removal refuses a running or paused workload container
// (libpod/runtime_ctr.go:860-864, container_internal.go:2632) and returns
// before the volume step, but a pod whose workloads are all stopped is
// removed along with the anonymous volumes of every container in it, with no
// flag to keep them (libpod/runtime_pod_common.go:256-273). So
// every pod removal needs allow_remove_volumes, and `force`, which stops the
// running ones first, needs allow_force too. Kube down stops every pod its
// YAML names and force-removes them whatever its query says
// (pkg/domain/infra/abi/play.go:1800-1808), so it needs both gates on every
// request. Its own `force` also deletes the named volumes the YAML lists
// (play.go:1818-1819), which is covered once allow_remove_volumes is open.
func TestServeChainLibpodPodRemoveAppliesTheRemoveGates(t *testing.T) {
	type gates struct{ force, volumes bool }
	const (
		podForceReason    = "libpod pod remove denied: force removal is not allowed"
		podVolumesReason  = "libpod pod remove denied: removing a pod deletes its containers' anonymous volumes and is not allowed"
		kubeForceReason   = "libpod kube down denied: tearing down kube YAML force-stops its pods and is not allowed"
		kubeVolumesReason = "libpod kube down denied: tearing down kube YAML deletes its pods' anonymous volumes and is not allowed"
	)
	removeRules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodDelete, Path: "/libpod/pods/*"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodDelete, Path: "/libpod/play/kube"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodDelete, Path: "/libpod/kube/play"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	tests := []struct {
		name          string
		gates         gates
		rules         []config.RuleConfig
		owner         string
		target        string
		wantStatus    int
		wantReason    string
		wantTeardowns []libpodPodTeardown
	}{
		// DELETE /libpod/pods/{name}
		{name: "pod rm", target: "/v5.0.0/libpod/pods/web", wantStatus: http.StatusForbidden, wantReason: podVolumesReason},
		{
			// podman-remote pod rm always sends force, once, in lowercase
			// (pkg/domain/infra/tunnel/pods.go:179, bindings/pods/pods.go:198).
			name:       "podman-remote pod rm shape",
			target:     "/v5.8.6/libpod/pods/web?force=false",
			wantStatus: http.StatusForbidden,
			wantReason: podVolumesReason,
		},
		{name: "pod rm with only force allowed", gates: gates{force: true}, target: "/v5.8.6/libpod/pods/web?force=false", wantStatus: http.StatusForbidden, wantReason: podVolumesReason},
		{name: "pod rm --force with only force allowed", gates: gates{force: true}, target: "/v5.8.6/libpod/pods/web?force=true", wantStatus: http.StatusForbidden, wantReason: podVolumesReason},
		{
			name:          "podman-remote pod rm with volumes allowed",
			gates:         gates{volumes: true},
			target:        "/v5.8.6/libpod/pods/web?force=false",
			wantStatus:    http.StatusOK,
			wantTeardowns: []libpodPodTeardown{{route: "pod rm", name: "web"}},
		},
		{
			name:          "pod rm --time without force",
			gates:         gates{volumes: true},
			target:        "/v5.8.6/libpod/pods/web?force=false&timeout=5",
			wantStatus:    http.StatusOK,
			wantTeardowns: []libpodPodTeardown{{route: "pod rm", name: "web"}},
		},
		{name: "pod rm --force with only volumes allowed", gates: gates{volumes: true}, target: "/v5.8.6/libpod/pods/web?force=true", wantStatus: http.StatusForbidden, wantReason: podForceReason},
		{name: "pod rm --force with nothing allowed", target: "/v5.8.6/libpod/pods/web?force=true", wantStatus: http.StatusForbidden, wantReason: podForceReason},
		{name: "force with the converter's on spelling", gates: gates{volumes: true}, target: "/v5.0.0/libpod/pods/web?force=on", wantStatus: http.StatusForbidden, wantReason: podForceReason},
		{name: "force in another spelling", gates: gates{volumes: true}, target: "/v5.0.0/libpod/pods/web?Force=true", wantStatus: http.StatusForbidden, wantReason: "libpod pod remove denied: ambiguous force query parameter"},
		{name: "force behind a false first value", gates: gates{volumes: true}, target: "/v5.0.0/libpod/pods/web?force=false&force=true", wantStatus: http.StatusForbidden, wantReason: "libpod pod remove denied: ambiguous force query parameter"},
		{
			name:          "podman-remote pod rm --force with both gates open",
			gates:         gates{force: true, volumes: true},
			target:        "/v5.8.6/libpod/pods/web?force=true&timeout=10",
			wantStatus:    http.StatusOK,
			wantTeardowns: []libpodPodTeardown{{route: "pod rm", name: "web", force: true}},
		},
		{
			// With the gates open nothing depends on which value wins.
			name:          "repeated force with both gates open",
			gates:         gates{force: true, volumes: true},
			target:        "/v5.0.0/libpod/pods/web?force=false&Force=true",
			wantStatus:    http.StatusOK,
			wantTeardowns: []libpodPodTeardown{{route: "pod rm", name: "web", force: true}},
		},
		{name: "pod rm under the default rules", rules: config.Defaults().Rules, gates: gates{force: true, volumes: true}, target: "/v5.8.6/libpod/pods/web?force=true", wantStatus: http.StatusForbidden, wantReason: "no matching allow rule"},
		{
			name:       "another owner's pod under owner isolation",
			owner:      "team-a",
			gates:      gates{force: true, volumes: true},
			target:     "/v5.8.6/libpod/pods/theirs?force=true",
			wantStatus: http.StatusForbidden,
			wantReason: "libpod owner policy denied access to pod",
		},
		{
			name:          "own pod under owner isolation",
			owner:         "team-a",
			gates:         gates{volumes: true},
			target:        "/v5.8.6/libpod/pods/mine?force=false",
			wantStatus:    http.StatusOK,
			wantTeardowns: []libpodPodTeardown{{route: "pod rm", name: "mine"}},
		},
		{name: "own pod rm without the volumes gate under owner isolation", owner: "team-a", target: "/v5.8.6/libpod/pods/mine?force=false", wantStatus: http.StatusForbidden, wantReason: podVolumesReason},

		// DELETE /libpod/play/kube, /libpod/kube/play
		{
			// podman-remote kube down always sends force, once, in lowercase,
			// on the play/kube spelling (pkg/domain/infra/tunnel/kube.go:83,
			// bindings/kube/kube.go:117).
			name:       "podman-remote kube down shape",
			target:     "/v5.8.6/libpod/play/kube?force=false",
			wantStatus: http.StatusForbidden,
			wantReason: kubeForceReason,
		},
		{name: "kube down alias", target: "/v5.8.6/libpod/kube/play?force=false", wantStatus: http.StatusForbidden, wantReason: kubeForceReason},
		{name: "kube down with only force allowed", gates: gates{force: true}, target: "/v5.8.6/libpod/play/kube?force=false", wantStatus: http.StatusForbidden, wantReason: kubeVolumesReason},
		{name: "kube down alias with only force allowed", gates: gates{force: true}, target: "/v5.8.6/libpod/kube/play", wantStatus: http.StatusForbidden, wantReason: kubeVolumesReason},
		{name: "kube down with only volumes allowed", gates: gates{volumes: true}, target: "/v5.8.6/libpod/play/kube?force=false", wantStatus: http.StatusForbidden, wantReason: kubeForceReason},
		{
			name:          "podman-remote kube down with both gates open",
			gates:         gates{force: true, volumes: true},
			target:        "/v5.8.6/libpod/play/kube?force=false",
			wantStatus:    http.StatusOK,
			wantTeardowns: []libpodPodTeardown{{route: "/libpod/play/kube", body: libpodKubeDownChainYAML}},
		},
		{
			name:          "podman-remote kube down --force with both gates open",
			gates:         gates{force: true, volumes: true},
			target:        "/v5.8.6/libpod/play/kube?force=true",
			wantStatus:    http.StatusOK,
			wantTeardowns: []libpodPodTeardown{{route: "/libpod/play/kube", force: true, body: libpodKubeDownChainYAML}},
		},
		{
			name:          "kube down alias with both gates open",
			gates:         gates{force: true, volumes: true},
			target:        "/v5.8.6/libpod/kube/play?force=true",
			wantStatus:    http.StatusOK,
			wantTeardowns: []libpodPodTeardown{{route: "/libpod/kube/play", force: true, body: libpodKubeDownChainYAML}},
		},
		{name: "kube down under the default rules", rules: config.Defaults().Rules, gates: gates{force: true, volumes: true}, target: "/v5.8.6/libpod/play/kube?force=false", wantStatus: http.StatusForbidden, wantReason: "no matching allow rule"},
		{
			// The YAML names its pods, secrets and volumes in a body owner
			// isolation doesn't parse, so there's nothing to check an owner
			// against and the teardown is refused.
			name:       "kube down under owner isolation",
			owner:      "team-a",
			gates:      gates{force: true, volumes: true},
			target:     "/v5.8.6/libpod/play/kube?force=false",
			wantStatus: http.StatusForbidden,
			wantReason: "libpod kube down denied: DELETE /libpod/play/kube and /libpod/kube/play remove the pods, secrets and volumes named in a YAML body",
		},
		{
			name:       "kube down alias under owner isolation",
			owner:      "team-a",
			gates:      gates{force: true, volumes: true},
			target:     "/v5.8.6/libpod/kube/play?force=true",
			wantStatus: http.StatusForbidden,
			wantReason: "libpod kube down denied: DELETE /libpod/play/kube and /libpod/kube/play remove the pods, secrets and volumes named in a YAML body",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &libpodPodRemoveChainDaemon{owners: map[string]string{"mine": "team-a", "theirs": "team-b"}}
			addr := newEngineChain(t, "libpod-pod-rm", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.Ownership.Owner = tt.owner
				cfg.RequestBody.ContainerRemove.AllowForce = tt.gates.force
				cfg.RequestBody.ContainerRemove.AllowRemoveVolumes = tt.gates.volumes
				cfg.Rules = removeRules
				if tt.rules != nil {
					cfg.Rules = tt.rules
				}
			})

			body := ""
			if parsed, err := url.Parse(tt.target); err == nil && !strings.Contains(parsed.Path, "/pods/") {
				body = libpodKubeDownChainYAML
			}
			status, respBody := sendLibpodPodRemoveChainRequest(t, "http://"+addr+tt.target, body)
			if teardowns := daemon.seen(); !slices.Equal(teardowns, tt.wantTeardowns) {
				t.Errorf("daemon teardowns = %+v, want %+v", teardowns, tt.wantTeardowns)
			}
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, respBody)
			}
			if tt.wantStatus == http.StatusForbidden && tt.wantReason == "" {
				t.Fatal("a denied case must name the reason it is denied for")
			}
			if tt.wantReason != "" {
				// The filter names its reason in `reason`, and owner
				// isolation, which answers after it, in `message`.
				var denial struct {
					Reason  string `json:"reason"`
					Message string `json:"message"`
				}
				if err := json.Unmarshal(respBody, &denial); err != nil || !strings.HasPrefix(denial.Reason+denial.Message, tt.wantReason) {
					t.Errorf("body = %s, want a reason starting with %q", respBody, tt.wantReason)
				}
			}
		})
	}
}
