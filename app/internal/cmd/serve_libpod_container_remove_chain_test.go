package cmd

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/config"
)

// podmanLibpodSchemaBool is the value gorilla/schema leaves in a bool field
// tagged name on Podman's libpod routes, visiting spellings in the order
// podmanSchemaKeys gives. The libpod decoder (NewAPIDecoder) registers no bool
// converter, so the field goes through gorilla/schema v1.4.1's own
// convertBool: "on" is true, anything strconv.ParseBool reads is that value,
// an empty value leaves the field alone, and every other value is a
// conversion error, which the handler answers with 400. Read from Podman 5.8.6
// pkg/api/handlers/decoder.go and gorilla/schema v1.4.1 converter.go.
func podmanLibpodSchemaBool(query url.Values, name string) (value, ok bool) {
	for _, key := range podmanSchemaKeys(query, name) {
		values := query[key]
		if len(values) == 0 {
			continue
		}
		raw := values[len(values)-1]
		switch raw {
		case "":
		case "on":
			value = true
		default:
			parsed, err := strconv.ParseBool(raw)
			if err != nil {
				return false, false
			}
			value = parsed
		}
	}
	return value, true
}

type libpodContainerRemoval struct {
	name    string
	force   bool
	volumes bool
	depend  bool
}

// libpodContainerRemoveChainDaemon is Podman's DELETE /vX/libpod/containers/{name},
// and records what each removal actually did.
//
// Podman registers the route only under a version prefix, on the same
// compat.RemoveContainer handler as the Docker-compatible one
// (pkg/api/server/register_containers.go:894). The handler decodes `force`,
// `ignore`, `depend`, `link`, `timeout`, `v` and `volumes` with the libpod
// decoder, and on a libpod request takes the volumes flag from `volumes` and
// ignores `v` and `link` (pkg/api/handlers/compat/containers.go:38-71). A
// value any of them can't decode is a 400. Read from Podman 5.8.6.
//
// owners answers the owner lookup GET /containers/{name}/json that owner
// isolation makes: the value is the owner label each container carries.
type libpodContainerRemoveChainDaemon struct {
	owners map[string]string

	mu       sync.Mutex
	removals []libpodContainerRemoval
}

func (d *libpodContainerRemoveChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	versioned := normPath != r.URL.Path
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
	case r.Method == http.MethodGet && strings.HasPrefix(normPath, "/containers/") && strings.HasSuffix(normPath, "/json"):
		name := strings.TrimSuffix(strings.TrimPrefix(normPath, "/containers/"), "/json")
		owner, ok := d.owners[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id":     name,
			"Config": map[string]any{"Labels": map[string]string{"com.sockguard.owner": owner}},
		})
	case r.Method == http.MethodDelete && strings.HasPrefix(normPath, "/libpod/containers/") && versioned:
		name := strings.TrimPrefix(normPath, "/libpod/containers/")
		if name == "" || strings.Contains(name, "/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		removal, ok := d.decode(r.URL.Query())
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		removal.name = name
		d.mu.Lock()
		d.removals = append(d.removals, removal)
		d.mu.Unlock()
		_ = json.NewEncoder(w).Encode([]map[string]string{{"Id": name}})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *libpodContainerRemoveChainDaemon) decode(query url.Values) (libpodContainerRemoval, bool) {
	var removal libpodContainerRemoval
	var ok bool
	if removal.force, ok = podmanLibpodSchemaBool(query, "force"); !ok {
		return removal, false
	}
	if removal.volumes, ok = podmanLibpodSchemaBool(query, "volumes"); !ok {
		return removal, false
	}
	if removal.depend, ok = podmanLibpodSchemaBool(query, "depend"); !ok {
		return removal, false
	}
	for _, ignored := range []string{"ignore", "link", "v"} {
		if _, ok := podmanLibpodSchemaBool(query, ignored); !ok {
			return removal, false
		}
	}
	if timeout := podmanSchemaScalar(query, "timeout"); timeout != "" {
		if _, err := strconv.ParseUint(timeout, 10, 0); err != nil {
			return removal, false
		}
	}
	return removal, true
}

func (d *libpodContainerRemoveChainDaemon) seen() []libpodContainerRemoval {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.removals)
}

// TestServeChainLibpodContainerRemoveAppliesTheRemoveGates sends Podman's
// native container removals through the production chain to a daemon that
// decodes the query the way Podman does, and asserts on what it removed.
//
// The remove gates only matched the Docker-compatible DELETE /containers/{id}.
// The libpod spelling went to the daemon with its query unread, so a rule that
// allowed DELETE /libpod/containers/* force-removed a running container with
// allow_force off and deleted its anonymous volumes with allow_remove_volumes
// off. The libpod route takes the volumes flag from `volumes`, not `v`, and
// `depend` removes every container that depends on the target. When the
// target is a pod's infra container or a kube service container, that removes
// the pod, and Podman deletes the anonymous volumes of every container in it
// whatever `volumes` says (libpod/runtime_ctr.go:837, runtime_pod_common.go:256), so `depend`
// sits behind allow_remove_volumes too. `timeout` only applies to a forced
// stop and `ignore` only hides a missing container, so neither is gated.
func TestServeChainLibpodContainerRemoveAppliesTheRemoveGates(t *testing.T) {
	type gates struct{ force, volumes bool }
	libpodRemoveRules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodDelete, Path: "/libpod/containers/*"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	tests := []struct {
		name         string
		gates        gates
		rules        []config.RuleConfig
		owner        string
		target       string
		wantStatus   int
		wantReason   string
		wantRemovals []libpodContainerRemoval
	}{
		{
			name:         "plain remove",
			target:       "/v5.0.0/libpod/containers/app",
			wantStatus:   http.StatusOK,
			wantRemovals: []libpodContainerRemoval{{name: "app"}},
		},
		{
			// podman-remote rm sends all four, once, in lowercase
			// (pkg/domain/infra/tunnel/containers.go:248).
			name:         "podman-remote rm shape",
			target:       "/v5.8.6/libpod/containers/app?depend=false&force=false&ignore=false&volumes=false",
			wantStatus:   http.StatusOK,
			wantRemovals: []libpodContainerRemoval{{name: "app"}},
		},
		{
			name:         "timeout without force",
			target:       "/v5.0.0/libpod/containers/app?timeout=5&ignore=true",
			wantStatus:   http.StatusOK,
			wantRemovals: []libpodContainerRemoval{{name: "app"}},
		},
		{name: "force", target: "/v5.0.0/libpod/containers/app?force=true", wantStatus: http.StatusForbidden, wantReason: "container remove denied: force removal is not allowed"},
		{name: "force with the converter's on spelling", target: "/v5.0.0/libpod/containers/app?force=on", wantStatus: http.StatusForbidden, wantReason: "container remove denied: force removal is not allowed"},
		{name: "force on another API version", target: "/v4.9.3/libpod/containers/app?force=1", wantStatus: http.StatusForbidden, wantReason: "container remove denied: force removal is not allowed"},
		{
			// Podman 5.8.6 answers this path with 404, but sockguard serves
			// it as the same libpod removal.
			name:       "force on the unversioned path",
			target:     "/libpod/containers/app?force=1",
			wantStatus: http.StatusForbidden,
			wantReason: "container remove denied: force removal is not allowed",
		},
		{name: "force in another spelling", target: "/v5.0.0/libpod/containers/app?Force=true", wantStatus: http.StatusForbidden, wantReason: "container remove denied: ambiguous force query parameter"},
		{name: "force behind a false first value", target: "/v5.0.0/libpod/containers/app?force=false&force=true", wantStatus: http.StatusForbidden, wantReason: "container remove denied: ambiguous force query parameter"},
		{name: "volumes", target: "/v5.0.0/libpod/containers/app?volumes=true", wantStatus: http.StatusForbidden, wantReason: "container remove denied: anonymous volume removal is not allowed"},
		{name: "volumes in another spelling", target: "/v5.0.0/libpod/containers/app?Volumes=true", wantStatus: http.StatusForbidden, wantReason: "container remove denied: ambiguous volumes query parameter"},
		{
			// The swagger documents `v` on this route and the 5.8.6 handler
			// ignores it, so it is refused as the volumes flag it claims to be.
			name:       "Docker volumes flag on the libpod route",
			target:     "/v5.0.0/libpod/containers/app?v=true",
			wantStatus: http.StatusForbidden,
			wantReason: "container remove denied: anonymous volume removal is not allowed",
		},
		{name: "depend", target: "/v5.0.0/libpod/containers/app?depend=true", wantStatus: http.StatusForbidden, wantReason: "container remove denied: removing dependent containers can delete anonymous volumes and is not allowed"},
		{
			// podman-remote rm --all always sends depend=true.
			name:       "podman-remote rm --all shape",
			target:     "/v5.8.6/libpod/containers/app?depend=true&force=false&ignore=false&volumes=false",
			wantStatus: http.StatusForbidden,
			wantReason: "container remove denied: removing dependent containers can delete anonymous volumes and is not allowed",
		},
		{
			// podman-remote's cleanup after run --rm asks for the volumes too.
			name:       "podman-remote run --rm cleanup shape",
			target:     "/v5.8.6/libpod/containers/app?force=false&volumes=true",
			wantStatus: http.StatusForbidden,
			wantReason: "container remove denied: anonymous volume removal is not allowed",
		},
		{name: "depend with only force allowed", gates: gates{force: true}, target: "/v5.0.0/libpod/containers/app?force=true&depend=true", wantStatus: http.StatusForbidden, wantReason: "container remove denied: removing dependent containers can delete anonymous volumes and is not allowed"},
		{
			name:         "force with only force allowed",
			gates:        gates{force: true},
			target:       "/v5.0.0/libpod/containers/app?force=true",
			wantStatus:   http.StatusOK,
			wantRemovals: []libpodContainerRemoval{{name: "app", force: true}},
		},
		{name: "volumes with only force allowed", gates: gates{force: true}, target: "/v5.0.0/libpod/containers/app?force=true&volumes=true", wantStatus: http.StatusForbidden, wantReason: "container remove denied: anonymous volume removal is not allowed"},
		{name: "force with only volumes allowed", gates: gates{volumes: true}, target: "/v5.0.0/libpod/containers/app?volumes=true&force=true", wantStatus: http.StatusForbidden, wantReason: "container remove denied: force removal is not allowed"},
		{
			name:         "podman-remote rm --force --volumes --depend with both gates open",
			gates:        gates{force: true, volumes: true},
			target:       "/v5.8.6/libpod/containers/app?depend=true&force=true&ignore=false&volumes=true",
			wantStatus:   http.StatusOK,
			wantRemovals: []libpodContainerRemoval{{name: "app", force: true, volumes: true, depend: true}},
		},
		{
			// With the gates open nothing depends on which value wins.
			name:         "repeated force with both gates open",
			gates:        gates{force: true, volumes: true},
			target:       "/v5.0.0/libpod/containers/app?force=false&Force=true",
			wantStatus:   http.StatusOK,
			wantRemovals: []libpodContainerRemoval{{name: "app", force: true}},
		},
		{
			name:       "default rules",
			rules:      config.Defaults().Rules,
			target:     "/v5.0.0/libpod/containers/app?force=true",
			wantStatus: http.StatusForbidden,
			wantReason: "no matching allow rule",
		},
		{
			name:       "another owner's container under owner isolation",
			owner:      "team-a",
			gates:      gates{force: true, volumes: true},
			target:     "/v5.0.0/libpod/containers/theirs",
			wantStatus: http.StatusForbidden,
			wantReason: "libpod owner policy denied access to container",
		},
		{
			name:         "own container under owner isolation",
			owner:        "team-a",
			target:       "/v5.0.0/libpod/containers/mine",
			wantStatus:   http.StatusOK,
			wantRemovals: []libpodContainerRemoval{{name: "mine"}},
		},
		{
			name:       "force on own container under owner isolation",
			owner:      "team-a",
			target:     "/v5.0.0/libpod/containers/mine?force=true",
			wantStatus: http.StatusForbidden,
			wantReason: "container remove denied: force removal is not allowed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &libpodContainerRemoveChainDaemon{owners: map[string]string{"mine": "team-a", "theirs": "team-b"}}
			addr := newEngineChain(t, "libpod-rm", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.Ownership.Owner = tt.owner
				cfg.RequestBody.ContainerRemove.AllowForce = tt.gates.force
				cfg.RequestBody.ContainerRemove.AllowRemoveVolumes = tt.gates.volumes
				cfg.Rules = libpodRemoveRules
				if tt.rules != nil {
					cfg.Rules = tt.rules
				}
			})

			status, body := sendChainRequest(t, http.MethodDelete, "http://"+addr+tt.target)
			if removals := daemon.seen(); !slices.Equal(removals, tt.wantRemovals) {
				t.Errorf("daemon removals = %+v, want %+v", removals, tt.wantRemovals)
			}
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
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
				if err := json.Unmarshal(body, &denial); err != nil || !strings.HasPrefix(denial.Reason+denial.Message, tt.wantReason) {
					t.Errorf("body = %s, want a reason starting with %q", body, tt.wantReason)
				}
			}
		})
	}
}
