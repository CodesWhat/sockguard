package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/apipath"
	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

// podmanSchemaBool is the value gorilla/schema leaves in a bool field tagged
// name on Podman's compat routes, visiting spellings in the order
// podmanSchemaKeys gives. NewCompatAPIDecoder registers a converter that
// copies dockerd's httputils.BoolValue, so the last value under each spelling
// is false only for "", "0", "no", "false" and "none" (trimmed, any case) and
// true for everything else. An empty value therefore sets false rather than
// leaving the field alone, and nothing is a conversion error, so ok is always
// true. Read from Podman 5.8.6 pkg/api/handlers/decoder.go.
func podmanSchemaBool(query url.Values, name string) (value, ok bool) {
	for _, key := range podmanSchemaKeys(query, name) {
		values := query[key]
		if len(values) == 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(values[len(values)-1])) {
		case "", "0", "no", "false", "none":
			value = false
		default:
			value = true
		}
	}
	return value, true
}

// dockerdBoolValue is moby's httputils.BoolValue: the first value under the
// exact key, false only for the five spellings below.
func dockerdBoolValue(r *http.Request, name string) bool {
	switch strings.ToLower(strings.TrimSpace(r.FormValue(name))) {
	case "", "0", "no", "false", "none":
		return false
	default:
		return true
	}
}

type containerRemoval struct {
	force   bool
	volumes bool
	link    bool
}

// containerRemoveChainDaemon is DELETE /containers/{name} as each engine
// serves it, and records what each removal actually did.
//
// dockerd reads `force`, `v` and `link` with httputils.BoolValue, which takes
// the first value under the exact key (moby 28.5.1, deleteContainers in
// api/server/router/container/container_routes.go).
//
// Podman's compat.RemoveContainer decodes the same three into bools with
// gorilla/schema, which folds the key's case and keeps the last value, and
// answers a compat request with `link` set with 400 ErrLinkNotSupport. Read
// from Podman 5.8.6 (pkg/api/handlers/compat/containers.go).
type containerRemoveChainDaemon struct {
	podman bool

	mu       sync.Mutex
	removals []containerRemoval
}

func (d *containerRemoveChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(d.podman))
	case r.Method == http.MethodDelete && strings.HasPrefix(normPath, "/containers/"):
		removal, status := d.remove(r)
		if status != http.StatusNoContent {
			w.WriteHeader(status)
			return
		}
		d.mu.Lock()
		d.removals = append(d.removals, removal)
		d.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *containerRemoveChainDaemon) remove(r *http.Request) (containerRemoval, int) {
	if !d.podman {
		_ = r.ParseForm()
		return containerRemoval{
			force:   dockerdBoolValue(r, "force"),
			volumes: dockerdBoolValue(r, "v"),
			link:    dockerdBoolValue(r, "link"),
		}, http.StatusNoContent
	}
	query := r.URL.Query()
	force, forceOK := podmanSchemaBool(query, "force")
	volumes, volumesOK := podmanSchemaBool(query, "v")
	link, linkOK := podmanSchemaBool(query, "link")
	if !forceOK || !volumesOK || !linkOK || link {
		return containerRemoval{}, http.StatusBadRequest
	}
	return containerRemoval{force: force, volumes: volumes}, http.StatusNoContent
}

func (d *containerRemoveChainDaemon) seen() []containerRemoval {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.removals)
}

// TestServeChainContainerRemoveReadsEachFlagOnce sends container removals
// through the production chain to a daemon that reads `force`, `v` and `link`
// the way the engine does.
//
// The inspector read each flag as the first value under the exact lowercase
// key, which is how dockerd reads it. Podman folds the key's case and keeps
// the last value, so on a Podman upstream `?Force=1` or `?force=0&force=1`
// force-removed a running container with allow_force off, and the same shapes
// of `v` deleted its anonymous volumes with allow_remove_volumes off. Every
// case asserts on what the daemon did.
func TestServeChainContainerRemoveReadsEachFlagOnce(t *testing.T) {
	tests := []struct {
		name         string
		podman       bool
		allowAll     bool
		target       string
		wantStatus   int
		wantRemovals []containerRemoval
	}{
		{name: "force on Podman", podman: true, target: "/v1.41/containers/app?force=1", wantStatus: http.StatusForbidden},
		{name: "force in another spelling on Podman", podman: true, target: "/v1.41/containers/app?Force=1", wantStatus: http.StatusForbidden},
		{name: "force behind a false first value on Podman", podman: true, target: "/v1.41/containers/app?force=0&force=1", wantStatus: http.StatusForbidden},
		{name: "percent-encoded force spelling on Podman", podman: true, target: "/v1.41/containers/app?%46orce=true", wantStatus: http.StatusForbidden},
		{name: "shouted force with the converter's on spelling on Podman", podman: true, target: "/v1.41/containers/app?FORCE=on", wantStatus: http.StatusForbidden},
		{name: "volumes in another spelling on Podman", podman: true, target: "/v1.41/containers/app?V=1", wantStatus: http.StatusForbidden},
		{name: "volumes behind a false first value on Podman", podman: true, target: "/v1.41/containers/app?v=false&v=true", wantStatus: http.StatusForbidden},
		{name: "link in another spelling on Podman", podman: true, target: "/v1.41/containers/app?Link=1", wantStatus: http.StatusForbidden},
		{name: "link behind a false first value on Podman", podman: true, target: "/v1.41/containers/app?link=0&link=1", wantStatus: http.StatusForbidden},
		{
			// strings.EqualFold, and so gorilla/schema, matches the Kelvin
			// sign (U+212A) to k.
			name:       "link spelled with a Kelvin sign on Podman",
			podman:     true,
			target:     "/v1.41/containers/app?lin%E2%84%AA=1",
			wantStatus: http.StatusForbidden,
		},
		{
			// dockerd reads the first value, so this one never forced, but
			// sockguard no longer guesses which engine is behind it.
			name:       "repeated force on dockerd",
			target:     "/v1.45/containers/app?force=0&force=1",
			wantStatus: http.StatusForbidden,
		},
		{name: "force in another spelling on dockerd", target: "/v1.45/containers/app?Force=1", wantStatus: http.StatusForbidden},
		{
			name:         "plain remove on Podman",
			podman:       true,
			target:       "/v1.41/containers/app",
			wantStatus:   http.StatusNoContent,
			wantRemovals: []containerRemoval{{}},
		},
		{
			// docker-py sends every flag, once and in lowercase, as Python's
			// str(False).
			name:         "docker-py shape on Podman",
			podman:       true,
			target:       "/v1.41/containers/app?v=False&link=False&force=False",
			wantStatus:   http.StatusNoContent,
			wantRemovals: []containerRemoval{{}},
		},
		{
			name:         "plain remove on dockerd",
			target:       "/v1.45/containers/app",
			wantStatus:   http.StatusNoContent,
			wantRemovals: []containerRemoval{{}},
		},
		{
			name:         "Docker CLI force and volumes when allowed",
			allowAll:     true,
			target:       "/v1.45/containers/app?force=1&v=1",
			wantStatus:   http.StatusNoContent,
			wantRemovals: []containerRemoval{{force: true, volumes: true}},
		},
		{
			name:         "force when allowed on Podman",
			podman:       true,
			allowAll:     true,
			target:       "/v1.41/containers/app?force=true",
			wantStatus:   http.StatusNoContent,
			wantRemovals: []containerRemoval{{force: true}},
		},
		{
			// With the gate open nothing depends on which value wins.
			name:         "repeated force when allowed on Podman",
			podman:       true,
			allowAll:     true,
			target:       "/v1.41/containers/app?force=0&force=1",
			wantStatus:   http.StatusNoContent,
			wantRemovals: []containerRemoval{{force: true}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &containerRemoveChainDaemon{podman: tt.podman}
			addr := newEngineChain(t, "ctr-rm", daemon, func(cfg *config.Config) {
				cfg.RequestBody.ContainerRemove.AllowForce = tt.allowAll
				cfg.RequestBody.ContainerRemove.AllowRemoveVolumes = tt.allowAll
				cfg.RequestBody.ContainerRemove.AllowRemoveLinks = tt.allowAll
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodDelete, Path: "/containers/**"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			})

			status, body := sendChainRequest(t, http.MethodDelete, "http://"+addr+tt.target)
			if removals := daemon.seen(); !slices.Equal(removals, tt.wantRemovals) {
				t.Errorf("daemon removals = %+v, want %+v", removals, tt.wantRemovals)
			}
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
		})
	}
}

// libpodSecretChainDaemon is POST /libpod/secrets/create as Podman serves it.
// libpod.CreateSecret decodes `driver` with gorilla/schema, so the driver a
// secret is stored with is podmanSchemaScalar's answer, and an empty one is
// the configured default. Read from Podman 5.8.6
// (pkg/api/handlers/libpod/secrets.go).
type libpodSecretChainDaemon struct {
	mu      sync.Mutex
	drivers []string
}

func (d *libpodSecretChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
	case r.Method == http.MethodPost && normPath == "/libpod/secrets/create":
		_, _ = io.Copy(io.Discard, r.Body)
		driver := podmanSchemaScalar(r.URL.Query(), "driver")
		if driver == "" {
			driver = "file"
		}
		d.mu.Lock()
		d.drivers = append(d.drivers, driver)
		d.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"ID": "s1"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *libpodSecretChainDaemon) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.drivers)
}

// TestServeChainLibpodSecretCreateReadsDriverOnce sends libpod secret creates
// through the production chain to a daemon that reads `driver` the way Podman
// does.
//
// The inspector read the first value of the exact lowercase key, so with
// allow_custom_drivers off, `?Driver=shell` and `?driver=&driver=shell` both
// stored the secret with a driver the policy refuses. Every case asserts on
// the driver the daemon used.
func TestServeChainLibpodSecretCreateReadsDriverOnce(t *testing.T) {
	tests := []struct {
		name        string
		allow       bool
		target      string
		wantStatus  int
		wantDrivers []string
	}{
		{name: "custom driver", target: "/v5.0.0/libpod/secrets/create?name=s&driver=shell", wantStatus: http.StatusForbidden},
		{name: "custom driver in another spelling", target: "/v5.0.0/libpod/secrets/create?name=s&Driver=shell", wantStatus: http.StatusForbidden},
		{name: "custom driver behind an empty first value", target: "/v5.0.0/libpod/secrets/create?name=s&driver=&driver=shell", wantStatus: http.StatusForbidden},
		{name: "custom driver behind an empty exact spelling", target: "/v5.0.0/libpod/secrets/create?name=s&driver=&DRIVER=pass", wantStatus: http.StatusForbidden},
		{name: "percent-encoded driver spelling", target: "/v5.0.0/libpod/secrets/create?name=s&%44river=shell", wantStatus: http.StatusForbidden},
		{
			name:        "default driver",
			target:      "/v5.0.0/libpod/secrets/create?name=s",
			wantStatus:  http.StatusOK,
			wantDrivers: []string{"file"},
		},
		{
			name:        "empty driver",
			target:      "/v5.0.0/libpod/secrets/create?name=s&driver=",
			wantStatus:  http.StatusOK,
			wantDrivers: []string{"file"},
		},
		{
			// podman-remote sends the containers.conf default once.
			name:        "custom driver when allowed",
			allow:       true,
			target:      "/v5.0.0/libpod/secrets/create?name=s&driver=pass",
			wantStatus:  http.StatusOK,
			wantDrivers: []string{"pass"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &libpodSecretChainDaemon{}
			addr := newEngineChain(t, "pod-sec", daemon, func(cfg *config.Config) {
				cfg.RequestBody.LibpodSecret.AllowCustomDrivers = tt.allow
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/secrets/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			})

			status, body := sendChainRequest(t, http.MethodPost, "http://"+addr+tt.target)
			if drivers := daemon.seen(); !slices.Equal(drivers, tt.wantDrivers) {
				t.Errorf("daemon stored secrets with drivers %q, want %q", drivers, tt.wantDrivers)
			}
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
		})
	}
}

func sendChainRequest(t *testing.T, method, target string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, target, strings.NewReader("c2VjcmV0"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}
