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

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/config"
)

// podmanFileDriverDefaultPath is where Podman's file driver writes secret
// data when the request names no `path`: the secrets directory under the
// storage graph root, plus "filedriver".
const podmanFileDriverDefaultPath = "/var/lib/containers/storage/secrets/filedriver"

// secretCreateChainDaemon stores a secret wherever each engine would, and
// records where every one went.
//
// Podman serves POST /vX/libpod/secrets/create and the compat POST
// /secrets/create. The libpod handler decodes `driver` and `driveropts`
// from the query with gorilla/schema, `driveropts` being a JSON object
// (convertStringMap). The compat handler reads a JSON body and passes on
// Driver.Name only, never Driver.Options. Both then hand the request to
// abi.SecretCreate, which fills an empty driver with the containers.conf
// default ("file", with no options), and the file driver writes under its
// `path` option or the default directory. Read from Podman 5.8.6
// pkg/api/handlers/libpod/secrets.go, pkg/api/handlers/compat/secrets.go,
// pkg/api/handlers/decoder.go and pkg/domain/infra/abi/secrets.go, and
// go.podman.io/common v0.67.1 pkg/secrets/secrets.go (getDriver) and
// pkg/config/default.go (defaultSecretConfig).
//
// dockerd serves only the compat route. Its SecretSpec.Driver is an object,
// {Name, Options}, and a named driver is a secrets plugin; without one the
// secret goes into the swarm's own store. Read from moby 28.5.1
// api/types/swarm/secret.go and api/types/swarm/common.go.
type secretCreateChainDaemon struct {
	podman bool

	mu     sync.Mutex
	stored []string
}

func (d *secretCreateChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(d.podman))
	case r.Method == http.MethodPost && normPath == "/libpod/secrets/create" && d.podman:
		_, _ = io.Copy(io.Discard, r.Body)
		query := r.URL.Query()
		d.podmanStore(w, podmanSchemaScalar(query, "driver"), podmanSchemaStringMap(query, "driveropts"))
	case r.Method == http.MethodPost && normPath == "/secrets/create" && d.podman:
		var spec struct {
			Driver struct {
				Name    string
				Options map[string]string
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		d.podmanStore(w, spec.Driver.Name, nil)
	case r.Method == http.MethodPost && normPath == "/secrets/create":
		var spec struct {
			Driver *struct {
				Name    string
				Options map[string]string
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if spec.Driver == nil {
			d.record(w, "swarm store")
			return
		}
		d.record(w, "plugin "+spec.Driver.Name)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *secretCreateChainDaemon) podmanStore(w http.ResponseWriter, driver string, options map[string]string) {
	if driver == "" {
		driver = "file"
	}
	switch driver {
	case "file":
		path, ok := options["path"]
		if !ok {
			path = podmanFileDriverDefaultPath
		}
		d.record(w, "file "+path)
	case "pass", "shell":
		d.record(w, driver)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (d *secretCreateChainDaemon) record(w http.ResponseWriter, where string) {
	d.mu.Lock()
	d.stored = append(d.stored, where)
	d.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]string{"ID": "s1"})
}

func (d *secretCreateChainDaemon) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.stored)
}

// podmanSchemaStringMap is the value gorilla/schema leaves in a
// map[string]string field tagged name. Podman registers convertStringMap for
// that type, which JSON-decodes the last value of a spelling and keeps
// whatever keys decoded even when another one did not, so every spelling,
// empty or not, replaces the field.
func podmanSchemaStringMap(query url.Values, name string) map[string]string {
	var field map[string]string
	for _, key := range podmanSchemaKeys(query, name) {
		value := ""
		if values := query[key]; len(values) > 0 {
			value = values[len(values)-1]
		}
		decoded := map[string]string{}
		_ = json.Unmarshal([]byte(value), &decoded)
		field = decoded
	}
	return field
}

// TestServeChainSecretCreateDriverAndOptions sends secret creates through the
// production chain to a daemon that stores them the way each engine does,
// and asserts on where each secret went.
//
// The libpod inspector refused every non-empty `driver`, and podman-remote
// always sends `driver=file`, so `podman secret create` was denied unless
// allow_custom_drivers was on. It never read `driveropts` at all, so with
// the flag off a create could still set the file driver's `path` and have
// the daemon write the secret data into any directory on its host. The
// compat inspector read Driver as a string, but both engines send an object,
// so a named driver was refused as uninspectable even with the flag on.
func TestServeChainSecretCreateDriverAndOptions(t *testing.T) {
	const pathOption = "driveropts=%7B%22path%22%3A%22%2Fetc%2Fcron.d%22%7D"
	tests := []struct {
		name       string
		podman     bool
		allow      bool
		target     string
		body       string
		wantStatus int
		wantReason string
		wantStored []string
	}{
		{
			name:       "podman-remote secret create",
			podman:     true,
			target:     "/v5.0.0/libpod/secrets/create?driver=file&ignore=false&labels=%7B%7D&name=s&replace=false",
			wantStatus: http.StatusOK,
			wantStored: []string{"file " + podmanFileDriverDefaultPath},
		},
		{
			name:       "libpod create with no driver",
			podman:     true,
			target:     "/v5.0.0/libpod/secrets/create?name=s",
			wantStatus: http.StatusOK,
			wantStored: []string{"file " + podmanFileDriverDefaultPath},
		},
		{
			name:       "file driver path on the default driver",
			podman:     true,
			target:     "/v5.0.0/libpod/secrets/create?name=s&" + pathOption,
			wantStatus: http.StatusForbidden,
			wantReason: "libpod secret create denied: driver options are not allowed",
		},
		{
			name:       "file driver path in another spelling",
			podman:     true,
			target:     "/v5.0.0/libpod/secrets/create?name=s&Driver" + strings.TrimPrefix(pathOption, "driver"),
			wantStatus: http.StatusForbidden,
			wantReason: `libpod secret create denied: ambiguous driveropts query parameter (repeated, or not spelled "driveropts")`,
		},
		{
			name:       "file driver path on the file driver",
			podman:     true,
			target:     "/v5.0.0/libpod/secrets/create?name=s&driver=file&" + pathOption,
			wantStatus: http.StatusForbidden,
			wantReason: "libpod secret create denied: driver options are not allowed",
		},
		{
			name:       "libpod create with a custom driver",
			podman:     true,
			target:     "/v5.0.0/libpod/secrets/create?name=s&driver=shell",
			wantStatus: http.StatusForbidden,
			wantReason: `libpod secret create denied: driver "shell" is not allowed`,
		},
		{
			name:       "file driver path when allowed",
			podman:     true,
			allow:      true,
			target:     "/v5.0.0/libpod/secrets/create?name=s&driveropts=%7B%22path%22%3A%22%2Fsrv%2Fsecrets%22%7D",
			wantStatus: http.StatusOK,
			wantStored: []string{"file /srv/secrets"},
		},
		{
			name:       "compat create on Podman",
			podman:     true,
			target:     "/v1.41/secrets/create",
			body:       `{"Name":"s","Data":"c2VjcmV0"}`,
			wantStatus: http.StatusOK,
			wantStored: []string{"file " + podmanFileDriverDefaultPath},
		},
		{
			name:       "compat create on Podman with a custom driver",
			podman:     true,
			target:     "/v1.41/secrets/create",
			body:       `{"Name":"s","Data":"c2VjcmV0","Driver":{"Name":"shell"}}`,
			wantStatus: http.StatusForbidden,
			wantReason: `secret create denied: driver "shell" is not allowed`,
		},
		{
			name:       "compat create on Podman with a custom driver when allowed",
			podman:     true,
			allow:      true,
			target:     "/v1.41/secrets/create",
			body:       `{"Name":"s","Data":"c2VjcmV0","Driver":{"Name":"shell"}}`,
			wantStatus: http.StatusOK,
			wantStored: []string{"shell"},
		},
		{
			name:       "compat create on dockerd",
			target:     "/v1.45/secrets/create",
			body:       `{"Name":"s","Data":"c2VjcmV0"}`,
			wantStatus: http.StatusOK,
			wantStored: []string{"swarm store"},
		},
		{
			// dockerd has no "file" driver; the name is a plugin's.
			name:       "compat create on dockerd naming a file driver",
			target:     "/v1.45/secrets/create",
			body:       `{"Name":"s","Driver":{"Name":"file"}}`,
			wantStatus: http.StatusForbidden,
			wantReason: `secret create denied: driver "file" is not allowed`,
		},
		{
			name:       "compat create on dockerd with a plugin driver when allowed",
			allow:      true,
			target:     "/v1.45/secrets/create",
			body:       `{"Name":"s","Driver":{"Name":"vault","Options":{"addr":"https://vault:8200"}}}`,
			wantStatus: http.StatusOK,
			wantStored: []string{"plugin vault"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &secretCreateChainDaemon{podman: tt.podman}
			addr := newEngineChain(t, "sec-create", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.RequestBody.Secret.AllowCustomDrivers = tt.allow
				cfg.RequestBody.LibpodSecret.AllowCustomDrivers = tt.allow
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/secrets/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/secrets/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			})

			status, body := sendSecretCreateChainRequest(t, "http://"+addr+tt.target, tt.body)
			if stored := daemon.seen(); !slices.Equal(stored, tt.wantStored) {
				t.Errorf("daemon stored secrets in %q, want %q", stored, tt.wantStored)
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
				if err := json.Unmarshal(body, &denial); err != nil || !strings.HasSuffix(denial.Reason, tt.wantReason) {
					t.Errorf("body = %s, want reason ending in %q", body, tt.wantReason)
				}
			}
		})
	}
}

// sendSecretCreateChainRequest posts body as JSON, the compat shape, or the
// raw payload "c2VjcmV0" when body is empty, the libpod shape.
func sendSecretCreateChainRequest(t *testing.T, target, body string) (int, []byte) {
	t.Helper()
	contentType := "application/json"
	if body == "" {
		body, contentType = "c2VjcmV0", "application/octet-stream"
	}
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}
