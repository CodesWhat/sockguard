package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/config"
)

// chainStoredSecret is one secret in libpodSecretStoreChainDaemon's store.
type chainStoredSecret struct {
	ID    string
	Owner string
	Data  string
}

// libpodSecretStoreChainDaemon is a Podman secret store behind two routes:
// POST /vX/libpod/secrets/create and the compat GET /secrets/{name} owner
// isolation inspects a secret through.
//
// The create handler decodes `name`, `labels`, `replace` and `ignore` with the
// libpod decoder and hands them to SecretsManager.Store, which this daemon
// copies. A name that matches an existing secret's name or full ID exactly is
// that secret. Without `replace` or `ignore` that's an error. With `ignore`
// the existing secret's ID comes back and nothing changes. With `replace` the
// existing secret is deleted and a new one is stored under its name, with the
// request's labels and data and a new ID. Both flags at once is an error. Read
// from Podman 5.8.6 pkg/api/handlers/libpod/secrets.go and
// pkg/domain/infra/abi/secrets.go, and go.podman.io/common v0.67.1
// pkg/secrets/secrets.go:168-259 and secretsdb.go:104-133.
//
// The inspect answers by exact name or exact ID, the first step of Podman's
// lookupSecret, with the compat SecretInfoReportCompat shape, and 404 when
// nothing matches. A secret named "broken" answers 500 so the lookup failure
// path can be driven.
//
// Podman's router is gorilla/mux v1.8.1 with UseEncodedPath, which answers a
// path that cleans to another one with a 301 to the cleaned path before any
// route matches (Router.ServeHTTP), so GET /secrets/.. lands on "/" and
// GET /secrets/. on the secret list. Valid secret names include "." and "..",
// so the daemon redirects the same way.
type libpodSecretStoreChainDaemon struct {
	mu      sync.Mutex
	secrets map[string]chainStoredSecret
	nextID  int
}

func newLibpodSecretStoreChainDaemon() *libpodSecretStoreChainDaemon {
	return &libpodSecretStoreChainDaemon{secrets: map[string]chainStoredSecret{
		"mine":       {ID: "aaaaaaaaaaaaaaaaaaaaaaaa1", Owner: "team-a", Data: "team-a data"},
		"theirs":     {ID: "bbbbbbbbbbbbbbbbbbbbbbbb2", Owner: "team-b", Data: "team-b data"},
		"host-level": {ID: "cccccccccccccccccccccccc3", Data: "unlabeled data"},
		"broken":     {ID: "dddddddddddddddddddddddd4", Owner: "team-a", Data: "x"},
		".":          {ID: "eeeeeeeeeeeeeeeeeeeeeeee5", Owner: "team-b", Data: "team-b dot data"},
		"..":         {ID: "ffffffffffffffffffffffff6", Owner: "team-b", Data: "team-b dot-dot data"},
	}}
}

// muxCleanPath is gorilla/mux v1.8.1's cleanPath.
func muxCleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	cleaned := path.Clean(p)
	if p[len(p)-1] == '/' && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

func (d *libpodSecretStoreChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if escaped := r.URL.EscapedPath(); muxCleanPath(escaped) != escaped {
		w.Header().Set("Location", muxCleanPath(escaped))
		w.WriteHeader(http.StatusMovedPermanently)
		return
	}
	normPath := apipath.NormalizePath(r.URL.Path)
	versioned := normPath != r.URL.Path
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
	case r.Method == http.MethodGet && normPath == "/secrets":
		_ = json.NewEncoder(w).Encode([]map[string]string{})
	case r.Method == http.MethodGet && strings.HasPrefix(normPath, "/secrets/"):
		d.inspect(w, strings.TrimPrefix(normPath, "/secrets/"))
	case r.Method == http.MethodPost && normPath == "/libpod/secrets/create" && versioned:
		d.create(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *libpodSecretStoreChainDaemon) inspect(w http.ResponseWriter, nameOrID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	name, secret, ok := d.lookupLocked(nameOrID)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if name == "broken" {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	labels := map[string]string{}
	if secret.Owner != "" {
		labels["com.sockguard.owner"] = secret.Owner
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ID":      secret.ID,
		"Spec":    map[string]any{"Name": name, "Driver": map[string]any{"Name": "file"}, "Labels": labels},
		"Version": map[string]int{"Index": 1},
	})
}

func (d *libpodSecretStoreChainDaemon) create(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	query := r.URL.Query()
	replace, ok := podmanLibpodSchemaBool(query, "replace")
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ignore, ok := podmanLibpodSchemaBool(query, "ignore")
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	name := podmanSchemaScalar(query, "name")
	owner := podmanSchemaStringMap(query, "labels")["com.sockguard.owner"]

	d.mu.Lock()
	defer d.mu.Unlock()
	if name == "" || len(data) == 0 || (replace && ignore) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	existingName, existing, exists := d.lookupLocked(name)
	if exists {
		switch {
		case ignore:
			_ = json.NewEncoder(w).Encode(map[string]string{"ID": existing.ID})
			return
		case !replace:
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"cause": "secret name in use"})
			return
		}
		delete(d.secrets, existingName)
		name = existingName
	}
	d.nextID++
	stored := chainStoredSecret{ID: fmt.Sprintf("%025d", d.nextID), Owner: owner, Data: string(data)}
	d.secrets[name] = stored
	_ = json.NewEncoder(w).Encode(map[string]string{"ID": stored.ID})
}

// lookupLocked resolves an exact name or an exact ID, which is what both
// Store's existence check and the first step of the inspect lookup match.
func (d *libpodSecretStoreChainDaemon) lookupLocked(nameOrID string) (string, chainStoredSecret, bool) {
	if secret, ok := d.secrets[nameOrID]; ok {
		return nameOrID, secret, true
	}
	for name, secret := range d.secrets {
		if secret.ID == nameOrID {
			return name, secret, true
		}
	}
	return "", chainStoredSecret{}, false
}

func (d *libpodSecretStoreChainDaemon) snapshot() map[string]chainStoredSecret {
	d.mu.Lock()
	defer d.mu.Unlock()
	return maps.Clone(d.secrets)
}

// TestServeChainLibpodSecretCreateReplaceIsOwnerChecked sends libpod secret
// creates through the production chain to a daemon that stores them the way
// Podman does, and asserts on what the store holds afterwards.
//
// Owner isolation stamped the caller's label on POST /libpod/secrets/create
// and checked nothing else, because a create names a new secret. With
// `replace=true` Podman deletes the existing secret of that name and stores a
// new one under it with the caller's labels and data, so team-a could take
// over team-b's secret, and every team-b container that mounts it by name
// would read team-a's data on its next start. `ignore=true` on an existing
// name answers with that secret's ID and changes nothing, which hands team-a
// the ID of a secret it can't inspect and a 200 that says its create worked.
func TestServeChainLibpodSecretCreateReplaceIsOwnerChecked(t *testing.T) {
	const (
		theirsID  = "bbbbbbbbbbbbbbbbbbbbbbbb2"
		createURL = "/v5.0.0/libpod/secrets/create?"
	)
	tests := []struct {
		name       string
		owner      string
		rollout    string
		query      string
		wantStatus int
		wantReason string
		// wantChanged is the secrets the request should have created or
		// replaced, with their new owner and data; every other secret must
		// be exactly as it was.
		wantChanged map[string]chainStoredSecret
	}{
		{
			name:       "replace another owner's secret",
			query:      "name=theirs&replace=true",
			wantStatus: http.StatusForbidden,
			wantReason: `libpod owner policy denied access to secret "theirs" referenced by secret create replace`,
		},
		{
			name:       "replace another owner's secret by its ID",
			query:      "name=" + theirsID + "&replace=true",
			wantStatus: http.StatusForbidden,
			wantReason: `libpod owner policy denied access to secret "` + theirsID + `" referenced by secret create replace`,
		},
		{
			name:       "replace with the converter's on spelling",
			query:      "name=theirs&replace=on",
			wantStatus: http.StatusForbidden,
			wantReason: `libpod owner policy denied access to secret "theirs" referenced by secret create replace`,
		},
		{
			name:       "replace with a value ParseBool reads as true",
			query:      "name=theirs&replace=1",
			wantStatus: http.StatusForbidden,
			wantReason: `libpod owner policy denied access to secret "theirs" referenced by secret create replace`,
		},
		{
			name:       "replace an unlabeled secret",
			query:      "name=host-level&replace=true",
			wantStatus: http.StatusForbidden,
			wantReason: `libpod owner policy denied access to secret "host-level" referenced by secret create replace`,
		},
		{
			name:       "ignore on another owner's secret",
			query:      "name=theirs&ignore=true",
			wantStatus: http.StatusForbidden,
			wantReason: `libpod owner policy denied access to secret "theirs" referenced by secret create ignore`,
		},
		{
			// Podman's router redirects GET /secrets/.. to "/", which answers
			// 404, so the lookup would read another owner's secret as absent.
			name:       "replace a secret named ..",
			query:      "name=..&replace=true",
			wantStatus: http.StatusForbidden,
			wantReason: "libpod owner policy denied secret create naming a secret it can't look up",
		},
		{
			name:       "replace a secret named .",
			query:      "name=.&replace=true",
			wantStatus: http.StatusForbidden,
			wantReason: "libpod owner policy denied secret create naming a secret it can't look up",
		},
		{
			name:       "replace in another spelling",
			query:      "name=theirs&Replace=true",
			wantStatus: http.StatusForbidden,
			wantReason: "libpod owner policy denied secret create with an ambiguous replace parameter",
		},
		{
			name:       "replace behind a false first value",
			query:      "name=theirs&replace=false&replace=true",
			wantStatus: http.StatusForbidden,
			wantReason: "libpod owner policy denied secret create with an ambiguous replace parameter",
		},
		{
			name:       "ignore in another spelling",
			query:      "name=theirs&Ignore=true",
			wantStatus: http.StatusForbidden,
			wantReason: "libpod owner policy denied secret create with an ambiguous ignore parameter",
		},
		{
			// Podman keeps the last name, so the owned one in front would be
			// checked and the foreign one replaced.
			name:       "replace with a repeated name",
			query:      "name=mine&name=theirs&replace=true",
			wantStatus: http.StatusForbidden,
			wantReason: "libpod owner policy denied secret create with an ambiguous name parameter",
		},
		{
			name:       "replace with the name in another spelling",
			query:      "Name=theirs&replace=true",
			wantStatus: http.StatusForbidden,
			wantReason: "libpod owner policy denied secret create with an ambiguous name parameter",
		},
		{
			name:       "lookup failure",
			query:      "name=broken&replace=true",
			wantStatus: http.StatusBadGateway,
		},
		{
			name:        "replace own secret",
			query:       "name=mine&replace=true",
			wantStatus:  http.StatusOK,
			wantChanged: map[string]chainStoredSecret{"mine": {ID: "0000000000000000000000001", Owner: "team-a", Data: "new data"}},
		},
		{
			name:        "replace a name nobody holds",
			query:       "name=fresh&replace=true",
			wantStatus:  http.StatusOK,
			wantChanged: map[string]chainStoredSecret{"fresh": {ID: "0000000000000000000000001", Owner: "team-a", Data: "new data"}},
		},
		{
			name:       "ignore on own secret",
			query:      "name=mine&ignore=true",
			wantStatus: http.StatusOK,
		},
		{
			// podman-remote sends both flags on every create
			// (pkg/bindings/secrets.CreateOptions).
			name:        "podman-remote secret create",
			query:       "driver=file&ignore=false&labels=%7B%7D&name=fresh&replace=false",
			wantStatus:  http.StatusOK,
			wantChanged: map[string]chainStoredSecret{"fresh": {ID: "0000000000000000000000001", Owner: "team-a", Data: "new data"}},
		},
		{
			// Without either flag Podman refuses a name in use on its own,
			// so nothing is looked up.
			name:       "plain create on another owner's name",
			query:      "name=theirs",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "replace another owner's secret in warn mode",
			rollout:    "warn",
			query:      "name=theirs&replace=true",
			wantStatus: http.StatusOK,
			wantChanged: map[string]chainStoredSecret{
				"theirs": {ID: "0000000000000000000000001", Owner: "team-a", Data: "new data"},
			},
		},
		{
			name:       "replace without owner isolation",
			owner:      "none",
			query:      "name=theirs&replace=true",
			wantStatus: http.StatusOK,
			wantChanged: map[string]chainStoredSecret{
				"theirs": {ID: "0000000000000000000000001", Data: "new data"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newLibpodSecretStoreChainDaemon()
			before := daemon.snapshot()
			addr := newEngineChain(t, "sec-replace", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.Ownership.Owner = "team-a"
				if tt.owner == "none" {
					cfg.Ownership.Owner = ""
				}
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/secrets/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				if tt.rollout != "" {
					cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "rollout", Mode: tt.rollout, Rules: cfg.Rules}}
					cfg.Clients.DefaultProfile = "rollout"
				}
			})

			req, err := http.NewRequest(http.MethodPost, "http://"+addr+createURL+tt.query, strings.NewReader("new data"))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			want := maps.Clone(before)
			for name, secret := range tt.wantChanged {
				want[name] = secret
			}
			if got := daemon.snapshot(); !maps.Equal(got, want) {
				t.Errorf("daemon secrets = %+v, want %+v", got, want)
			}
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", resp.StatusCode, tt.wantStatus, body)
			}
			if resp.StatusCode != http.StatusOK && !strings.Contains(tt.query, theirsID) && strings.Contains(string(body), theirsID) {
				t.Errorf("refusal body carries the other owner's secret ID: %s", body)
			}
			if tt.wantStatus == http.StatusForbidden && tt.wantReason == "" {
				t.Fatal("a denied case must name the reason it is denied for")
			}
			if tt.wantReason != "" {
				var denial struct {
					Message string `json:"message"`
				}
				if err := json.Unmarshal(body, &denial); err != nil || denial.Message != tt.wantReason {
					t.Errorf("body = %s, want message %q", body, tt.wantReason)
				}
			}
		})
	}
}
