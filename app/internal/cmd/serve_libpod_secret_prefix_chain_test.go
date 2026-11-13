package cmd

import (
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// libpodSecretPrefixChainDaemon is a Podman secret store whose lookup resolves
// the way SecretsManager.Lookup does: an exact name or ID first, then a unique
// ID prefix, which is ambiguous (an error) when two IDs share it. Store, the
// create path, matches only an exact name or ID. Read from go.podman.io/common
// v0.67.1 pkg/secrets/secretsdb.go:71-133 and secrets.go:168-259.
//
// The compat inspect GET /secrets/{name} and libpod DELETE
// /libpod/secrets/{name} both go through Lookup. deleteGate, when set, holds
// every DELETE until that many have arrived, so a test can have two deletes
// both pass owner isolation's inspect before either one reaches the store.
type libpodSecretPrefixChainDaemon struct {
	mu      sync.Mutex
	secrets map[string]chainStoredSecret

	deleteGate chan struct{}
	deleteWG   *sync.WaitGroup
}

func newLibpodSecretPrefixChainDaemon() *libpodSecretPrefixChainDaemon {
	return &libpodSecretPrefixChainDaemon{secrets: map[string]chainStoredSecret{
		"mine":   {ID: "a0a0a0a0a0a0a0a0a0a0a0a01", Owner: "team-a", Data: "team-a data"},
		"theirs": {ID: "b0b0b0b0b0b0b0b0b0b0b0b02", Owner: "team-b", Data: "team-b data"},
		"twin":   {ID: "b0b1b1b1b1b1b1b1b1b1b1b13", Owner: "team-b", Data: "team-b twin"},
	}}
}

// lookupLocked is Lookup: exact name or ID, then a unique ID prefix. ok is
// false when nothing matches or the prefix is ambiguous; ambiguous tells the
// two apart.
func (d *libpodSecretPrefixChainDaemon) lookupLocked(ref string) (name string, secret chainStoredSecret, ok, ambiguous bool) {
	if s, found := d.secrets[ref]; found {
		return ref, s, true, false
	}
	for n, s := range d.secrets {
		if s.ID == ref {
			return n, s, true, false
		}
	}
	matches := 0
	for n, s := range d.secrets {
		if ref != "" && strings.HasPrefix(s.ID, ref) {
			name, secret = n, s
			matches++
		}
	}
	switch matches {
	case 0:
		return "", chainStoredSecret{}, false, false
	case 1:
		return name, secret, true, false
	default:
		return "", chainStoredSecret{}, false, true
	}
}

func (d *libpodSecretPrefixChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	norm := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && norm == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
	case r.Method == http.MethodGet && strings.HasPrefix(norm, "/secrets/"):
		d.inspect(w, strings.TrimPrefix(norm, "/secrets/"))
	case r.Method == http.MethodPost && norm == "/libpod/secrets/create":
		d.create(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(norm, "/libpod/secrets/"):
		d.remove(w, strings.TrimPrefix(norm, "/libpod/secrets/"))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *libpodSecretPrefixChainDaemon) inspect(w http.ResponseWriter, ref string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	name, secret, ok, ambiguous := d.lookupLocked(ref)
	switch {
	case ambiguous:
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"cause": "more than one result", "message": "more than one result secret with prefix " + ref + ": ambiguous", "response": "500"})
	case !ok:
		w.WriteHeader(http.StatusNotFound)
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ID":   secret.ID,
			"Spec": map[string]any{"Name": name, "Labels": map[string]string{"com.sockguard.owner": secret.Owner}},
		})
	}
}

func (d *libpodSecretPrefixChainDaemon) create(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	query := r.URL.Query()
	name := query.Get("name")
	replace := query.Get("replace") == "true"
	owner := podmanSchemaStringMap(query, "labels")["com.sockguard.owner"]
	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, ok := d.secrets[name]; ok {
		if !replace {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		delete(d.secrets, name)
		_ = existing
	}
	for _, s := range d.secrets {
		if s.ID == name {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	id := "c0c0c0c0c0c0c0c0c0c0c0c0" + string(rune('0'+len(d.secrets)))
	d.secrets[name] = chainStoredSecret{ID: id, Owner: owner, Data: string(data)}
	_ = json.NewEncoder(w).Encode(map[string]string{"ID": id})
}

func (d *libpodSecretPrefixChainDaemon) remove(w http.ResponseWriter, ref string) {
	if d.deleteGate != nil {
		d.deleteWG.Done()
		d.deleteWG.Wait()
		<-d.deleteGate
		defer func() { d.deleteGate <- struct{}{} }()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	name, _, ok, _ := d.lookupLocked(ref)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	delete(d.secrets, name)
	w.WriteHeader(http.StatusNoContent)
}

func (d *libpodSecretPrefixChainDaemon) snapshot() map[string]chainStoredSecret {
	d.mu.Lock()
	defer d.mu.Unlock()
	return maps.Clone(d.secrets)
}

func secretPrefixChainRequest(t *testing.T, method, target, body string) int {
	t.Helper()
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func secretPrefixChain(t *testing.T, daemon http.Handler) string {
	return newEngineChain(t, "sec-prefix", daemon, func(cfg *config.Config) {
		cfg.Ownership.Owner = "team-a"
		cfg.Rules = []config.RuleConfig{
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/secrets/create"}, Action: "allow"},
			{Match: config.MatchConfig{Method: http.MethodDelete, Path: "/libpod/secrets/*"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}
	})
}

// TestServeChainLibpodSecretCreateIgnoresIDPrefixOracle creates secrets whose
// names are lowercase hex of fewer than 25 characters, some of them a prefix of
// another owner's secret ID.
//
// Store matches an exact name or ID, so none of these collide with anything.
// The owner lookup goes through Lookup, which also resolves a unique ID prefix,
// so a name that was a prefix of team-b's ID got a 403 and one that was a
// prefix of two IDs got a 502, while a name matching nothing was created. The
// three answers told team-a which hex strings begin a team-b secret ID. A name
// like that can't be addressed afterwards either (path-targeted routes refuse
// it, see TestServeChainLibpodSecretDeleteNameCannotFallThroughToForeignID), so
// the create refuses all of them alike. A name that isn't such a string goes
// through, and a prefix-only match on it reads as absent.
func TestServeChainLibpodSecretCreateIgnoresIDPrefixOracle(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantStatus int
	}{
		{"prefix of one foreign ID", "name=b0b0&replace=true", http.StatusForbidden},
		{"prefix of two foreign IDs", "name=b0b&replace=true", http.StatusForbidden},
		{"prefix of nothing", "name=d0d0&replace=true", http.StatusForbidden},
		{"prefix of one foreign ID with ignore", "name=b0b0&ignore=true", http.StatusForbidden},
		{"prefix of one foreign ID without a flag", "name=b0b0", http.StatusForbidden},
		{"short name with a non-hex letter", "name=b0b0z&replace=true", http.StatusOK},
		{"name of 25 hex digits nobody holds", "name=d0d0d0d0d0d0d0d0d0d0d0d09&replace=true", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newLibpodSecretPrefixChainDaemon()
			before := daemon.snapshot()
			addr := secretPrefixChain(t, daemon)
			status := secretPrefixChainRequest(t, http.MethodPost, "http://"+addr+"/v5.0.0/libpod/secrets/create?"+tt.query, "x")
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d", status, tt.wantStatus)
			}
			after := daemon.snapshot()
			for name, secret := range before {
				if after[name] != secret {
					t.Errorf("secret %q = %+v, want it untouched (%+v)", name, after[name], secret)
				}
			}
		})
	}
}
