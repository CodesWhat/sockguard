package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/apipath"
	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

var (
	errChainNoSuchSecret    = errors.New("no such secret")
	errChainSecretAmbiguous = errors.New("secret is ambiguous")
)

// chainCreatedContainer is one container libpodSecretRefChainDaemon created:
// the owner label it carries and the secret data Podman would hand it, keyed
// by where the container reads it ("/run/secrets/<target>" or "$<ENV>").
type chainCreatedContainer struct {
	Owner   string
	Secrets map[string]string
}

// libpodSecretRefChainDaemon is a Podman secret store behind the routes a
// container create that names a secret goes through:
// POST /vX/libpod/containers/create, and the compat GET /secrets/{name} and
// GET /images/{name}/json owner isolation looks its references up with.
//
// The create handler decodes the body with encoding/json into a
// SpecGenerator, so keys match in any letter case. `secrets` is a []Secret
// whose Source has no JSON tag, and `secret_env` is a map from an environment
// variable to a source. A null or empty element decodes to a Secret with an
// empty Source, and a null map value to an empty source. MakeContainer and
// WithEnvSecrets then resolve every source with SecretsManager.Lookup and
// fail the create on the first one that doesn't resolve. A mounted secret's
// data is copied into the container at create. An environment secret's is
// read at every start and every exec, by the resolved secret's name, so what
// this daemon records for one is only the first of those reads. Read from
// Podman 5.8.6 pkg/api/handlers/libpod/containers_create.go,
// pkg/specgen/specgen.go:201, :351 and :647,
// pkg/specgen/generate/container_create.go:667-691,
// libpod/options.go:1812-1830, libpod/runtime_ctr.go:479-484,
// libpod/container_internal_common.go:753-765 and
// libpod/oci_conmon_exec_common.go:711-722.
//
// Lookup matches a full ID, then a name, then a unique ID prefix when the
// reference is no longer than an ID, and answers "secret is ambiguous" when
// more than one ID has the prefix. Every ID has the empty prefix, so an empty
// reference resolves to the only secret in a store that holds one. Names can't
// contain `,`, `/`, `=` or NUL and are otherwise free, so " mine", "." and
// ".." are names. Read from go.podman.io/common v0.67.1
// pkg/secrets/secretsdb.go:71-119 and secrets.go:332-337, and run against that
// package: Lookup("") on a store of one answered with its secret.
//
// The inspect is the same Lookup behind compat.InspectSecret, which answers
// 404 for "no such secret" and 500 for anything else, an ambiguous prefix
// included (pkg/domain/infra/abi/secrets.go:68-103). The router redirects a
// path that cleans to another one, as libpodSecretStoreChainDaemon does. A
// secret named "broken" answers 500 so the lookup failure path can be driven.
//
// "bbbb" is team-a's own secret, named after the first characters of the ID
// of team-b's "theirs". While it exists the name wins, and once it's deleted
// the same reference is a unique prefix of that ID.
type libpodSecretRefChainDaemon struct {
	mu         sync.Mutex
	secrets    map[string]chainStoredSecret
	lookups    []string
	containers []chainCreatedContainer
}

func newLibpodSecretRefChainDaemon() *libpodSecretRefChainDaemon {
	return &libpodSecretRefChainDaemon{secrets: map[string]chainStoredSecret{
		"mine":       {ID: "aaaaaaaaaaaaaaaaaaaaaaaa1", Owner: "team-a", Data: "team-a data"},
		"theirs":     {ID: "bbbbbbbbbbbbbbbbbbbbbbbb2", Owner: "team-b", Data: "team-b data"},
		"host-level": {ID: "cccccccccccccccccccccccc3", Data: "unlabeled data"},
		"broken":     {ID: "dddddddddddddddddddddddd4", Owner: "team-a", Data: "x"},
		".":          {ID: "eeeeeeeeeeeeeeeeeeeeeeee5", Owner: "team-b", Data: "team-b dot data"},
		"..":         {ID: "ffffffffffffffffffffffff6", Owner: "team-b", Data: "team-b dot-dot data"},
		" mine":      {ID: "9999999999999999999999997", Owner: "team-b", Data: "team-b spaced data"},
		"bbbb":       {ID: "1111111111111111111111118", Owner: "team-a", Data: "team-a decoy data"},
		"CAFE":       {ID: "2222222222222222222222229", Owner: "team-a", Data: "team-a hex data"},
	}}
}

func (d *libpodSecretRefChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	case r.Method == http.MethodGet && strings.HasPrefix(normPath, "/images/") && strings.HasSuffix(normPath, "/json"):
		_ = json.NewEncoder(w).Encode(map[string]any{"Config": map[string]any{"Labels": map[string]string{}}})
	case r.Method == http.MethodPost && normPath == "/libpod/containers/create" && versioned:
		d.createContainer(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *libpodSecretRefChainDaemon) inspect(w http.ResponseWriter, nameOrID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lookups = append(d.lookups, nameOrID)
	name, secret, err := d.lookupLocked(nameOrID)
	switch {
	case errors.Is(err, errChainNoSuchSecret):
		w.WriteHeader(http.StatusNotFound)
		return
	case err != nil, name == "broken":
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

func (d *libpodSecretRefChainDaemon) createContainer(w http.ResponseWriter, r *http.Request) {
	var spec struct {
		Labels     map[string]string `json:"labels"`
		EnvSecrets map[string]string `json:"secret_env"`
		Secrets    []struct {
			Source string
			Target string
		} `json:"secrets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"cause": "decode(): " + err.Error()})
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	created := chainCreatedContainer{Owner: spec.Labels["com.sockguard.owner"], Secrets: map[string]string{}}
	fail := func(err error) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"cause": err.Error()})
	}
	for _, mount := range spec.Secrets {
		name, secret, err := d.lookupLocked(mount.Source)
		if err != nil {
			fail(err)
			return
		}
		target := mount.Target
		if target == "" {
			target = name
		}
		created.Secrets["/run/secrets/"+target] = secret.Data
	}
	for _, variable := range slices.Sorted(maps.Keys(spec.EnvSecrets)) {
		_, secret, err := d.lookupLocked(spec.EnvSecrets[variable])
		if err != nil {
			fail(err)
			return
		}
		created.Secrets["$"+variable] = secret.Data
	}
	d.containers = append(d.containers, created)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"Id": fmt.Sprintf("%064d", len(d.containers)), "Warnings": []string{}})
}

// lookupLocked is SecretsManager.Lookup.
func (d *libpodSecretRefChainDaemon) lookupLocked(nameOrID string) (string, chainStoredSecret, error) {
	for name, secret := range d.secrets {
		if secret.ID == nameOrID {
			return name, secret, nil
		}
	}
	if secret, ok := d.secrets[nameOrID]; ok {
		return nameOrID, secret, nil
	}
	const secretIDLength = 25
	if len(nameOrID) > secretIDLength {
		return "", chainStoredSecret{}, errChainNoSuchSecret
	}
	var (
		foundName string
		found     chainStoredSecret
		exists    bool
	)
	for name, secret := range d.secrets {
		if !strings.HasPrefix(secret.ID, nameOrID) {
			continue
		}
		if exists {
			return "", chainStoredSecret{}, errChainSecretAmbiguous
		}
		foundName, found, exists = name, secret, true
	}
	if !exists {
		return "", chainStoredSecret{}, errChainNoSuchSecret
	}
	return foundName, found, nil
}

func (d *libpodSecretRefChainDaemon) keepOnly(names ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for name := range d.secrets {
		if !slices.Contains(names, name) {
			delete(d.secrets, name)
		}
	}
}

func (d *libpodSecretRefChainDaemon) created() []chainCreatedContainer {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.containers)
}

func (d *libpodSecretRefChainDaemon) lookedUp() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.lookups)
}

// TestServeChainLibpodContainerCreateSecretsAreOwnerChecked sends libpod
// container creates through the production chain to a daemon that resolves
// their secrets the way Podman does, and asserts on the secret data each
// container it created was handed.
//
// Owner isolation checked a create's image, pod and namespace targets and
// never read `secrets` or `secret_env`, so team-a could name team-b's secret
// in either one, by name, full ID or ID prefix, and get a container of its own
// with the data mounted under /run/secrets or set in its environment.
//
// A reference that could be an ID or an ID prefix is refused without a
// lookup, whoever's secret it resolves to. Podman reads the data by the
// resolved secret's name afterwards, and that read falls through to an ID
// prefix once nothing holds the name, so team-a could pass the owner check
// with its own "bbbb", delete it, and have the read answer with team-b's
// secret.
//
// `secret_env` is refused whoever's secret it names. Podman reads an
// environment secret by name again at every start and exec, so team-a could
// create the container with its own secret, remove the secret, and read
// whatever team-b later stores under that name.
func TestServeChainLibpodContainerCreateSecretsAreOwnerChecked(t *testing.T) {
	const (
		mineID         = "aaaaaaaaaaaaaaaaaaaaaaaa1"
		theirsID       = "bbbbbbbbbbbbbbbbbbbbbbbb2"
		createURL      = "/v5.0.0/libpod/containers/create"
		cantLookUp     = "libpod owner policy denied container create with a secret reference it can't look up"
		idShaped       = "libpod owner policy denied container create with a secret reference that could be a secret ID or ID prefix"
		envSecret      = "libpod owner policy denied container create with secret_env, which Podman reads by name at every start"
		deniedMount    = "libpod owner policy denied access to secret %q referenced by container create secrets"
		unresolved     = "libpod owner policy could not resolve secret %q referenced by container create secrets"
		tooMany        = "libpod owner policy denied container create that names more resources than it can authorize"
		teamAContainer = "team-a"
	)
	// One more than a create is checked for, each a name team-a could hold.
	var manySecrets []string
	for i := range 257 {
		manySecrets = append(manySecrets, fmt.Sprintf(`{"source":"secret-%d"}`, i))
	}
	tests := []struct {
		name       string
		owner      string
		rollout    string
		only       []string
		body       string
		wantStatus int
		wantReason string
		// wantSecrets is the secret data the one container the daemon
		// created was handed. Nil means the daemon created nothing.
		wantSecrets map[string]string
		wantOwner   string
	}{
		{
			name:       "mount another owner's secret",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":"theirs"}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: fmt.Sprintf(deniedMount, "theirs"),
		},
		{
			name:       "another owner's secret in the environment",
			body:       `{"image":"alpine","systemd":"false","secret_env":{"DB_PASSWORD":"theirs"}}`,
			wantStatus: http.StatusForbidden,
			wantReason: envSecret,
		},
		{
			// podman-remote sends every Secret field, with Go's field names.
			name:       "podman-remote shape naming another owner's secret",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"Source":"theirs","Target":"","UID":0,"GID":0,"Mode":292}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: fmt.Sprintf(deniedMount, "theirs"),
		},
		{
			name:       "another owner's secret by its ID",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":"` + theirsID + `"}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: idShaped,
		},
		{
			name:       "another owner's secret by an ID prefix",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":"bbb"}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: idShaped,
		},
		{
			name:       "own secret named after another owner's ID prefix",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":"bbbb"}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: idShaped,
		},
		{
			name:       "own secret named after another owner's ID prefix in the environment",
			body:       `{"image":"alpine","systemd":"false","secret_env":{"DB_PASSWORD":"bbbb"}}`,
			wantStatus: http.StatusForbidden,
			wantReason: envSecret,
		},
		{
			name:       "own secret by its ID",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":"` + mineID + `"}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: idShaped,
		},
		{
			name:       "own secret by an ID prefix",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":"aaaa","target":"password"}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: idShaped,
		},
		{
			name:       "keys in another case",
			body:       `{"image":"alpine","systemd":"false","Secrets":[{"SOURCE":"theirs"}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: fmt.Sprintf(deniedMount, "theirs"),
		},
		{
			name:       "secret_env in another case",
			body:       `{"image":"alpine","systemd":"false","SECRET_ENV":{"DB_PASSWORD":"theirs"}}`,
			wantStatus: http.StatusForbidden,
			wantReason: envSecret,
		},
		{
			name:       "own secret beside another owner's",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":"mine"},{"source":"theirs"}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: fmt.Sprintf(deniedMount, "theirs"),
		},
		{
			name:       "own secret mounted, another owner's in the environment",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":"mine"}],"secret_env":{"K":"theirs"}}`,
			wantStatus: http.StatusForbidden,
			wantReason: envSecret,
		},
		{
			name:       "an unlabeled secret",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":"host-level"}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: fmt.Sprintf(deniedMount, "host-level"),
		},
		{
			// Podman doesn't trim a source, and " mine" is a name of its own.
			name:       "another owner's secret whose name trims to an owned one",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":" mine"}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: fmt.Sprintf(deniedMount, " mine"),
		},
		{
			// Every ID has the empty prefix, so with one secret in the store
			// an empty source is that secret.
			name:       "empty source against a store of one",
			only:       []string{"theirs"},
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":""}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: cantLookUp,
		},
		{
			name:       "secret with no source against a store of one",
			only:       []string{"theirs"},
			body:       `{"image":"alpine","systemd":"false","secrets":[{"target":"password"}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: cantLookUp,
		},
		{
			name:       "null source against a store of one",
			only:       []string{"theirs"},
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":null}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: cantLookUp,
		},
		{
			name:       "null secret against a store of one",
			only:       []string{"theirs"},
			body:       `{"image":"alpine","systemd":"false","secrets":[null]}`,
			wantStatus: http.StatusForbidden,
			wantReason: cantLookUp,
		},
		{
			name:       "empty environment source against a store of one",
			only:       []string{"theirs"},
			body:       `{"image":"alpine","systemd":"false","secret_env":{"DB_PASSWORD":""}}`,
			wantStatus: http.StatusForbidden,
			wantReason: envSecret,
		},
		{
			name:       "null environment source against a store of one",
			only:       []string{"theirs"},
			body:       `{"image":"alpine","systemd":"false","secret_env":{"DB_PASSWORD":null}}`,
			wantStatus: http.StatusForbidden,
			wantReason: envSecret,
		},
		{
			// Podman's router redirects GET /secrets/.. to "/", which answers
			// 404, and GET /secrets/. to the secret list.
			name:       "a secret named ..",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":".."}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: cantLookUp,
		},
		{
			name:       "a secret named .",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":"."}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: cantLookUp,
		},
		{
			// Podman refuses each of these bodies while decoding it.
			name:       "secrets that isn't a list",
			body:       `{"image":"alpine","systemd":"false","secrets":"theirs"}`,
			wantStatus: http.StatusForbidden,
			wantReason: cantLookUp,
		},
		{
			name:       "a secret that isn't an object",
			body:       `{"image":"alpine","systemd":"false","secrets":["theirs"]}`,
			wantStatus: http.StatusForbidden,
			wantReason: cantLookUp,
		},
		{
			name:       "a source that isn't a string",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":["theirs"]}]}`,
			wantStatus: http.StatusForbidden,
			wantReason: cantLookUp,
		},
		{
			name:       "secret_env that isn't an object",
			body:       `{"image":"alpine","systemd":"false","secret_env":["theirs"]}`,
			wantStatus: http.StatusForbidden,
			wantReason: envSecret,
		},
		{
			// Each secret costs a lookup, and the list is the client's to
			// fill, so secrets count toward the 256 resources a create may name.
			name:       "more secrets than owner isolation will look up",
			body:       `{"image":"alpine","systemd":"false","secrets":[` + strings.Join(manySecrets, ",") + `]}`,
			wantStatus: http.StatusForbidden,
			wantReason: tooMany,
		},
		{
			name:       "a secret nobody holds",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":"nobody"}]}`,
			wantStatus: http.StatusNotFound,
			wantReason: fmt.Sprintf(unresolved, "nobody"),
		},
		{
			name:       "lookup failure",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":"broken"}]}`,
			wantStatus: http.StatusBadGateway,
		},
		{
			name:        "own secret",
			body:        `{"image":"alpine","systemd":"false","secrets":[{"source":"mine"}]}`,
			wantStatus:  http.StatusCreated,
			wantOwner:   teamAContainer,
			wantSecrets: map[string]string{"/run/secrets/mine": "team-a data"},
		},
		{
			// Lookup compares case-sensitively and IDs are lowercase, so this
			// can only ever be a name.
			name:        "own secret with an uppercase hex name",
			body:        `{"image":"alpine","systemd":"false","secrets":[{"source":"CAFE","target":"password"}]}`,
			wantStatus:  http.StatusCreated,
			wantOwner:   teamAContainer,
			wantSecrets: map[string]string{"/run/secrets/password": "team-a hex data"},
		},
		{
			name:        "podman-remote shape naming own secret",
			body:        `{"image":"alpine","systemd":"false","secrets":[{"Source":"mine","Target":"","UID":0,"GID":0,"Mode":292}]}`,
			wantStatus:  http.StatusCreated,
			wantOwner:   teamAContainer,
			wantSecrets: map[string]string{"/run/secrets/mine": "team-a data"},
		},
		{
			name:       "own secret in the environment",
			body:       `{"image":"alpine","systemd":"false","secret_env":{"DB_PASSWORD":"mine"}}`,
			wantStatus: http.StatusForbidden,
			wantReason: envSecret,
		},
		{
			name:       "own secret mounted and in the environment",
			body:       `{"image":"alpine","systemd":"false","secrets":[{"source":"mine"}],"secret_env":{"DB_PASSWORD":"mine"}}`,
			wantStatus: http.StatusForbidden,
			wantReason: envSecret,
		},
		{
			name:        "another owner's secret in the environment in warn mode",
			rollout:     "warn",
			body:        `{"image":"alpine","systemd":"false","secret_env":{"DB_PASSWORD":"theirs"}}`,
			wantStatus:  http.StatusCreated,
			wantOwner:   teamAContainer,
			wantSecrets: map[string]string{"$DB_PASSWORD": "team-b data"},
		},
		{
			name:        "no secrets",
			body:        `{"image":"alpine","systemd":"false","secrets":[],"secret_env":{}}`,
			wantStatus:  http.StatusCreated,
			wantOwner:   teamAContainer,
			wantSecrets: map[string]string{},
		},
		{
			name:        "null secrets",
			body:        `{"image":"alpine","systemd":"false","secrets":null,"secret_env":null}`,
			wantStatus:  http.StatusCreated,
			wantOwner:   teamAContainer,
			wantSecrets: map[string]string{},
		},
		{
			name:        "another owner's secret in warn mode",
			rollout:     "warn",
			body:        `{"image":"alpine","systemd":"false","secrets":[{"source":"theirs"}]}`,
			wantStatus:  http.StatusCreated,
			wantOwner:   teamAContainer,
			wantSecrets: map[string]string{"/run/secrets/theirs": "team-b data"},
		},
		{
			name:        "another owner's secret without owner isolation",
			owner:       "none",
			body:        `{"image":"alpine","systemd":"false","secrets":[{"source":"theirs"}],"secret_env":{"K":"theirs"}}`,
			wantStatus:  http.StatusCreated,
			wantSecrets: map[string]string{"/run/secrets/theirs": "team-b data", "$K": "team-b data"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newLibpodSecretRefChainDaemon()
			if tt.only != nil {
				daemon.keepOnly(tt.only...)
			}
			addr := newEngineChain(t, "sec-ref", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.Ownership.Owner = "team-a"
				if tt.owner == "none" {
					cfg.Ownership.Owner = ""
				}
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				if tt.rollout != "" {
					cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "rollout", Mode: tt.rollout, Rules: cfg.Rules}}
					cfg.Clients.DefaultProfile = "rollout"
				}
			})

			status, body := postOwnerSecretReferenceChainJSON(t, "http://"+addr+createURL, tt.body)

			created := daemon.created()
			switch {
			case tt.wantSecrets == nil && len(created) != 0:
				t.Errorf("daemon created %+v, want nothing", created)
			case tt.wantSecrets != nil && len(created) != 1:
				t.Errorf("daemon created %+v, want one container", created)
			case tt.wantSecrets != nil:
				if !maps.Equal(created[0].Secrets, tt.wantSecrets) {
					t.Errorf("container was handed %q, want %q", created[0].Secrets, tt.wantSecrets)
				}
				if created[0].Owner != tt.wantOwner {
					t.Errorf("container owner = %q, want %q", created[0].Owner, tt.wantOwner)
				}
			}
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
			if status != http.StatusCreated && strings.Contains(string(body), "team-b") {
				t.Errorf("refusal body carries the other owner's data: %s", body)
			}
			if lookups := daemon.lookedUp(); (tt.wantReason == cantLookUp || tt.wantReason == idShaped || tt.wantReason == envSecret || tt.wantReason == tooMany) && len(lookups) != 0 {
				t.Errorf("daemon was asked for secrets %q, want no lookup", lookups)
			}
			assertOwnerSecretReferenceChainReason(t, tt.wantStatus, tt.wantReason, body)
		})
	}
}

// swarmObjectRefChainDaemon is dockerd's service create and update over a
// swarm store of secrets and configs, with the inspects owner isolation
// looks the references up through.
//
// A service names its secrets and configs under
// TaskTemplate.ContainerSpec.Secrets and .Configs, each with an ID and a
// name. The manager reads the object by exactly that ID and refuses the
// service unless the object exists and its name is the reference's name, and
// the tasks then get the data of the object with that ID. Read from swarmkit
// manager/controlapi/service.go (checkSecretExistence, checkConfigExistence).
//
// The inspects, GET /secrets/{id} and GET /configs/{id}, match a full ID, then
// a name, then an ID prefix. Read from moby 28.5.1 daemon/cluster/helpers.go
// (getSecret, getConfig).
type swarmObjectRefChainDaemon struct {
	mu       sync.Mutex
	secrets  map[string]chainStoredSecret
	configs  map[string]chainStoredSecret
	services []chainCreatedContainer
}

func newSwarmObjectRefChainDaemon() *swarmObjectRefChainDaemon {
	return &swarmObjectRefChainDaemon{
		secrets: map[string]chainStoredSecret{
			"mine":   {ID: "secretaaaaaaaaaaaaaaaaaaa", Owner: "team-a", Data: "team-a secret"},
			"theirs": {ID: "secretbbbbbbbbbbbbbbbbbbb", Owner: "team-b", Data: "team-b secret"},
		},
		configs: map[string]chainStoredSecret{
			"mine":   {ID: "configaaaaaaaaaaaaaaaaaaa", Owner: "team-a", Data: "team-a config"},
			"theirs": {ID: "configbbbbbbbbbbbbbbbbbbb", Owner: "team-b", Data: "team-b config"},
		},
	}
}

func (d *swarmObjectRefChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(false))
	case r.Method == http.MethodGet && strings.HasPrefix(normPath, "/secrets/"):
		d.inspect(w, d.secrets, strings.TrimPrefix(normPath, "/secrets/"))
	case r.Method == http.MethodGet && strings.HasPrefix(normPath, "/configs/"):
		d.inspect(w, d.configs, strings.TrimPrefix(normPath, "/configs/"))
	case r.Method == http.MethodGet && normPath == "/services/web":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ID":   "web",
			"Spec": map[string]any{"Name": "web", "Labels": map[string]string{"com.sockguard.owner": "team-a"}},
		})
	case r.Method == http.MethodGet && strings.HasPrefix(normPath, "/images/") && strings.HasSuffix(normPath, "/json"):
		_ = json.NewEncoder(w).Encode(map[string]any{"Config": map[string]any{"Labels": map[string]string{}}})
	case r.Method == http.MethodPost && (normPath == "/services/create" || normPath == "/services/web/update"):
		d.writeService(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *swarmObjectRefChainDaemon) inspect(w http.ResponseWriter, store map[string]chainStoredSecret, input string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	name, object, ok := swarmChainLookup(store, input)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ID":   object.ID,
		"Spec": map[string]any{"Name": name, "Labels": map[string]string{"com.sockguard.owner": object.Owner}},
	})
}

// swarmChainLookup is getSecret and getConfig: a full ID, then a name, then
// an ID prefix. The store here never holds two objects with one prefix.
func swarmChainLookup(store map[string]chainStoredSecret, input string) (string, chainStoredSecret, bool) {
	for name, object := range store {
		if object.ID == input {
			return name, object, true
		}
	}
	if object, ok := store[input]; ok {
		return input, object, true
	}
	for name, object := range store {
		if strings.HasPrefix(object.ID, input) {
			return name, object, true
		}
	}
	return "", chainStoredSecret{}, false
}

func (d *swarmObjectRefChainDaemon) writeService(w http.ResponseWriter, r *http.Request) {
	var spec struct {
		Labels       map[string]string
		TaskTemplate struct {
			ContainerSpec struct {
				Secrets []struct{ SecretID, SecretName string }
				Configs []struct{ ConfigID, ConfigName string }
			}
		}
	}
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	service := chainCreatedContainer{Owner: spec.Labels["com.sockguard.owner"], Secrets: map[string]string{}}
	resolve := func(store map[string]chainStoredSecret, kind, id, name string) bool {
		object, ok := store[name]
		if !ok || object.ID != id {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": kind + " not found: " + name})
			return false
		}
		service.Secrets[kind+" "+name] = object.Data
		return true
	}
	for _, ref := range spec.TaskTemplate.ContainerSpec.Secrets {
		if !resolve(d.secrets, "secret", ref.SecretID, ref.SecretName) {
			return
		}
	}
	for _, ref := range spec.TaskTemplate.ContainerSpec.Configs {
		if !resolve(d.configs, "config", ref.ConfigID, ref.ConfigName) {
			return
		}
	}
	d.services = append(d.services, service)
	_ = json.NewEncoder(w).Encode(map[string]any{"ID": "web", "Warnings": []string{}})
}

func (d *swarmObjectRefChainDaemon) written() []chainCreatedContainer {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.services)
}

// TestServeChainServiceSecretAndConfigReferencesAreOwnerChecked sends Swarm
// service creates and updates through the production chain to a daemon that
// resolves their secret and config references the way the swarm manager does,
// and asserts on the data each service it accepted was handed.
//
// This is the surface next to the libpod one above, and it was already
// covered: the manager reads a reference by its ID alone, and owner isolation
// looks that ID up with an inspect that matches a full ID before anything
// else.
func TestServeChainServiceSecretAndConfigReferencesAreOwnerChecked(t *testing.T) {
	const (
		mineSecretID   = "secretaaaaaaaaaaaaaaaaaaa"
		theirsSecretID = "secretbbbbbbbbbbbbbbbbbbb"
		mineConfigID   = "configaaaaaaaaaaaaaaaaaaa"
		theirsConfigID = "configbbbbbbbbbbbbbbbbbbb"
		deniedSecret   = "owner policy denied access to secret %q referenced by service TaskTemplate.ContainerSpec.Secrets"
		deniedConfig   = "owner policy denied access to config %q referenced by service TaskTemplate.ContainerSpec.Configs"
	)
	service := func(containerSpec string) string {
		return `{"Name":"web","TaskTemplate":{"ContainerSpec":{"Image":"alpine",` + containerSpec + `}}}`
	}
	tests := []struct {
		name       string
		target     string
		body       string
		wantStatus int
		wantReason string
		// wantData is the secret and config data the one service the daemon
		// accepted was handed. Nil means the daemon accepted nothing.
		wantData map[string]string
	}{
		{
			name:       "create with another owner's secret",
			target:     "/v1.45/services/create",
			body:       service(`"Secrets":[{"SecretID":"` + theirsSecretID + `","SecretName":"theirs","File":{"Name":"theirs"}}]`),
			wantStatus: http.StatusForbidden,
			wantReason: fmt.Sprintf(deniedSecret, theirsSecretID),
		},
		{
			name:       "create with another owner's config",
			target:     "/v1.45/services/create",
			body:       service(`"Configs":[{"ConfigID":"` + theirsConfigID + `","ConfigName":"theirs","File":{"Name":"theirs"}}]`),
			wantStatus: http.StatusForbidden,
			wantReason: fmt.Sprintf(deniedConfig, theirsConfigID),
		},
		{
			name:       "update with another owner's secret",
			target:     "/v1.45/services/web/update?version=7",
			body:       service(`"Secrets":[{"SecretID":"` + theirsSecretID + `","SecretName":"theirs"}]`),
			wantStatus: http.StatusForbidden,
			wantReason: fmt.Sprintf(deniedSecret, theirsSecretID),
		},
		{
			name:       "update with another owner's config",
			target:     "/v1.45/services/web/update?version=7",
			body:       service(`"Configs":[{"ConfigID":"` + theirsConfigID + `","ConfigName":"theirs"}]`),
			wantStatus: http.StatusForbidden,
			wantReason: fmt.Sprintf(deniedConfig, theirsConfigID),
		},
		{
			name:       "keys in another case",
			target:     "/v1.45/services/create",
			body:       `{"Name":"web","tasktemplate":{"containerspec":{"Image":"alpine","secrets":[{"secretid":"` + theirsSecretID + `","secretname":"theirs"}]}}}`,
			wantStatus: http.StatusForbidden,
			wantReason: fmt.Sprintf(deniedSecret, theirsSecretID),
		},
		{
			name:       "another owner's secret by name with no ID",
			target:     "/v1.45/services/create",
			body:       service(`"Secrets":[{"SecretName":"theirs"}]`),
			wantStatus: http.StatusForbidden,
			wantReason: fmt.Sprintf(deniedSecret, "theirs"),
		},
		{
			// The owned ID passes the check, and the manager then refuses a
			// reference whose name isn't that object's.
			name:       "own secret ID under another owner's secret name",
			target:     "/v1.45/services/create",
			body:       service(`"Secrets":[{"SecretID":"` + mineSecretID + `","SecretName":"theirs"}]`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "create with own secret and config",
			target:     "/v1.45/services/create",
			body:       service(`"Secrets":[{"SecretID":"` + mineSecretID + `","SecretName":"mine"}],"Configs":[{"ConfigID":"` + mineConfigID + `","ConfigName":"mine"}]`),
			wantStatus: http.StatusOK,
			wantData:   map[string]string{"secret mine": "team-a secret", "config mine": "team-a config"},
		},
		{
			name:       "update with own secret",
			target:     "/v1.45/services/web/update?version=7",
			body:       service(`"Secrets":[{"SecretID":"` + mineSecretID + `","SecretName":"mine"}]`),
			wantStatus: http.StatusOK,
			wantData:   map[string]string{"secret mine": "team-a secret"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newSwarmObjectRefChainDaemon()
			addr := newEngineChain(t, "svc-ref", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.Ownership.Owner = "team-a"
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/services/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/services/*/update"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			})

			status, body := postOwnerSecretReferenceChainJSON(t, "http://"+addr+tt.target, tt.body)

			written := daemon.written()
			switch {
			case tt.wantData == nil && len(written) != 0:
				t.Errorf("daemon accepted %+v, want nothing", written)
			case tt.wantData != nil && len(written) != 1:
				t.Errorf("daemon accepted %+v, want one service", written)
			case tt.wantData != nil && !maps.Equal(written[0].Secrets, tt.wantData):
				t.Errorf("service was handed %q, want %q", written[0].Secrets, tt.wantData)
			}
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
			assertOwnerSecretReferenceChainReason(t, tt.wantStatus, tt.wantReason, body)
		})
	}
}

func postOwnerSecretReferenceChainJSON(t *testing.T, target, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

func assertOwnerSecretReferenceChainReason(t *testing.T, wantStatus int, wantReason string, body []byte) {
	t.Helper()
	if (wantStatus == http.StatusForbidden || wantStatus == http.StatusNotFound) && wantReason == "" {
		t.Fatal("a denied case must name the reason it is denied for")
	}
	if wantReason == "" {
		return
	}
	var denial struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &denial); err != nil || denial.Message != wantReason {
		t.Errorf("body = %s, want message %q", body, wantReason)
	}
}
