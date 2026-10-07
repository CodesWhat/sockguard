package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/config"
)

// podman6Fields maps a struct's JSON field names, lowered, to what binding
// each one does with its value.
type podman6Fields map[string]func(json.RawMessage) error

// podman6DecodeObject binds one JSON object's members the way Podman 6 does.
//
// Podman 6.0.0 through 6.1.3 read a create body with utils.ReadJSONFromBody
// (pkg/api/handlers/utils/handler.go:158-166, called from
// libpod/containers_create.go:64, libpod/pods.go:38 and
// compat/containers_create.go:51), and that file's `json` is
// jsoniter.ConfigCompatibleWithStandardLibrary (handler.go:117). Podman 5.8.6
// and earlier called encoding/json in the same three places.
//
// json-iterator v1.1.12 binds a key in generalStructDecoder.decodeOneField
// (reflect_struct_decoder.go): it looks the key up as written, and when that
// misses, looks up strings.ToLower(key) in a map holding every field name
// lowered. Members are applied in document order, so a repeated key is
// applied again, and an unknown one is skipped. That lookup is what this
// function is; the module isn't a dependency of this repo.
//
// strings.ToLower maps U+0130 to "i" and U+212A to "k". encoding/json folds
// U+212A and U+017F and leaves U+0130 alone, which is the whole difference.
func podman6DecodeObject(raw json.RawMessage, fields podman6Fields) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil // null leaves a struct as it was
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return errors.New("expect { or n")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := keyTok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
		bind, known := fields[key]
		if !known {
			bind, known = fields[strings.ToLower(key)]
		}
		if !known {
			continue
		}
		if err := bind(value); err != nil {
			return err
		}
	}
	return nil
}

// podman6String binds a string field. json-iterator's string decoder writes
// the zero value for a null (reflect_native.go, stringCodec.Decode calls
// ReadString, which returns "" for null), where encoding/json leaves the
// field as it was. So a string a later null follows is cleared.
func podman6String(dst *string) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		if string(raw) == "null" {
			*dst = ""
			return nil
		}
		return json.Unmarshal(raw, dst)
	}
}

// podman6Bool binds a bool field, which a null leaves alone in both decoders.
func podman6Bool(dst *bool) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		if string(raw) == "null" {
			return nil
		}
		return json.Unmarshal(raw, dst)
	}
}

func podman6Int(dst *int64) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		if string(raw) == "null" {
			return nil
		}
		return json.Unmarshal(raw, dst)
	}
}

func podman6Labels(dst *map[string]string) func(json.RawMessage) error {
	return func(raw json.RawMessage) error { return json.Unmarshal(raw, dst) }
}

// podman6Namespace binds a specgen.Namespace (pkg/specgen/namespaces.go:73-76).
func podman6Namespace(mode, value *string) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		return podman6DecodeObject(raw, podman6Fields{"nsmode": podman6String(mode), "value": podman6String(value)})
	}
}

// podman6KeyChainDaemon is a Podman 6 that creates whatever it's sent and
// records the fields a gate exists for, read the way Podman 6 reads them.
type podman6KeyChainDaemon struct {
	mu      sync.Mutex
	created []string
}

func (d *podman6KeyChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		if normPath == "/version" {
			_ = json.NewEncoder(w).Encode(engineChainVersion(true))
			return
		}
		// Owner isolation's lookups: everything it asks about is the caller's.
		labels := map[string]string{"com.sockguard.owner": "team-a"}
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": "sha256:1", "Config": map[string]any{"Labels": labels}, "Labels": labels})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err == nil {
		var made string
		switch normPath {
		case "/libpod/containers/create":
			made, err = podman6LibpodContainer(body)
		case "/libpod/pods/create":
			made, err = podman6Pod(body)
		case "/containers/create":
			made, err = podman6CompatContainer(body)
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err == nil {
			d.mu.Lock()
			d.created = append(d.created, made)
			d.mu.Unlock()
		}
	}
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"cause": err.Error(), "message": "decoding request body as JSON: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"Id": "c1"})
}

func (d *podman6KeyChainDaemon) made() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.created)
}

// podman6LibpodContainer reads the SpecGenerator fields under test
// (pkg/specgen/specgen.go: `privileged`, `pidns`, `user`, `labels`).
func podman6LibpodContainer(body []byte) (string, error) {
	var (
		privileged     bool
		pidMode, pidNS string
		user           string
		labels         map[string]string
	)
	err := podman6DecodeObject(body, podman6Fields{
		"privileged": podman6Bool(&privileged),
		"pidns":      podman6Namespace(&pidMode, &pidNS),
		"user":       podman6String(&user),
		"labels":     podman6Labels(&labels),
	})
	return describePodman6Create("container", privileged, pidMode, user, 0, labels), err
}

// podman6Pod reads the PodSpecGenerator fields under test
// (pkg/specgen/podspecgen.go: `pidns`, `labels`).
func podman6Pod(body []byte) (string, error) {
	var (
		pidMode, pidNS string
		labels         map[string]string
	)
	err := podman6DecodeObject(body, podman6Fields{
		"pidns":  podman6Namespace(&pidMode, &pidNS),
		"labels": podman6Labels(&labels),
	})
	return describePodman6Create("pod", false, pidMode, "", 0, labels), err
}

// podman6CompatContainer reads the handlers.CreateContainerConfig fields
// under test (pkg/api/handlers/types.go): the embedded container.Config's
// `User` and `Labels`, and `HostConfig`'s `Privileged`, `PidMode` and
// `Memory`. HostConfig is a struct there, so a null leaves it alone.
func podman6CompatContainer(body []byte) (string, error) {
	var (
		privileged bool
		pidMode    string
		user       string
		memory     int64
		labels     map[string]string
	)
	err := podman6DecodeObject(body, podman6Fields{
		"user":   podman6String(&user),
		"labels": podman6Labels(&labels),
		"hostconfig": func(raw json.RawMessage) error {
			return podman6DecodeObject(raw, podman6Fields{
				"privileged": podman6Bool(&privileged),
				"pidmode":    podman6String(&pidMode),
				"memory":     podman6Int(&memory),
			})
		},
	})
	return describePodman6Create("container", privileged, pidMode, user, memory, labels), err
}

func describePodman6Create(kind string, privileged bool, pidMode, user string, memory int64, labels map[string]string) string {
	parts := []string{kind}
	if privileged {
		parts = append(parts, "privileged")
	}
	if pidMode != "" {
		parts = append(parts, "pid="+pidMode)
	}
	if user != "" {
		parts = append(parts, "user="+user)
	}
	if memory != 0 {
		parts = append(parts, fmt.Sprintf("memory=%d", memory))
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		if key != "com.sockguard.owner" {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	for _, key := range keys {
		parts = append(parts, "label "+key)
	}
	return strings.Join(parts, " ")
}

// TestPodman6ReplicaBindsKeysEncodingJSONDoesNot is the reason the chain test
// below exists, shown on the replica alone: each body sets a field Podman 6
// acts on, under a key or in a shape sockguard's own decoder reads as that
// field being absent or safe.
func TestPodman6ReplicaBindsKeysEncodingJSONDoesNot(t *testing.T) {
	tests := []struct {
		name          string
		decode        func([]byte) (string, error)
		body          string
		wantPodman6   string
		encodingJSON  func([]byte) string
		wantSockguard string
	}{
		{
			name:        "libpod privileged under a dotted capital I",
			decode:      podman6LibpodContainer,
			body:        "{\"image\":\"alpine\",\"pr\u0130v\u0130leged\":true}",
			wantPodman6: "container privileged",
			encodingJSON: func(body []byte) string {
				var spec struct {
					Privileged bool `json:"privileged"`
				}
				_ = json.Unmarshal(body, &spec)
				return fmt.Sprintf("privileged=%v", spec.Privileged)
			},
			wantSockguard: "privileged=false",
		},
		{
			name:        "pod pidns under a dotted capital I",
			decode:      podman6Pod,
			body:        "{\"name\":\"p\",\"p\u0130dns\":{\"nsmode\":\"host\"}}",
			wantPodman6: "pod pid=host",
			encodingJSON: func(body []byte) string {
				var spec struct {
					PidNS struct {
						NSMode string `json:"nsmode"`
					} `json:"pidns"`
				}
				_ = json.Unmarshal(body, &spec)
				return "pid=" + spec.PidNS.NSMode
			},
			wantSockguard: "pid=",
		},
		{
			name:        "compat HostConfig.Privileged under a dotted capital I",
			decode:      podman6CompatContainer,
			body:        "{\"Image\":\"alpine\",\"HostConfig\":{\"Pr\u0130v\u0130leged\":true}}",
			wantPodman6: "container privileged",
			encodingJSON: func(body []byte) string {
				var spec struct {
					HostConfig struct{ Privileged bool }
				}
				_ = json.Unmarshal(body, &spec)
				return fmt.Sprintf("privileged=%v", spec.HostConfig.Privileged)
			},
			wantSockguard: "privileged=false",
		},
		{
			name:        "libpod user cleared by a later null",
			decode:      podman6LibpodContainer,
			body:        `{"image":"alpine","user":"1000","user":null}`,
			wantPodman6: "container",
			encodingJSON: func(body []byte) string {
				var spec struct {
					User string `json:"user"`
				}
				_ = json.Unmarshal(body, &spec)
				return "user=" + spec.User
			},
			wantSockguard: "user=1000",
		},
		{
			// The other direction: sockguard binds it and Podman 6 doesn't.
			name:        "libpod user under a long s",
			decode:      podman6LibpodContainer,
			body:        "{\"image\":\"alpine\",\"u\u017fer\":\"0\"}",
			wantPodman6: "container",
			encodingJSON: func(body []byte) string {
				var spec struct {
					User string `json:"user"`
				}
				_ = json.Unmarshal(body, &spec)
				return "user=" + spec.User
			},
			wantSockguard: "user=0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.decode([]byte(tt.body))
			if err != nil || got != tt.wantPodman6 {
				t.Errorf("Podman 6 reads %q, %v, want %q", got, err, tt.wantPodman6)
			}
			if got := tt.encodingJSON([]byte(tt.body)); got != tt.wantSockguard {
				t.Errorf("encoding/json reads %q, want %q", got, tt.wantSockguard)
			}
		})
	}
}

// TestServeChainRefusesBodiesTheEnginesReadTwoWays sends bodies whose keys
// Podman 6 and sockguard's decoder bind differently through the whole chain,
// with owner isolation off and on. Off, the engine gets the client's bytes.
// On, it gets the body re-marshaled from a map, which keeps an unknown key
// exactly as it was spelled, so that path is no safer.
//
// Before 2.2.6 every refused case below was forwarded: `allow_privileged`
// and the host PID gates read the field as absent, and the replica created
// a privileged container or a pod in the host PID namespace.
func TestServeChainRefusesBodiesTheEnginesReadTwoWays(t *testing.T) {
	const (
		libpodCreate = "/v6.1.3/libpod/containers/create"
		podCreate    = "/v6.1.3/libpod/pods/create"
		compatCreate = "/v1.41/containers/create"
	)
	type gates = config.RequestBodyConfig
	nonRoot := func(body *gates) {
		body.ContainerCreate.RequireNonRootUser = true
		body.LibpodContainerCreate.RequireNonRootUser = true
	}
	memoryLimit := func(body *gates) { body.ContainerCreate.RequireMemoryLimit = true }
	ambiguous := func(key, codePoint string) string {
		return fmt.Sprintf("request body denied: ambiguous JSON object key %s: %s matches a field name in some JSON decoders and not in others", key, codePoint)
	}
	repeated := func(first, second string) string {
		return fmt.Sprintf("request body denied: duplicate case-variant JSON keys %q and %q", first, second)
	}

	tests := []struct {
		name        string
		configure   func(*gates)
		target      string
		body        string
		wantStatus  int
		wantReason  string
		wantCreated []string
	}{
		// The reported gap: U+0130 is `i` to Podman 6 and nothing to
		// encoding/json.
		{
			name:       "libpod create with privileged under a dotted capital I",
			target:     libpodCreate,
			body:       "{\"image\":\"alpine\",\"systemd\":\"false\",\"pr\u0130v\u0130leged\":true}",
			wantStatus: http.StatusBadRequest,
			wantReason: ambiguous(`"pr\u0130v\u0130leged"`, "U+0130"),
		},
		{
			name:       "pod create with pidns under a dotted capital I",
			target:     podCreate,
			body:       "{\"name\":\"p\",\"p\u0130dns\":{\"nsmode\":\"host\"}}",
			wantStatus: http.StatusBadRequest,
			wantReason: ambiguous(`"p\u0130dns"`, "U+0130"),
		},
		{
			name:       "compat create with HostConfig.Privileged under a dotted capital I",
			target:     compatCreate,
			body:       "{\"Image\":\"alpine\",\"HostConfig\":{\"Pr\u0130v\u0130leged\":true}}",
			wantStatus: http.StatusBadRequest,
			wantReason: ambiguous(`"Pr\u0130v\u0130leged"`, "U+0130"),
		},
		{
			name:       "compat create with PidMode under a dotted capital I",
			target:     compatCreate,
			body:       "{\"Image\":\"alpine\",\"HostConfig\":{\"P\u0130dMode\":\"host\"}}",
			wantStatus: http.StatusBadRequest,
			wantReason: ambiguous(`"P\u0130dMode"`, "U+0130"),
		},
		{
			name:       "libpod create with the key escaped in the JSON",
			target:     libpodCreate,
			body:       `{"image":"alpine","systemd":"false","pr\u0130vileged":true}`,
			wantStatus: http.StatusBadRequest,
			wantReason: ambiguous(`"pr\u0130vileged"`, "U+0130"),
		},
		{
			name:       "pod create with the namespace's own key under a dotted capital I",
			target:     podCreate,
			body:       "{\"name\":\"p\",\"pidns\":{\"nsmode\":\"host\",\"\u0130gnored\":1}}",
			wantStatus: http.StatusBadRequest,
			wantReason: ambiguous(`"\u0130gnored"`, "U+0130"),
		},

		// The characters only encoding/json folds, or that both do. Refusing
		// them costs nothing and keeps the rule one rule.
		{
			name:       "libpod create with user under a long s",
			target:     libpodCreate,
			body:       "{\"image\":\"alpine\",\"systemd\":\"false\",\"u\u017fer\":\"0\"}",
			wantStatus: http.StatusBadRequest,
			wantReason: ambiguous(`"u\u017fer"`, "U+017F"),
		},
		{
			name:       "compat create with NetworkMode under a Kelvin sign",
			target:     compatCreate,
			body:       "{\"Image\":\"alpine\",\"HostConfig\":{\"Networ\u212aMode\":\"host\"}}",
			wantStatus: http.StatusBadRequest,
			wantReason: ambiguous(`"Networ\u212aMode"`, "U+212A"),
		},

		// A repeated key, which each decoder settles its own way.
		{
			name:       "libpod create with a user a later null clears in Podman 6",
			configure:  nonRoot,
			target:     libpodCreate,
			body:       `{"image":"alpine","systemd":"false","user":"1000","user":null}`,
			wantStatus: http.StatusBadRequest,
			wantReason: repeated("user", "user"),
		},
		{
			name:       "compat create with a host config a later null resets in dockerd",
			configure:  memoryLimit,
			target:     compatCreate,
			body:       `{"Image":"alpine","HostConfig":{"Memory":268435456},"HostConfig":null}`,
			wantStatus: http.StatusBadRequest,
			wantReason: repeated("HostConfig", "HostConfig"),
		},
		{
			name:       "compat create with a host config a map decode keeps the last of",
			configure:  memoryLimit,
			target:     compatCreate,
			body:       `{"Image":"alpine","HostConfig":{"Memory":268435456},"HostConfig":{}}`,
			wantStatus: http.StatusBadRequest,
			wantReason: repeated("HostConfig", "HostConfig"),
		},

		// A label key is refused for the same characters. That is the cost
		// of checking every key instead of guessing which objects are maps.
		{
			name:       "libpod create with a dotted capital I in a label key",
			target:     libpodCreate,
			body:       "{\"image\":\"alpine\",\"systemd\":\"false\",\"labels\":{\"\u0130stanbul\":\"1\"}}",
			wantStatus: http.StatusBadRequest,
			wantReason: ambiguous(`"\u0130stanbul"`, "U+0130"),
		},

		// What a client really sends still passes, non-ASCII label keys and
		// values included.
		{
			name:        "libpod create",
			target:      libpodCreate,
			body:        `{"image":"alpine","systemd":"false","privileged":false,"pidns":{"nsmode":"private"},"user":"1000"}`,
			wantStatus:  http.StatusCreated,
			wantCreated: []string{"container pid=private user=1000"},
		},
		{
			name:        "libpod create with non-ASCII label keys",
			target:      libpodCreate,
			body:        "{\"image\":\"alpine\",\"systemd\":\"false\",\"labels\":{\"\u043a\u043b\u044e\u0447\":\"1\",\"caf\u00e9\":\"2\",\"city\":\"\u0130stanbul\"}}",
			wantStatus:  http.StatusCreated,
			wantCreated: []string{"container label caf\u00e9 label city label \u043a\u043b\u044e\u0447"},
		},
		{
			name:        "libpod create with both proxy spellings in env",
			target:      libpodCreate,
			body:        `{"image":"alpine","systemd":"false","env":{"http_proxy":"http://p","HTTP_PROXY":"http://p"}}`,
			wantStatus:  http.StatusCreated,
			wantCreated: []string{"container"},
		},
		{
			name:        "pod create",
			target:      podCreate,
			body:        `{"name":"p","pidns":{"nsmode":"private"},"labels":{"app":"web"}}`,
			wantStatus:  http.StatusCreated,
			wantCreated: []string{"pod pid=private label app"},
		},
		{
			name:        "compat create",
			configure:   memoryLimit,
			target:      compatCreate,
			body:        `{"Image":"alpine","User":"1000","HostConfig":{"Privileged":false,"Memory":268435456},"Labels":{"app":"web"}}`,
			wantStatus:  http.StatusCreated,
			wantCreated: []string{"container user=1000 memory=268435456 label app"},
		},
		{
			name:       "libpod create with privileged set",
			target:     libpodCreate,
			body:       `{"image":"alpine","systemd":"false","privileged":true}`,
			wantStatus: http.StatusForbidden,
			wantReason: "libpod container create denied: privileged containers are not allowed",
		},
	}
	for _, owner := range []string{"", "team-a"} {
		isolation := "owner isolation off"
		if owner != "" {
			isolation = "owner isolation on"
		}
		for _, tt := range tests {
			t.Run(isolation+"/"+tt.name, func(t *testing.T) {
				daemon := &podman6KeyChainDaemon{}
				addr := newEngineChain(t, "key-parity", daemon, func(cfg *config.Config) {
					cfg.Response.DenyVerbosity = "verbose"
					cfg.Ownership.Owner = owner
					cfg.Rules = []config.RuleConfig{
						{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
						{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/pods/create"}, Action: "allow"},
						{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
						{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
					}
					if tt.configure != nil {
						tt.configure(&cfg.RequestBody)
					}
				})

				status, body := sendNamespaceChainRequest(t, "http://"+addr+tt.target, tt.body)
				if got := daemon.made(); !slices.Equal(got, tt.wantCreated) {
					t.Errorf("daemon created %q, want %q", got, tt.wantCreated)
				}
				if status != tt.wantStatus {
					t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
				}
				if tt.wantStatus != http.StatusCreated && tt.wantReason == "" {
					t.Fatal("a refused case must name the reason it is refused for")
				}
				if tt.wantReason != "" {
					var denial struct {
						Reason string `json:"reason"`
					}
					if err := json.Unmarshal(body, &denial); err != nil || denial.Reason != tt.wantReason {
						t.Errorf("body = %s, want reason %q", body, tt.wantReason)
					}
				}
			})
		}
	}
}
