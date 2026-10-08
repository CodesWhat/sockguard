package cmd

import (
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/testhelp"
)

// keyRolloutChainDaemon is a dockerd that keeps the body of every write it is
// sent. The caller owns whatever owner isolation asks it about, and a
// container the resource-limit guard asks about has a memory limit.
type keyRolloutChainDaemon struct {
	mu     sync.Mutex
	bodies []string
}

func (d *keyRolloutChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		if apipath.NormalizePath(r.URL.Path) == "/version" {
			_ = json.NewEncoder(w).Encode(engineChainVersion(false))
			return
		}
		labels := map[string]string{"com.sockguard.owner": "team-a"}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id":         "sha256:1",
			"Labels":     labels,
			"Config":     map[string]any{"Labels": labels},
			"HostConfig": map[string]any{"Memory": 268435456},
		})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	d.mu.Lock()
	d.bodies = append(d.bodies, string(body))
	d.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(w, `{"Id":"c1"}`)
}

func (d *keyRolloutChainDaemon) received() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.bodies)
}

// keyRolloutChainRecord waits for the access-log record of the one request a
// case sends and returns it. The record is written after the response, so
// the client can have its answer first.
func keyRolloutChainRecord(t *testing.T, collector *testhelp.CollectingHandler) testhelp.LogRecord {
	t.Helper()
	messages := []string{"request", "request_denied", "request_would_deny"}
	var records []testhelp.LogRecord
	testhelp.Eventually(t, func() bool {
		records = records[:0]
		for _, message := range messages {
			records = append(records, collector.FindMessage(message)...)
		}
		return len(records) > 0
	})
	if len(records) != 1 {
		t.Fatalf("access log has %d request records, want one: %#v", len(records), records)
	}
	return records[0]
}

// TestServeChainRolloutForwardsBodiesWithAmbiguousKeys sends bodies the
// inspectors refuse as request_body_ambiguous through the production chain
// under a profile in each rollout mode, with a layer behind the inspectors
// that reads the same body: owner isolation, or the resource-limit guard.
//
// Warn and audit forward a request the policy would deny, and the inspectors
// did. The two layers behind them then refused the body themselves, whatever
// the mode. A container or volume create whose label key held a Turkish
// letter, with owner isolation on, and a service create that did or that gave
// "Name" twice, with require_cpu_limit on, were all answered 201 under warn
// before the refusal existed and 400 after it. A staged rollout is where an
// operator finds out a client sends such a body, so that is the one place it
// can't start failing.
func TestServeChainRolloutForwardsBodiesWithAmbiguousKeys(t *testing.T) {
	const (
		containerCreate = "/v1.45/containers/create"
		volumeCreate    = "/v1.45/volumes/create"
		serviceCreate   = "/v1.45/services/create"
		containerUpdate = "/v1.45/containers/c/update"

		ambiguous          = "request_body_ambiguous"
		ownerInvalid       = "owner_request_invalid"
		resourceInvalid    = "resource_limit_request_invalid"
		serviceSpec        = `"TaskTemplate":{"ContainerSpec":{"Image":"alpine"},"Resources":{"Limits":{"NanoCPUs":1000000000}}}`
		serviceSpecStamped = `"TaskTemplate":{"ContainerSpec":{"Image":"alpine","Labels":{"com.sockguard.owner":"team-a"}},"Resources":{"Limits":{"NanoCPUs":1000000000}}}`
	)
	tests := []struct {
		name  string
		owner string
		// target and body are the request.
		target string
		body   string
		// refusedWith is the reason code enforce refuses the body with, or ""
		// for a body every mode forwards.
		refusedWith string
		// rolloutRefusedWith is the reason code warn and audit still refuse
		// it with, or "" when they forward it.
		rolloutRefusedWith string
		// wantForwarded is the body the daemon gets when the request is
		// forwarded. Owner isolation re-marshals it with the owner label and
		// its keys sorted; without it the daemon gets the client's bytes.
		wantForwarded string
	}{
		// Owner isolation, behind the container and volume inspectors.
		{
			name:          "container create with a dotted capital I in a label key",
			owner:         "team-a",
			target:        containerCreate,
			body:          "{\"Image\":\"alpine\",\"Labels\":{\"\u0130stanbul\":\"1\"}}",
			refusedWith:   ambiguous,
			wantForwarded: "{\"Image\":\"alpine\",\"Labels\":{\"com.sockguard.owner\":\"team-a\",\"\u0130stanbul\":\"1\"}}",
		},
		{
			name:          "volume create with a dotted capital I in a label key",
			owner:         "team-a",
			target:        volumeCreate,
			body:          "{\"Name\":\"v\",\"Labels\":{\"\u0130stanbul\":\"1\"}}",
			refusedWith:   ambiguous,
			wantForwarded: "{\"Labels\":{\"com.sockguard.owner\":\"team-a\",\"\u0130stanbul\":\"1\"},\"Name\":\"v\"}",
		},
		{
			// The dotless i binds to no field in either decoder, so no mode
			// refuses it.
			name:          "container create with a dotless i in a label key",
			owner:         "team-a",
			target:        containerCreate,
			body:          "{\"Image\":\"alpine\",\"Labels\":{\"a\u0131\":\"1\"}}",
			wantForwarded: "{\"Image\":\"alpine\",\"Labels\":{\"a\u0131\":\"1\",\"com.sockguard.owner\":\"team-a\"}}",
		},
		{
			name:          "volume create with a dotless i in a label key",
			owner:         "team-a",
			target:        volumeCreate,
			body:          "{\"Name\":\"v\",\"Labels\":{\"a\u0131\":\"1\"}}",
			wantForwarded: "{\"Labels\":{\"a\u0131\":\"1\",\"com.sockguard.owner\":\"team-a\"},\"Name\":\"v\"}",
		},
		{
			// Podman 6 reads both keys as PidMode and keeps the later one,
			// and the re-marshal sorts the dotted one last. Owner isolation
			// can't forward that as the client sent it, in any mode.
			name:               "container create with a key beside its dotted capital I spelling",
			owner:              "team-a",
			target:             containerCreate,
			body:               "{\"Image\":\"alpine\",\"HostConfig\":{\"P\u0130dMode\":\"host\",\"PidMode\":\"private\"}}",
			refusedWith:        ambiguous,
			rolloutRefusedWith: ownerInvalid,
		},

		// The resource-limit guard, behind the service and container update
		// inspectors.
		{
			name:          "service create with a dotted capital I in a label key",
			target:        serviceCreate,
			body:          "{\"Name\":\"web\",\"Labels\":{\"\u0130stanbul\":\"1\"}," + serviceSpec + "}",
			refusedWith:   ambiguous,
			wantForwarded: "{\"Name\":\"web\",\"Labels\":{\"\u0130stanbul\":\"1\"}," + serviceSpec + "}",
		},
		{
			name:          "service create that gives Name twice",
			target:        serviceCreate,
			body:          `{"Name":"web","Name":"web",` + serviceSpec + `}`,
			refusedWith:   ambiguous,
			wantForwarded: `{"Name":"web","Name":"web",` + serviceSpec + `}`,
		},
		{
			name:          "service create with a dotted capital I in a label key, behind owner isolation",
			owner:         "team-a",
			target:        serviceCreate,
			body:          "{\"Name\":\"web\",\"Labels\":{\"\u0130stanbul\":\"1\"}," + serviceSpec + "}",
			refusedWith:   ambiguous,
			wantForwarded: "{\"Labels\":{\"com.sockguard.owner\":\"team-a\",\"\u0130stanbul\":\"1\"},\"Name\":\"web\"," + serviceSpecStamped + "}",
		},
		{
			name:          "service create with a dotless i in a label key",
			target:        serviceCreate,
			body:          "{\"Name\":\"web\",\"Labels\":{\"a\u0131\":\"1\"}," + serviceSpec + "}",
			wantForwarded: "{\"Name\":\"web\",\"Labels\":{\"a\u0131\":\"1\"}," + serviceSpec + "}",
		},
		{
			name:          "container update with a dotted capital I in a key",
			target:        containerUpdate,
			body:          "{\"Memory\":268435456,\"\u0130gnored\":1}",
			refusedWith:   ambiguous,
			wantForwarded: "{\"Memory\":268435456,\"\u0130gnored\":1}",
		},
		{
			// The guard has refused a repeated key on a container update in
			// every mode since it shipped, and still does.
			name:               "container update that gives Memory twice",
			target:             containerUpdate,
			body:               `{"Memory":268435456,"Memory":0}`,
			refusedWith:        ambiguous,
			rolloutRefusedWith: resourceInvalid,
		},
	}
	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/volumes/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/services/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/update"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	for _, tt := range tests {
		for _, mode := range []string{"enforce", "warn", "audit"} {
			t.Run(tt.name+"/"+mode, func(t *testing.T) {
				daemon := &keyRolloutChainDaemon{}
				collector := &testhelp.CollectingHandler{}
				logger := testhelp.NewTeeLogger(slog.NewTextHandler(io.Discard, nil), collector)
				addr := newEngineChainWithLogger(t, "key-rollout", daemon, logger, func(cfg *config.Config) {
					cfg.Log.AccessLog = true
					cfg.Ownership.Owner = tt.owner
					cfg.Rules = rules
					cfg.Clients.Profiles = []config.ClientProfileConfig{{
						Name:  "rollout",
						Mode:  mode,
						Rules: rules,
						RequestBody: config.RequestBodyConfig{
							Service:         config.ServiceRequestBodyConfig{RequireCPULimit: true, AllowAllRegistries: true},
							ContainerUpdate: config.ContainerUpdateRequestBodyConfig{AllowResourceUpdates: true, RequireMemoryLimit: true},
						},
					}}
					cfg.Clients.DefaultProfile = "rollout"
				})

				status, answer := sendNamespaceChainRequest(t, "http://"+addr+tt.target, tt.body)
				record := keyRolloutChainRecord(t, collector)

				refusedWith := tt.refusedWith
				if mode != "enforce" {
					refusedWith = tt.rolloutRefusedWith
				}
				if refusedWith != "" {
					if status != http.StatusBadRequest {
						t.Errorf("status = %d, want %d; body: %s", status, http.StatusBadRequest, answer)
					}
					if got := daemon.received(); len(got) != 0 {
						t.Errorf("daemon received %q, want the request stopped", got)
					}
					if record.Message != "request_denied" || record.Attrs["reason_code"] != refusedWith {
						t.Errorf("access log = %s with reason_code %v, want request_denied with %s", record.Message, record.Attrs["reason_code"], refusedWith)
					}
					return
				}

				if status != http.StatusCreated {
					t.Errorf("status = %d, want %d; body: %s", status, http.StatusCreated, answer)
				}
				if got := daemon.received(); !slices.Equal(got, []string{tt.wantForwarded}) {
					t.Errorf("daemon received %q, want %q", got, tt.wantForwarded)
				}
				if tt.refusedWith == "" {
					if record.Message != "request" {
						t.Errorf("access log = %s with reason_code %v (%v), want a plain request record", record.Message, record.Attrs["reason_code"], record.Attrs["reason"])
					}
					return
				}
				// What enforce would have refused is on the record, under the
				// mode that let it through.
				if record.Message != "request_would_deny" || record.Attrs["decision"] != "would_deny" || record.Attrs["reason_code"] != tt.refusedWith || record.Attrs["rollout_mode"] != mode {
					t.Errorf("access log = %s with decision %v, reason_code %v, rollout_mode %v, want request_would_deny with would_deny, %s, %s",
						record.Message, record.Attrs["decision"], record.Attrs["reason_code"], record.Attrs["rollout_mode"], tt.refusedWith, mode)
				}
				wantLevel := slog.LevelWarn
				if mode == "audit" {
					wantLevel = slog.LevelInfo
				}
				if record.Level != wantLevel {
					t.Errorf("access log level = %s, want %s under %s", record.Level, wantLevel, mode)
				}
			})
		}
	}
}

// podman6LabelChainDaemon is a Podman 6 that creates the container it's sent
// and keeps the labels it bound, read the way Podman 6 reads a body.
type podman6LabelChainDaemon struct {
	mu     sync.Mutex
	labels []map[string]string
}

func (d *podman6LabelChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		if apipath.NormalizePath(r.URL.Path) == "/version" {
			_ = json.NewEncoder(w).Encode(engineChainVersion(true))
			return
		}
		labels := map[string]string{"com.sockguard.owner": "team-a"}
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": "sha256:1", "Config": map[string]any{"Labels": labels}, "Labels": labels})
		return
	}
	body, err := io.ReadAll(r.Body)
	var labels map[string]string
	if err == nil {
		err = podman6DecodeObject(body, podman6Fields{"labels": podman6Labels(&labels)})
	}
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	d.labels = append(d.labels, maps.Clone(labels))
	d.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(w, `{"Id":"c1"}`)
}

func (d *podman6LabelChainDaemon) bound() []map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.labels)
}

// TestServeChainRolloutStampsABodyPodman6ReadsDifferently is the case that
// decides whether owner isolation can forward such a body at all. Go's
// encoding/json reads `label\u017f` as `labels` and Podman 6's decoder
// doesn't. Had the owner label been written under the client's spelling of
// the key, a warn or audit profile would have had Podman 6 create a
// container with no owner label.
//
// It is written under the exact key, with the client's labels moved there,
// so Podman 6 binds the stamp and the client's own claim to the label is
// overwritten like any other.
func TestServeChainRolloutStampsABodyPodman6ReadsDifferently(t *testing.T) {
	const body = "{\"image\":\"alpine\",\"systemd\":\"false\",\"label\u017f\":{\"app\":\"web\",\"com.sockguard.owner\":\"team-b\"}}"
	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	for _, mode := range []string{"enforce", "warn", "audit"} {
		t.Run(mode, func(t *testing.T) {
			daemon := &podman6LabelChainDaemon{}
			addr := newEngineChain(t, "key-stamp", daemon, func(cfg *config.Config) {
				cfg.Ownership.Owner = "team-a"
				cfg.Rules = rules
				cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "rollout", Mode: mode, Rules: rules}}
				cfg.Clients.DefaultProfile = "rollout"
			})

			status, answer := sendNamespaceChainRequest(t, "http://"+addr+"/v6.1.3/libpod/containers/create", body)
			if mode == "enforce" {
				if status != http.StatusBadRequest {
					t.Errorf("status = %d, want %d; body: %s", status, http.StatusBadRequest, answer)
				}
				if got := daemon.bound(); len(got) != 0 {
					t.Errorf("Podman 6 created containers labeled %v, want the request stopped", got)
				}
				return
			}
			if status != http.StatusCreated {
				t.Errorf("status = %d, want %d; body: %s", status, http.StatusCreated, answer)
			}
			want := map[string]string{"app": "web", "com.sockguard.owner": "team-a"}
			if got := daemon.bound(); len(got) != 1 || !maps.Equal(got[0], want) {
				t.Errorf("Podman 6 bound labels %v, want one container with %v", got, want)
			}
		})
	}
}
