package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// libpodPodCreateCounterDaemon counts the pod creates that reach it. A pod
// create that arrives has been accepted by the whole chain.
type libpodPodCreateCounterDaemon struct {
	created atomic.Int32
}

func (d *libpodPodCreateCounterDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
	case r.Method == http.MethodPost && normPath == "/libpod/pods/create":
		_, _ = io.Copy(io.Discard, r.Body)
		d.created.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "p1"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// TestServeChainLibpodPodCreateAppliesTheContainerGatesToInheritedFields sends
// pod creates that carry mounts, pod_devices, security_opt, sysctl and a
// container-joined namespace through the production chain.
//
// Podman copies those onto the pod's infra container, and the pod's members
// inherit them (pkg/api/handlers/libpod/pods.go:46-65,
// pkg/specgen/generate/container_create.go:717-756), but the pod body never
// passed through the container create inspector, so with every pod option off a
// rule allowing the route reached the daemon with a host bind, a host device, a
// sysctl, an unconfined seccomp profile and another container's namespace. Each
// case first runs against the default (libpod_container_create unset), where it
// must be refused, then with the matching container option opened, where it
// must reach the daemon.
func TestServeChainLibpodPodCreateAppliesTheContainerGatesToInheritedFields(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		open       func(*config.LibpodContainerCreateRequestBodyConfig)
		wantReason string
	}{
		{
			name:       "host bind mount",
			body:       `{"name":"p","mounts":[{"type":"bind","source":"/etc","destination":"/h"}]}`,
			open:       func(c *config.LibpodContainerCreateRequestBodyConfig) { c.AllowedBindMounts = []string{"/etc"} },
			wantReason: `libpod pod create denied: bind mount source "/etc" is not allowlisted`,
		},
		{
			name:       "bind mount named by a bind option",
			body:       `{"name":"p","mounts":[{"type":"none","source":"/","destination":"/h","options":["rbind"]}]}`,
			open:       func(c *config.LibpodContainerCreateRequestBodyConfig) { c.AllowedBindMounts = []string{"/"} },
			wantReason: `libpod pod create denied: bind mount source "/" is not allowlisted`,
		},
		{
			name:       "host device",
			body:       `{"name":"p","pod_devices":["/dev/mem:/dev/mem:rwm"]}`,
			open:       func(c *config.LibpodContainerCreateRequestBodyConfig) { c.AllowedDevices = []string{"/dev/mem"} },
			wantReason: `libpod pod create denied: device "/dev/mem:/dev/mem:rwm" is not allowlisted`,
		},
		{
			name:       "sysctl",
			body:       `{"name":"p","sysctl":{"net.ipv4.ip_forward":"1"}}`,
			open:       func(c *config.LibpodContainerCreateRequestBodyConfig) { c.AllowSysctls = true },
			wantReason: "libpod pod create denied: setting sysctls is not allowed",
		},
		{
			name:       "unconfined seccomp",
			body:       `{"name":"p","security_opt":["seccomp=unconfined"]}`,
			open:       func(c *config.LibpodContainerCreateRequestBodyConfig) { c.DenyUnconfinedSeccomp = false },
			wantReason: "libpod pod create denied: unconfined seccomp profile is not allowed",
		},
		{
			name:       "unconfined apparmor",
			body:       `{"name":"p","security_opt":["apparmor:unconfined"]}`,
			open:       func(c *config.LibpodContainerCreateRequestBodyConfig) { c.DenyUnconfinedAppArmor = false },
			wantReason: "libpod pod create denied: unconfined apparmor profile is not allowed",
		},
		{
			name:       "selinux disabled",
			body:       `{"name":"p","security_opt":["label=disable"]}`,
			open:       func(c *config.LibpodContainerCreateRequestBodyConfig) { c.DenySelinuxDisable = false },
			wantReason: "libpod pod create denied: selinux disable is not allowed",
		},
		{
			name:       "joining another container's network namespace",
			body:       `{"name":"p","netns":{"nsmode":"container","value":"victim"}}`,
			open:       func(c *config.LibpodContainerCreateRequestBodyConfig) { c.RestrictNamespaceSharing = false },
			wantReason: "libpod pod create denied: network namespace sharing with another container is not allowed",
		},
		{
			// The pod's own allow_host_pid already refuses a path join, so this is
			// refused whatever the container block says and has no opened run.
			name:       "joining a namespace by path",
			body:       `{"name":"p","pidns":{"nsmode":"path","value":"/proc/1/ns/pid"}}`,
			wantReason: "libpod pod create denied: PID namespace joined by path is not allowed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// "closed" is the shape the protection is for: the container block
			// is configured and the pod block is left alone.
			closed := func(c *config.LibpodContainerCreateRequestBodyConfig) {
				c.DenyUnconfinedSeccomp = true
				c.DenyUnconfinedAppArmor = true
				c.DenySelinuxDisable = true
				c.RestrictNamespaceSharing = true
			}
			for _, opened := range []bool{false, true} {
				if opened && tt.open == nil {
					continue
				}
				daemon := &libpodPodCreateCounterDaemon{}
				addr := newEngineChain(t, "libpod-pod-inherited", daemon, func(cfg *config.Config) {
					cfg.Response.DenyVerbosity = "verbose"
					c := &cfg.RequestBody.LibpodContainerCreate
					closed(c)
					if opened {
						tt.open(c)
					}
					cfg.Rules = []config.RuleConfig{
						{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/pods/create"}, Action: "allow"},
						{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
					}
				})
				req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v5.8.6/libpod/pods/create", strings.NewReader(tt.body))
				if err != nil {
					t.Fatalf("new request: %v", err)
				}
				resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
				if err != nil {
					t.Fatalf("POST pod create: %v", err)
				}
				respBody, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if opened {
					if resp.StatusCode != http.StatusCreated || daemon.created.Load() != 1 {
						t.Errorf("opened: status = %d, daemon creates = %d, want 201 and 1; body: %s", resp.StatusCode, daemon.created.Load(), respBody)
					}
					continue
				}
				if resp.StatusCode != http.StatusForbidden || daemon.created.Load() != 0 {
					t.Errorf("closed: status = %d, daemon creates = %d, want 403 and 0; body: %s", resp.StatusCode, daemon.created.Load(), respBody)
				}
				var denial struct {
					Reason string `json:"reason"`
				}
				if err := json.Unmarshal(respBody, &denial); err != nil || !strings.HasPrefix(denial.Reason, tt.wantReason) {
					t.Errorf("closed: body = %s, want a reason starting with %q", respBody, tt.wantReason)
				}
			}
		})
	}
}
