package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// presetCreateDaemon counts the container creates and starts that reach it. A
// request that arrives has been accepted by the whole chain.
type presetCreateDaemon struct {
	podman bool
	// silentVersion answers GET /version without naming an engine, which the
	// flavor probe reads as an unknown upstream.
	silentVersion bool
	created       atomic.Int32
	started       atomic.Int32
	// networkOps counts the network connect and disconnect requests that reach it.
	networkOps atomic.Int32
}

func (d *presetCreateDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		if d.silentVersion {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		_ = json.NewEncoder(w).Encode(engineChainVersion(d.podman))
	case r.Method == http.MethodPost && normPath == "/containers/create":
		_, _ = io.Copy(io.Discard, r.Body)
		d.created.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "c1"})
	case r.Method == http.MethodPost && strings.HasPrefix(normPath, "/containers/") && strings.HasSuffix(normPath, "/start"):
		_, _ = io.Copy(io.Discard, r.Body)
		d.started.Add(1)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && strings.HasPrefix(normPath, "/networks/") &&
		(strings.HasSuffix(normPath, "/connect") || strings.HasSuffix(normPath, "/disconnect")):
		_, _ = io.Copy(io.Discard, r.Body)
		d.networkOps.Add(1)
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// newPresetChain loads a shipped preset from app/configs and serves it through
// the production chain in front of daemon, so a test proves what a stock
// install does rather than what a hand-built config does.
func newPresetChain(t *testing.T, label, preset string, daemon http.Handler, tweak func(*config.Config)) string {
	t.Helper()
	loaded, err := config.Load(filepath.Join("..", "..", "configs", preset))
	if err != nil {
		t.Fatalf("load preset %s: %v", preset, err)
	}
	return newEngineChain(t, label, daemon, func(cfg *config.Config) {
		socket := cfg.Upstream.Socket
		*cfg = *loaded
		cfg.Upstream.Socket = socket
		cfg.Health.Enabled = false
		cfg.Log.AccessLog = false
		cfg.Response.DenyVerbosity = "verbose"
		if tweak != nil {
			tweak(cfg)
		}
	})
}

// presetChainPost sends one request and returns the status and body.
func presetChainPost(t *testing.T, addr, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// TestPresetChainDrydockRefusesWritableCgroups pins that the shipped drydock
// preset refuses the writable-cgroups SecurityOpt before it reaches dockerd.
func TestPresetChainDrydockRefusesWritableCgroups(t *testing.T) {
	for _, opt := range []string{"writable-cgroups", "writable-cgroups=true", "writable-cgroups:1", "Writable-Cgroups=T"} {
		t.Run(opt, func(t *testing.T) {
			daemon := &presetCreateDaemon{}
			addr := newPresetChain(t, "preset-wcg", "drydock.yaml", daemon, nil)
			for _, path := range []string{"/containers/create", "/v1.53/containers/create"} {
				status, body := presetChainPost(t, addr, path, `{"Image":"alpine","HostConfig":{"SecurityOpt":["`+opt+`"]}}`)
				if status != http.StatusForbidden || !strings.Contains(body, "writable-cgroups") {
					t.Errorf("%s: status = %d, body = %s, want 403 naming writable-cgroups", path, status, body)
				}
			}
			if daemon.created.Load() != 0 {
				t.Errorf("daemon creates = %d, want 0", daemon.created.Load())
			}
		})
	}
}

// cisCompliantHostConfig satisfies every hardening rail the CIS preset
// requires, so a test can vary one field and see only that field refused.
const cisCompliantHostConfig = `"CapDrop":["ALL"],"ReadonlyRootfs":true,"Memory":1048576,"NanoCpus":1000000000,"PidsLimit":100`

// TestPresetChainCISRefusesInlineSeccomp pins that the shipped CIS preset,
// which sets deny_unconfined_seccomp without a profile allowlist, refuses an
// inline seccomp document before it reaches dockerd.
func TestPresetChainCISRefusesInlineSeccomp(t *testing.T) {
	inline := `{\"defaultAction\":\"SCMP_ACT_ALLOW\"}`
	daemon := &presetCreateDaemon{}
	addr := newPresetChain(t, "preset-cis-seccomp", "cis-docker-benchmark.yaml", daemon, nil)

	status, body := presetChainPost(t, addr, "/v1.53/containers/create", `{"Image":"alpine","HostConfig":{`+cisCompliantHostConfig+`,"SecurityOpt":["no-new-privileges:true","seccomp=`+inline+`"]}}`)
	if status != http.StatusForbidden || !strings.Contains(body, "inline seccomp") {
		t.Errorf("inline seccomp: status = %d, body = %s, want 403 naming the inline profile", status, body)
	}
	status, body = presetChainPost(t, addr, "/containers/create", `{"Image":"alpine","HostConfig":{`+cisCompliantHostConfig+`,"SecurityOpt":["no-new-privileges:true","seccomp={}"]}}`)
	if status != http.StatusForbidden || !strings.Contains(body, "inline seccomp") {
		t.Errorf("empty inline seccomp: status = %d, body = %s, want 403 naming the inline profile", status, body)
	}
	if daemon.created.Load() != 0 {
		t.Fatalf("daemon creates = %d, want 0", daemon.created.Load())
	}

	status, body = presetChainPost(t, addr, "/containers/create", `{"Image":"alpine","HostConfig":{`+cisCompliantHostConfig+`,"SecurityOpt":["no-new-privileges:true"]}}`)
	if status != http.StatusCreated || daemon.created.Load() != 1 {
		t.Errorf("compliant create: status = %d, creates = %d, body = %s, want 201 and 1", status, daemon.created.Load(), body)
	}
}

// TestPresetChainDrydockRefusesCompatAnnotationsOnPodman pins that the shipped
// drydock preset refuses the compat HostConfig.Annotations keys Podman acts on
// (run.oci.* and io.podman.annotations.cid-file, which Podman removes as a
// host path when the container is deleted), and that an upstream whose flavor is pinned
// rather than probed is held to the same refusal. A known Docker upstream keeps
// annotations as plain metadata and still passes.
func TestPresetChainDrydockRefusesCompatAnnotationsOnPodman(t *testing.T) {
	bodies := map[string]string{
		"cid-file": `{"Image":"alpine","HostConfig":{"Annotations":{"io.podman.annotations.cid-file":"/etc/hostname"}}}`,
		"run.oci":  `{"Image":"alpine","HostConfig":{"Annotations":{"run.oci.keep_original_groups":"1"}}}`,
	}
	for name, body := range bodies {
		t.Run(name+" podman", func(t *testing.T) {
			daemon := &presetCreateDaemon{podman: true}
			addr := newPresetChain(t, "preset-ann-podman", "drydock.yaml", daemon, nil)
			for _, path := range []string{"/containers/create", "/v5.8.6/containers/create"} {
				status, out := presetChainPost(t, addr, path, body)
				if status != http.StatusForbidden || !strings.Contains(out, "runtime annotation") {
					t.Errorf("%s: status = %d, body = %s, want 403 naming the annotation", path, status, out)
				}
			}
			if daemon.created.Load() != 0 {
				t.Errorf("daemon creates = %d, want 0", daemon.created.Load())
			}
		})
		t.Run(name+" unprobed flavor", func(t *testing.T) {
			// An operator-pinned flavor is not a probe result, so the gate
			// stays on even when the pin says docker.
			daemon := &presetCreateDaemon{silentVersion: true}
			addr := newPresetChain(t, "preset-ann-unprobed", "drydock.yaml", daemon, func(cfg *config.Config) { cfg.Upstream.Flavor = "docker" })
			status, out := presetChainPost(t, addr, "/containers/create", body)
			if status != http.StatusForbidden || !strings.Contains(out, "runtime annotation") {
				t.Errorf("status = %d, body = %s, want 403 naming the annotation", status, out)
			}
			if daemon.created.Load() != 0 {
				t.Errorf("daemon creates = %d, want 0", daemon.created.Load())
			}
		})
		t.Run(name+" docker", func(t *testing.T) {
			daemon := &presetCreateDaemon{}
			addr := newPresetChain(t, "preset-ann-docker", "drydock.yaml", daemon, nil)
			status, out := presetChainPost(t, addr, "/containers/create", body)
			if status != http.StatusCreated || daemon.created.Load() != 1 {
				t.Errorf("status = %d, creates = %d, body = %s, want 201 and 1", status, daemon.created.Load(), out)
			}
		})
	}
}

// TestPresetChainDrydockRefusesRootLevelHostConfig pins that the shipped
// drydock preset refuses a create whose HostConfig fields sit at the top of
// the body, where Docker 24 to 26 read them from, before dockerd sees it.
func TestPresetChainDrydockRefusesRootLevelHostConfig(t *testing.T) {
	bodies := map[string]string{
		"no HostConfig":    `{"Image":"alpine","Privileged":true,"Binds":["/:/host"]}`,
		"null HostConfig":  `{"Image":"alpine","HostConfig":null,"Privileged":true,"Binds":["/:/host"]}`,
		"empty HostConfig": `{"Image":"alpine","HostConfig":{},"binds":["/:/host"]}`,
		"escaped key":      `{"Image":"alpine","\u0050rivileged":true}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			daemon := &presetCreateDaemon{}
			addr := newPresetChain(t, "preset-rootcfg", "drydock.yaml", daemon, nil)
			for _, path := range []string{"/containers/create", "/v1.45/containers/create", "/v1.23/containers/create"} {
				status, out := presetChainPost(t, addr, path, body)
				if status != http.StatusForbidden || !strings.Contains(out, "top level") {
					t.Errorf("%s: status = %d, body = %s, want 403 naming the top-level field", path, status, out)
				}
			}
			if daemon.created.Load() != 0 {
				t.Errorf("daemon creates = %d, want 0", daemon.created.Load())
			}
		})
	}
	daemon := &presetCreateDaemon{}
	addr := newPresetChain(t, "preset-rootcfg-ok", "drydock.yaml", daemon, nil)
	status, out := presetChainPost(t, addr, "/containers/create", `{"Image":"alpine","HostConfig":{"ReadonlyRootfs":true}}`)
	if status != http.StatusCreated || daemon.created.Load() != 1 {
		t.Errorf("nested create: status = %d, creates = %d, body = %s, want 201 and 1", status, daemon.created.Load(), out)
	}
}

// TestPresetChainDrydockRefusesStartBody pins that the shipped drydock preset
// refuses a start request that carries a body, which Docker 24 applies as the
// container's HostConfig below API 1.24, and that a plain start still passes.
func TestPresetChainDrydockRefusesStartBody(t *testing.T) {
	const hostConfig = `{"Privileged":true,"Binds":["/:/host"]}`
	daemon := &presetCreateDaemon{}
	addr := newPresetChain(t, "preset-start", "drydock.yaml", daemon, nil)
	for _, path := range []string{"/containers/abc/start", "/v1.23/containers/abc/start", "/v1.45/containers/abc/start"} {
		status, out := presetChainPost(t, addr, path, hostConfig)
		if status != http.StatusForbidden || !strings.Contains(out, "container start denied") {
			t.Errorf("%s: status = %d, body = %s, want 403 naming the start body", path, status, out)
		}
	}
	if daemon.started.Load() != 0 {
		t.Fatalf("daemon starts = %d, want 0", daemon.started.Load())
	}
	status, out := presetChainPost(t, addr, "/v1.23/containers/abc/start", "")
	if status != http.StatusNoContent || daemon.started.Load() != 1 {
		t.Errorf("plain start: status = %d, starts = %d, body = %s, want 204 and 1", status, daemon.started.Load(), out)
	}
}

// TestPresetChainPortainerGatesSlashBearingNetworkNames pins that a network
// whose name holds a slash is held to the same endpoint-config and
// force-disconnect gates as any other. Docker registers connect and
// disconnect as /networks/{id:.*}/..., so POST /networks/a/b/connect names the
// network "a/b", and a matcher that stopped at the first slash skipped the
// gates for it. The shipped Portainer preset allows /networks/** and leaves the
// gates at their defaults.
func TestPresetChainPortainerGatesSlashBearingNetworkNames(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want string
	}{
		{"static ip", "/networks/a/b/connect", `{"Container":"c","EndpointConfig":{"IPAMConfig":{"IPv4Address":"10.0.0.9"}}}`, "static IP"},
		{"mac pinning", "/v1.45/networks/a/b/connect", `{"Container":"c","EndpointConfig":{"MacAddress":"02:42:ac:11:00:02"}}`, "MAC address"},
		{"links", "/networks/a/b/c/connect", `{"Container":"c","EndpointConfig":{"Links":["x"]}}`, "links"},
		{"driver opts", "/networks/a/b/connect", `{"Container":"c","EndpointConfig":{"DriverOpts":{"k":"v"}}}`, "driver options"},
		{"force disconnect", "/v1.45/networks/a/b/disconnect", `{"Container":"c","Force":true}`, "force disconnect"},
		{"escaped slash", "/networks/a%2Fb/connect", `{"Container":"c","EndpointConfig":{"Links":["x"]}}`, "links"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &presetCreateDaemon{}
			addr := newPresetChain(t, "preset-netslash", "portainer.yaml", daemon, nil)
			status, out := presetChainPost(t, addr, tt.path, tt.body)
			if status != http.StatusForbidden || !strings.Contains(out, tt.want) {
				t.Errorf("status = %d, body = %s, want 403 naming %q", status, out, tt.want)
			}
			if daemon.networkOps.Load() != 0 {
				t.Errorf("daemon network operations = %d, want 0", daemon.networkOps.Load())
			}
		})
	}

	daemon := &presetCreateDaemon{}
	addr := newPresetChain(t, "preset-netslash-ok", "portainer.yaml", daemon, nil)
	for _, path := range []string{"/networks/app/connect", "/networks/a/b/connect"} {
		status, out := presetChainPost(t, addr, path, `{"Container":"c"}`)
		if status != http.StatusOK {
			t.Errorf("%s: plain connect status = %d, body = %s, want 200", path, status, out)
		}
	}
	if daemon.networkOps.Load() != 2 {
		t.Errorf("daemon network operations = %d, want 2", daemon.networkOps.Load())
	}
}

// TestNetworkMembershipCatalogEntriesTakeSlashBearingIdentifiers pins that the
// Docker connect and disconnect catalog rows carry the slash-bearing identifier
// shape, since moby registers both as /networks/{id:.*}/..., while the libpod
// rows stay single-segment like Podman's own {name} placeholder.
func TestNetworkMembershipCatalogEntriesTakeSlashBearingIdentifiers(t *testing.T) {
	want := map[string]catalogIdentifierShape{
		"/networks/sockguard-test/connect":    catalogIdentifierPath,
		"/networks/sockguard-test/disconnect": catalogIdentifierPath,
	}
	seen := map[string]bool{}
	for _, endpoint := range bodySensitiveWriteEndpoints {
		shape, ok := want[endpoint.path]
		if !ok {
			continue
		}
		seen[endpoint.path] = true
		if endpoint.identifierShape != shape {
			t.Errorf("%s identifierShape = %v, want %v", endpoint.path, endpoint.identifierShape, shape)
		}
	}
	for path := range want {
		if !seen[path] {
			t.Errorf("catalog is missing %s", path)
		}
	}
	for _, endpoint := range bodySensitiveWriteEndpoints {
		if strings.HasPrefix(endpoint.path, "/libpod/networks/sockguard-test/") && endpoint.identifierShape == catalogIdentifierPath {
			t.Errorf("%s must stay single-segment", endpoint.path)
		}
	}
}

// TestPresetChainRefusesLegacyLinks pins that the shipped Portainer and Drydock
// presets refuse HostConfig.Links on create. A link to a foreign container
// registers /<linker>/<alias> as a name the victim answers to, which every
// slash-bearing container route then resolves to the victim.
func TestPresetChainRefusesLegacyLinks(t *testing.T) {
	for _, preset := range []string{"portainer.yaml", "drydock.yaml"} {
		t.Run(preset, func(t *testing.T) {
			daemon := &presetCreateDaemon{}
			addr := newPresetChain(t, "preset-links", preset, daemon, nil)
			for _, path := range []string{"/containers/create", "/v1.45/containers/create"} {
				status, out := presetChainPost(t, addr, path, `{"Image":"alpine","HostConfig":{"Links":["victim:x"]}}`)
				if status != http.StatusForbidden || !strings.Contains(out, "legacy container links") {
					t.Errorf("%s: status = %d, body = %s, want 403 naming legacy links", path, status, out)
				}
			}
			if daemon.created.Load() != 0 {
				t.Errorf("daemon creates = %d, want 0", daemon.created.Load())
			}
		})
	}
}

// TestPresetChainPortainerStartAllowsEmptyObjectBody pins that Portainer's UI,
// which posts `{}` with every start, still reaches dockerd through the shipped
// portainer preset, while a HostConfig-sized body stays refused.
func TestPresetChainPortainerStartAllowsEmptyObjectBody(t *testing.T) {
	daemon := &presetCreateDaemon{}
	addr := newPresetChain(t, "preset-portainer-start", "portainer.yaml", daemon, nil)
	for _, path := range []string{"/containers/abc/start", "/v1.45/containers/abc/start"} {
		status, out := presetChainPost(t, addr, path, `{}`)
		if status != http.StatusNoContent {
			t.Errorf("%s: status = %d, body = %s, want 204", path, status, out)
		}
	}
	if daemon.started.Load() != 2 {
		t.Fatalf("daemon starts = %d, want 2", daemon.started.Load())
	}
	status, out := presetChainPost(t, addr, "/v1.23/containers/abc/start", `{"Privileged":true,"Binds":["/:/host"]}`)
	if status != http.StatusForbidden || !strings.Contains(out, "container start denied") || daemon.started.Load() != 2 {
		t.Errorf("hostconfig start: status = %d, starts = %d, body = %s, want 403 and no new start", status, daemon.started.Load(), out)
	}
}

// TestPresetChainDrydockAllowsCompatAnnotationsWhenOpened pins that
// request_body.container_create.allow_runtime_annotations lifts the refusal on
// a Podman upstream, so the option is wired from config through the shipped
// drydock preset's chain.
func TestPresetChainDrydockAllowsCompatAnnotationsWhenOpened(t *testing.T) {
	bodies := map[string]string{
		"cid-file": `{"Image":"alpine","HostConfig":{"Annotations":{"io.podman.annotations.cid-file":"/etc/hostname"}}}`,
		"run.oci":  `{"Image":"alpine","HostConfig":{"Annotations":{"run.oci.keep_original_groups":"1"}}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			daemon := &presetCreateDaemon{podman: true}
			addr := newPresetChain(t, "preset-ann-open", "drydock.yaml", daemon, func(cfg *config.Config) {
				cfg.RequestBody.ContainerCreate.AllowRuntimeAnnotations = true
			})
			status, out := presetChainPost(t, addr, "/containers/create", body)
			if status != http.StatusCreated || daemon.created.Load() != 1 {
				t.Errorf("status = %d, creates = %d, body = %s, want 201 and 1", status, daemon.created.Load(), out)
			}
		})
	}
}
