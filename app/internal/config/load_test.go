package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzLoadYAML(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("listen:\n  address: 127.0.0.1:2375\n"))
	f.Add([]byte("rules:\n  - match: { method: GET, path: /_ping }\n    action: allow\n"))
	f.Add([]byte("rules: definitely-not-a-list\n"))

	f.Fuzz(func(t *testing.T, yaml []byte) {
		restoreEnv := snapshotSockguardEnv(t)
		defer restoreEnv()

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "fuzz.yaml")
		if err := os.WriteFile(cfgPath, yaml, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		_, _ = Load(cfgPath)
	})
}

func snapshotSockguardEnv(t *testing.T) func() {
	t.Helper()

	type envVar struct {
		name    string
		value   string
		present bool
	}

	var saved []envVar
	for _, kv := range os.Environ() {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(name, "SOCKGUARD_") {
			continue
		}
		saved = append(saved, envVar{name: name, value: value, present: true})
	}

	return func() {
		for _, kv := range os.Environ() {
			name, _, ok := strings.Cut(kv, "=")
			if ok && strings.HasPrefix(name, "SOCKGUARD_") {
				_ = os.Unsetenv(name)
			}
		}
		for _, env := range saved {
			if env.present {
				_ = os.Setenv(env.name, env.value)
			}
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	// Load with non-existent file — should return defaults
	cfg, err := Load("/nonexistent/path.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	defaults := Defaults()

	// The default listener must stay loopback-only so the built-in config is safe
	// without exposing the Docker API proxy on the network.
	if defaults.Listen.Address != "127.0.0.1:2375" {
		t.Errorf("Defaults().Listen.Address = %q, want %q", defaults.Listen.Address, "127.0.0.1:2375")
	}
	if defaults.Listen.Socket != "" {
		t.Errorf("Defaults().Listen.Socket = %q, want empty (opt-in only)", defaults.Listen.Socket)
	}

	if cfg.Listen.Socket != defaults.Listen.Socket {
		t.Errorf("Listen.Socket = %q, want %q", cfg.Listen.Socket, defaults.Listen.Socket)
	}
	if cfg.Listen.Address != defaults.Listen.Address {
		t.Errorf("Listen.Address = %q, want %q", cfg.Listen.Address, defaults.Listen.Address)
	}
	if cfg.Upstream.Socket != defaults.Upstream.Socket {
		t.Errorf("Upstream.Socket = %q, want %q", cfg.Upstream.Socket, defaults.Upstream.Socket)
	}
	if cfg.Log.Level != defaults.Log.Level {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, defaults.Log.Level)
	}
	if cfg.Log.Format != defaults.Log.Format {
		t.Errorf("Log.Format = %q, want %q", cfg.Log.Format, defaults.Log.Format)
	}
	if cfg.Log.Output != defaults.Log.Output {
		t.Errorf("Log.Output = %q, want %q", cfg.Log.Output, defaults.Log.Output)
	}
	if cfg.Response.DenyVerbosity != defaults.Response.DenyVerbosity {
		t.Errorf("Response.DenyVerbosity = %q, want %q", cfg.Response.DenyVerbosity, defaults.Response.DenyVerbosity)
	}
	if cfg.Response.RedactContainerEnv != defaults.Response.RedactContainerEnv {
		t.Errorf("Response.RedactContainerEnv = %v, want %v", cfg.Response.RedactContainerEnv, defaults.Response.RedactContainerEnv)
	}
	if cfg.Response.RedactMountPaths != defaults.Response.RedactMountPaths {
		t.Errorf("Response.RedactMountPaths = %v, want %v", cfg.Response.RedactMountPaths, defaults.Response.RedactMountPaths)
	}
	if cfg.Response.RedactNetworkTopology != defaults.Response.RedactNetworkTopology {
		t.Errorf("Response.RedactNetworkTopology = %v, want %v", cfg.Response.RedactNetworkTopology, defaults.Response.RedactNetworkTopology)
	}
	if len(cfg.Response.VisibleResourceLabels) != len(defaults.Response.VisibleResourceLabels) {
		t.Errorf("got %d Response.VisibleResourceLabels, want %d", len(cfg.Response.VisibleResourceLabels), len(defaults.Response.VisibleResourceLabels))
	}
	if cfg.RequestBody.ContainerCreate.AllowPrivileged != defaults.RequestBody.ContainerCreate.AllowPrivileged {
		t.Errorf(
			"RequestBody.ContainerCreate.AllowPrivileged = %v, want %v",
			cfg.RequestBody.ContainerCreate.AllowPrivileged,
			defaults.RequestBody.ContainerCreate.AllowPrivileged,
		)
	}
	if cfg.RequestBody.ContainerCreate.AllowHostNetwork != defaults.RequestBody.ContainerCreate.AllowHostNetwork {
		t.Errorf(
			"RequestBody.ContainerCreate.AllowHostNetwork = %v, want %v",
			cfg.RequestBody.ContainerCreate.AllowHostNetwork,
			defaults.RequestBody.ContainerCreate.AllowHostNetwork,
		)
	}
	if len(cfg.RequestBody.ContainerCreate.AllowedBindMounts) != len(defaults.RequestBody.ContainerCreate.AllowedBindMounts) {
		t.Errorf(
			"got %d RequestBody.ContainerCreate.AllowedBindMounts, want %d",
			len(cfg.RequestBody.ContainerCreate.AllowedBindMounts),
			len(defaults.RequestBody.ContainerCreate.AllowedBindMounts),
		)
	}
	if cfg.RequestBody.Exec.AllowPrivileged != defaults.RequestBody.Exec.AllowPrivileged {
		t.Errorf("RequestBody.Exec.AllowPrivileged = %v, want %v", cfg.RequestBody.Exec.AllowPrivileged, defaults.RequestBody.Exec.AllowPrivileged)
	}
	if cfg.RequestBody.Exec.AllowRootUser != defaults.RequestBody.Exec.AllowRootUser {
		t.Errorf("RequestBody.Exec.AllowRootUser = %v, want %v", cfg.RequestBody.Exec.AllowRootUser, defaults.RequestBody.Exec.AllowRootUser)
	}
	if len(cfg.RequestBody.Exec.AllowedCommands) != len(defaults.RequestBody.Exec.AllowedCommands) {
		t.Errorf("got %d RequestBody.Exec.AllowedCommands, want %d", len(cfg.RequestBody.Exec.AllowedCommands), len(defaults.RequestBody.Exec.AllowedCommands))
	}
	if cfg.RequestBody.ImagePull.AllowImports != defaults.RequestBody.ImagePull.AllowImports {
		t.Errorf("RequestBody.ImagePull.AllowImports = %v, want %v", cfg.RequestBody.ImagePull.AllowImports, defaults.RequestBody.ImagePull.AllowImports)
	}
	if cfg.RequestBody.ImagePull.AllowAllRegistries != defaults.RequestBody.ImagePull.AllowAllRegistries {
		t.Errorf("RequestBody.ImagePull.AllowAllRegistries = %v, want %v", cfg.RequestBody.ImagePull.AllowAllRegistries, defaults.RequestBody.ImagePull.AllowAllRegistries)
	}
	if cfg.RequestBody.ImagePull.AllowOfficial != defaults.RequestBody.ImagePull.AllowOfficial {
		t.Errorf("RequestBody.ImagePull.AllowOfficial = %v, want %v", cfg.RequestBody.ImagePull.AllowOfficial, defaults.RequestBody.ImagePull.AllowOfficial)
	}
	if len(cfg.RequestBody.ImagePull.AllowedRegistries) != len(defaults.RequestBody.ImagePull.AllowedRegistries) {
		t.Errorf("got %d RequestBody.ImagePull.AllowedRegistries, want %d", len(cfg.RequestBody.ImagePull.AllowedRegistries), len(defaults.RequestBody.ImagePull.AllowedRegistries))
	}
	if cfg.RequestBody.Build.AllowRemoteContext != defaults.RequestBody.Build.AllowRemoteContext {
		t.Errorf("RequestBody.Build.AllowRemoteContext = %v, want %v", cfg.RequestBody.Build.AllowRemoteContext, defaults.RequestBody.Build.AllowRemoteContext)
	}
	if cfg.RequestBody.Build.AllowHostNetwork != defaults.RequestBody.Build.AllowHostNetwork {
		t.Errorf("RequestBody.Build.AllowHostNetwork = %v, want %v", cfg.RequestBody.Build.AllowHostNetwork, defaults.RequestBody.Build.AllowHostNetwork)
	}
	if cfg.RequestBody.Build.AllowRunInstructions != defaults.RequestBody.Build.AllowRunInstructions {
		t.Errorf("RequestBody.Build.AllowRunInstructions = %v, want %v", cfg.RequestBody.Build.AllowRunInstructions, defaults.RequestBody.Build.AllowRunInstructions)
	}
	if cfg.Ownership.Owner != defaults.Ownership.Owner {
		t.Errorf("Ownership.Owner = %q, want %q", cfg.Ownership.Owner, defaults.Ownership.Owner)
	}
	if cfg.Ownership.LabelKey != defaults.Ownership.LabelKey {
		t.Errorf("Ownership.LabelKey = %q, want %q", cfg.Ownership.LabelKey, defaults.Ownership.LabelKey)
	}
	if cfg.Ownership.AllowUnownedImages != defaults.Ownership.AllowUnownedImages {
		t.Errorf("Ownership.AllowUnownedImages = %v, want %v", cfg.Ownership.AllowUnownedImages, defaults.Ownership.AllowUnownedImages)
	}
	if got := len(cfg.Clients.AllowedCIDRs); got != 0 {
		t.Errorf("got %d Clients.AllowedCIDRs, want 0", got)
	}
	if cfg.Clients.ContainerLabels.LabelPrefix != defaults.Clients.ContainerLabels.LabelPrefix {
		t.Errorf(
			"Clients.ContainerLabels.LabelPrefix = %q, want %q",
			cfg.Clients.ContainerLabels.LabelPrefix,
			defaults.Clients.ContainerLabels.LabelPrefix,
		)
	}
	if len(cfg.Rules) != len(defaults.Rules) {
		t.Errorf("got %d rules, want %d", len(cfg.Rules), len(defaults.Rules))
	}
}

func TestLoadYAMLOverrides(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")

	yaml := `
upstream:
  socket: /custom/docker.sock
log:
  level: debug
response:
  deny_verbosity: minimal
  redact_container_env: false
  redact_mount_paths: false
  redact_network_topology: false
  visible_resource_labels:
    - com.sockguard.visible=true
request_body:
  container_create:
    allow_host_network: true
    allowed_bind_mounts:
      - /srv/data
      - /var/lib/sockguard
  exec:
    allow_root_user: true
    allowed_commands:
      - ["/usr/local/bin/pre-update", "--check"]
  image_pull:
    allow_all_registries: true
    allowed_registries:
      - ghcr.io
      - quay.io
  build:
    allow_remote_context: true
    allow_host_network: true
    allow_run_instructions: true
ownership:
  owner: ci-job-123
  label_key: com.example.owner
  allow_unowned_images: false
clients:
  allowed_cidrs:
    - 10.10.0.0/16
    - 192.0.2.0/24
  container_labels:
    enabled: true
    label_prefix: socket-proxy.allow.
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Upstream.Socket != "/custom/docker.sock" {
		t.Errorf("Upstream.Socket = %q, want /custom/docker.sock", cfg.Upstream.Socket)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want debug", cfg.Log.Level)
	}
	if cfg.Response.DenyVerbosity != "minimal" {
		t.Errorf("Response.DenyVerbosity = %q, want minimal", cfg.Response.DenyVerbosity)
	}
	if cfg.Response.RedactContainerEnv {
		t.Errorf("Response.RedactContainerEnv = %v, want false", cfg.Response.RedactContainerEnv)
	}
	if cfg.Response.RedactMountPaths {
		t.Errorf("Response.RedactMountPaths = %v, want false", cfg.Response.RedactMountPaths)
	}
	if cfg.Response.RedactNetworkTopology {
		t.Errorf("Response.RedactNetworkTopology = %v, want false", cfg.Response.RedactNetworkTopology)
	}
	if got := cfg.Response.VisibleResourceLabels; len(got) != 1 || got[0] != "com.sockguard.visible=true" {
		t.Errorf("Response.VisibleResourceLabels = %#v, want [com.sockguard.visible=true]", got)
	}
	if !cfg.RequestBody.ContainerCreate.AllowHostNetwork {
		t.Errorf("RequestBody.ContainerCreate.AllowHostNetwork = %v, want true", cfg.RequestBody.ContainerCreate.AllowHostNetwork)
	}
	if got := cfg.RequestBody.ContainerCreate.AllowedBindMounts; len(got) != 2 || got[0] != "/srv/data" || got[1] != "/var/lib/sockguard" {
		t.Errorf("RequestBody.ContainerCreate.AllowedBindMounts = %#v, want [/srv/data /var/lib/sockguard]", got)
	}
	if !cfg.RequestBody.Exec.AllowRootUser {
		t.Errorf("RequestBody.Exec.AllowRootUser = %v, want true", cfg.RequestBody.Exec.AllowRootUser)
	}
	if got := cfg.RequestBody.Exec.AllowedCommands; len(got) != 1 || len(got[0]) != 2 || got[0][0] != "/usr/local/bin/pre-update" || got[0][1] != "--check" {
		t.Errorf("RequestBody.Exec.AllowedCommands = %#v, want [[/usr/local/bin/pre-update --check]]", got)
	}
	if !cfg.RequestBody.ImagePull.AllowAllRegistries {
		t.Errorf("RequestBody.ImagePull.AllowAllRegistries = %v, want true", cfg.RequestBody.ImagePull.AllowAllRegistries)
	}
	if got := cfg.RequestBody.ImagePull.AllowedRegistries; len(got) != 2 || got[0] != "ghcr.io" || got[1] != "quay.io" {
		t.Errorf("RequestBody.ImagePull.AllowedRegistries = %#v, want [ghcr.io quay.io]", got)
	}
	if !cfg.RequestBody.Build.AllowRemoteContext {
		t.Errorf("RequestBody.Build.AllowRemoteContext = %v, want true", cfg.RequestBody.Build.AllowRemoteContext)
	}
	if !cfg.RequestBody.Build.AllowHostNetwork {
		t.Errorf("RequestBody.Build.AllowHostNetwork = %v, want true", cfg.RequestBody.Build.AllowHostNetwork)
	}
	if !cfg.RequestBody.Build.AllowRunInstructions {
		t.Errorf("RequestBody.Build.AllowRunInstructions = %v, want true", cfg.RequestBody.Build.AllowRunInstructions)
	}
	if cfg.Ownership.Owner != "ci-job-123" {
		t.Errorf("Ownership.Owner = %q, want ci-job-123", cfg.Ownership.Owner)
	}
	if cfg.Ownership.LabelKey != "com.example.owner" {
		t.Errorf("Ownership.LabelKey = %q, want com.example.owner", cfg.Ownership.LabelKey)
	}
	if cfg.Ownership.AllowUnownedImages {
		t.Errorf("Ownership.AllowUnownedImages = %v, want false", cfg.Ownership.AllowUnownedImages)
	}
	if got := cfg.Clients.AllowedCIDRs; len(got) != 2 || got[0] != "10.10.0.0/16" || got[1] != "192.0.2.0/24" {
		t.Errorf("Clients.AllowedCIDRs = %#v, want [10.10.0.0/16 192.0.2.0/24]", got)
	}
	if !cfg.Clients.ContainerLabels.Enabled {
		t.Errorf("Clients.ContainerLabels.Enabled = %v, want true", cfg.Clients.ContainerLabels.Enabled)
	}
	if cfg.Clients.ContainerLabels.LabelPrefix != "socket-proxy.allow." {
		t.Errorf("Clients.ContainerLabels.LabelPrefix = %q, want socket-proxy.allow.", cfg.Clients.ContainerLabels.LabelPrefix)
	}
	// YAML provided rules should override defaults
	if len(cfg.Rules) != 1 {
		t.Errorf("got %d rules, want 1", len(cfg.Rules))
	}
}

func TestLoadYAMLOverridesClientProfiles(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "profiles.yaml")

	yaml := `
listen:
  address: 127.0.0.1:2376
  tls:
    cert_file: /certs/server.pem
    key_file: /certs/server-key.pem
    client_ca_file: /certs/ca.pem
clients:
  default_profile: readonly
  source_ip_profiles:
    - profile: watchtower
      cidrs:
        - 172.18.0.0/16
  client_certificate_profiles:
    - profile: portainer
      common_names:
        - portainer-admin
  profiles:
    - name: readonly
      response:
        visible_resource_labels:
          - com.sockguard.visible=true
      rules:
        - match: { method: GET, path: "/_ping" }
          action: allow
        - match: { method: "*", path: "/**" }
          action: deny
    - name: watchtower
      request_body:
        exec:
          allowed_commands:
            - ["/usr/local/bin/pre-update"]
      rules:
        - match: { method: POST, path: "/containers/*/exec" }
          action: allow
        - match: { method: POST, path: "/exec/*/start" }
          action: allow
        - match: { method: "*", path: "/**" }
          action: deny
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Clients.DefaultProfile != "readonly" {
		t.Fatalf("Clients.DefaultProfile = %q, want readonly", cfg.Clients.DefaultProfile)
	}
	if got := cfg.Clients.SourceIPProfiles; len(got) != 1 || got[0].Profile != "watchtower" || len(got[0].CIDRs) != 1 || got[0].CIDRs[0] != "172.18.0.0/16" {
		t.Fatalf("Clients.SourceIPProfiles = %#v, want watchtower assignment", got)
	}
	if got := cfg.Clients.ClientCertificateProfiles; len(got) != 1 || got[0].Profile != "portainer" || len(got[0].CommonNames) != 1 || got[0].CommonNames[0] != "portainer-admin" {
		t.Fatalf("Clients.ClientCertificateProfiles = %#v, want portainer certificate assignment", got)
	}
	if got := cfg.Clients.Profiles; len(got) != 2 || got[0].Name != "readonly" || got[1].Name != "watchtower" {
		t.Fatalf("Clients.Profiles = %#v, want readonly/watchtower profiles", got)
	}
	if got := cfg.Clients.Profiles[0].Response.VisibleResourceLabels; len(got) != 1 || got[0] != "com.sockguard.visible=true" {
		t.Fatalf("Clients.Profiles[0].Response.VisibleResourceLabels = %#v, want [com.sockguard.visible=true]", got)
	}
	if got := cfg.Clients.Profiles[1].RequestBody.Exec.AllowedCommands; len(got) != 1 || len(got[0]) != 1 || got[0][0] != "/usr/local/bin/pre-update" {
		t.Fatalf("Clients.Profiles[1].RequestBody.Exec.AllowedCommands = %#v, want [[/usr/local/bin/pre-update]]", got)
	}
}

func TestLoadExplicitDefaultRulesStillTriggerCompat(t *testing.T) {
	// The published sockguard image ships `/etc/sockguard/sockguard.yaml`
	// with a rules block that is byte-identical to Defaults().Rules so
	// `validate` can print the posture even for fresh installs. That
	// baked YAML used to silently suppress the Tecnativa compat shim,
	// which meant the README Quick Start (`CONTAINERS=1 IMAGES=1
	// EVENTS=1`) did not actually wire up any allow rules on the
	// published image. Compat must fire whenever the effective ruleset
	// still matches the defaults, regardless of whether those rules
	// came from the fallback path or from a YAML file that happens to
	// match them.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "default-rules.yaml")

	yaml := `
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: HEAD, path: "/_ping" }
    action: allow
  - match: { method: GET, path: "/version" }
    action: allow
  - match: { method: GET, path: "/events" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
    reason: no matching allow rule
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	t.Setenv("CONTAINERS", "1")

	if !ApplyCompat(cfg, discardLogger) {
		t.Fatal("expected default-equivalent YAML + CONTAINERS=1 to activate compat mode")
	}

	foundContainers := false
	for _, rule := range cfg.Rules {
		if rule.Match.Method == "GET" && rule.Match.Path == "/containers/**" && rule.Action == "allow" {
			foundContainers = true
			break
		}
	}
	if !foundContainers {
		t.Fatalf("compat mode did not wire up CONTAINERS=1 allow rule; got rules: %+v", cfg.Rules)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	t.Setenv("SOCKGUARD_LISTEN_ADDRESS", "0.0.0.0:1234")
	t.Setenv("SOCKGUARD_LISTEN_SOCKET", "/env/sockguard.sock")
	t.Setenv("SOCKGUARD_UPSTREAM_SOCKET", "/env/docker.sock")
	t.Setenv("SOCKGUARD_LOG_LEVEL", "warn")
	t.Setenv("SOCKGUARD_LOG_OUTPUT", "stdout")
	t.Setenv("SOCKGUARD_RESPONSE_DENY_VERBOSITY", "minimal")
	t.Setenv("SOCKGUARD_LISTEN_INSECURE_ALLOW_PLAIN_TCP", "true")
	t.Setenv("SOCKGUARD_LISTEN_TLS_CERT_FILE", "/env/server-cert.pem")
	t.Setenv("SOCKGUARD_LISTEN_TLS_KEY_FILE", "/env/server-key.pem")
	t.Setenv("SOCKGUARD_LISTEN_TLS_CLIENT_CA_FILE", "/env/ca.pem")
	t.Setenv("SOCKGUARD_INSECURE_ALLOW_BODY_BLIND_WRITES", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_ALLOW_PRIVILEGED", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_ALLOW_HOST_NETWORK", "true")
	t.Setenv("SOCKGUARD_OWNERSHIP_OWNER", "ci-job-456")
	t.Setenv("SOCKGUARD_OWNERSHIP_LABEL_KEY", "com.example.owner")
	t.Setenv("SOCKGUARD_OWNERSHIP_ALLOW_UNOWNED_IMAGES", "false")

	cfg, err := Load("/nonexistent/path.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Upstream.Socket != "/env/docker.sock" {
		t.Errorf("Upstream.Socket = %q, want /env/docker.sock", cfg.Upstream.Socket)
	}
	if cfg.Listen.Address != "0.0.0.0:1234" {
		t.Errorf("Listen.Address = %q, want 0.0.0.0:1234", cfg.Listen.Address)
	}
	if cfg.Listen.Socket != "/env/sockguard.sock" {
		t.Errorf("Listen.Socket = %q, want /env/sockguard.sock", cfg.Listen.Socket)
	}
	if cfg.Log.Level != "warn" {
		t.Errorf("Log.Level = %q, want warn", cfg.Log.Level)
	}
	if cfg.Log.Output != "stdout" {
		t.Errorf("Log.Output = %q, want stdout", cfg.Log.Output)
	}
	if cfg.Response.DenyVerbosity != "minimal" {
		t.Errorf("Response.DenyVerbosity = %q, want minimal", cfg.Response.DenyVerbosity)
	}
	if !cfg.Listen.InsecureAllowPlainTCP {
		t.Errorf("Listen.InsecureAllowPlainTCP = %v, want true", cfg.Listen.InsecureAllowPlainTCP)
	}
	if cfg.Listen.TLS.CertFile != "/env/server-cert.pem" {
		t.Errorf("Listen.TLS.CertFile = %q, want /env/server-cert.pem", cfg.Listen.TLS.CertFile)
	}
	if cfg.Listen.TLS.KeyFile != "/env/server-key.pem" {
		t.Errorf("Listen.TLS.KeyFile = %q, want /env/server-key.pem", cfg.Listen.TLS.KeyFile)
	}
	if cfg.Listen.TLS.ClientCAFile != "/env/ca.pem" {
		t.Errorf("Listen.TLS.ClientCAFile = %q, want /env/ca.pem", cfg.Listen.TLS.ClientCAFile)
	}
	if !cfg.InsecureAllowBodyBlindWrites {
		t.Errorf("InsecureAllowBodyBlindWrites = %v, want true", cfg.InsecureAllowBodyBlindWrites)
	}
	if !cfg.RequestBody.ContainerCreate.AllowPrivileged {
		t.Errorf("RequestBody.ContainerCreate.AllowPrivileged = %v, want true", cfg.RequestBody.ContainerCreate.AllowPrivileged)
	}
	if !cfg.RequestBody.ContainerCreate.AllowHostNetwork {
		t.Errorf("RequestBody.ContainerCreate.AllowHostNetwork = %v, want true", cfg.RequestBody.ContainerCreate.AllowHostNetwork)
	}
	if cfg.Ownership.Owner != "ci-job-456" {
		t.Errorf("Ownership.Owner = %q, want ci-job-456", cfg.Ownership.Owner)
	}
	if cfg.Ownership.LabelKey != "com.example.owner" {
		t.Errorf("Ownership.LabelKey = %q, want com.example.owner", cfg.Ownership.LabelKey)
	}
	if cfg.Ownership.AllowUnownedImages {
		t.Errorf("Ownership.AllowUnownedImages = %v, want false", cfg.Ownership.AllowUnownedImages)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")

	if err := os.WriteFile(cfgPath, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadEmptyPath(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	// Should have defaults
	if cfg.Listen.Socket != Defaults().Listen.Socket {
		t.Errorf("expected default listen socket")
	}
}

func TestLoadReadConfigError(t *testing.T) {
	dir := t.TempDir()

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error when config path is a directory")
	}
}

func TestLoadReadConfigErrorWhenParentIsNotDirectory(t *testing.T) {
	dir := t.TempDir()
	parentFile := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(parentFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Load(filepath.Join(parentFile, "sockguard.yaml"))
	if err == nil {
		t.Fatal("expected error when config path parent is not a directory")
	}
}

func TestLoadUnmarshalError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad-types.yaml")

	yaml := `
rules: definitely-not-a-list
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected unmarshal error for invalid rules type")
	}
}
