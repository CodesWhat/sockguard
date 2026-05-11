package config

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/testcert"
)

func TestValidateDefaults(t *testing.T) {
	cfg := Defaults()
	if err := Validate(&cfg); err != nil {
		t.Errorf("Validate(Defaults()) = %v, want nil", err)
	}
}

func TestValidateRejectsNonLoopbackPlainTCPWithoutExplicitInsecureOptIn(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Address = ":2375"
	cfg.Listen.Socket = ""

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for non-loopback plaintext TCP")
	}
	if !strings.Contains(err.Error(), "listen.tls") {
		t.Fatalf("expected mTLS requirement in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "listen.insecure_allow_plain_tcp") {
		t.Fatalf("expected insecure opt-in hint in error, got: %v", err)
	}
}

func TestValidateAllowsNonLoopbackPlainTCPWithExplicitInsecureOptIn(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Address = ":2375"
	cfg.Listen.Socket = ""
	cfg.Listen.InsecureAllowPlainTCP = true

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateRejectsIncompleteMutualTLSConfig(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Address = ":2376"
	cfg.Listen.Socket = ""
	cfg.Listen.TLS.CertFile = "/tmp/server-cert.pem"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for incomplete listen.tls config")
	}
	if !strings.Contains(err.Error(), "listen.tls") {
		t.Fatalf("expected listen.tls error, got: %v", err)
	}
}

func TestValidateRejectsMutualTLSClientIdentitySelectorsWithoutCertificates(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Address = ":2376"
	cfg.Listen.Socket = ""
	cfg.Listen.TLS.AllowedCommonNames = []string{"portainer"}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for incomplete listen.tls config with identity selectors")
	}
	if !strings.Contains(err.Error(), "listen.tls") {
		t.Fatalf("expected listen.tls error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "cert_file, key_file, and client_ca_file together") {
		t.Fatalf("expected listen.tls completeness hint, got: %v", err)
	}
}

func TestValidateRejectsUnixSocketModeOtherThan0600(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Socket = "/tmp/sockguard.sock"
	cfg.Listen.Address = ""
	cfg.Listen.SocketMode = "0660"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for unsupported listen.socket_mode")
	}
	if !strings.Contains(err.Error(), "listen.socket_mode") {
		t.Fatalf("expected listen.socket_mode in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), `"0600"`) {
		t.Fatalf("expected hardened mode hint in error, got: %v", err)
	}
}

func TestValidateAcceptsNonLoopbackTCPWithMutualTLS(t *testing.T) {
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}

	cfg := Defaults()
	cfg.Listen.Address = ":2376"
	cfg.Listen.Socket = ""
	cfg.Listen.TLS.CertFile = bundle.ServerCertFile
	cfg.Listen.TLS.KeyFile = bundle.ServerKeyFile
	cfg.Listen.TLS.ClientCAFile = bundle.CAFile

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateRejectsCompleteButInvalidMutualTLSConfig(t *testing.T) {
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}

	invalidCA := dir + "/invalid-ca.pem"
	if err := os.WriteFile(invalidCA, []byte("not pem"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := Defaults()
	cfg.Listen.Address = ":2376"
	cfg.Listen.Socket = ""
	cfg.Listen.TLS.CertFile = bundle.ServerCertFile
	cfg.Listen.TLS.KeyFile = bundle.ServerKeyFile
	cfg.Listen.TLS.ClientCAFile = invalidCA

	err = Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "no PEM certificates found") {
		t.Fatalf("expected TLS parse error, got: %v", err)
	}
}

func TestValidateMissingUpstream(t *testing.T) {
	cfg := Defaults()
	cfg.Upstream.Socket = ""
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for missing upstream")
	}
	if !strings.Contains(err.Error(), "upstream.socket") {
		t.Errorf("error should mention upstream.socket, got: %v", err)
	}
}

func TestValidateMissingListeners(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Socket = ""
	cfg.Listen.Address = ""
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for missing listeners")
	}
	if !strings.Contains(err.Error(), "listener") {
		t.Errorf("error should mention listener, got: %v", err)
	}
}

func TestValidateInvalidLogLevel(t *testing.T) {
	cfg := Defaults()
	cfg.Log.Level = "verbose"
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid log level")
	}
	if !strings.Contains(err.Error(), `log.level must be debug, info, warn, or error, got "verbose"`) {
		t.Errorf("error should use normalized log.level phrasing, got: %v", err)
	}
}

func TestValidateInvalidLogFormat(t *testing.T) {
	cfg := Defaults()
	cfg.Log.Format = "xml"
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid log format")
	}
	if !strings.Contains(err.Error(), `log.format must be json or text, got "xml"`) {
		t.Errorf("error should use normalized log.format phrasing, got: %v", err)
	}
}

func TestValidateInvalidLogOutput(t *testing.T) {
	cfg := Defaults()
	cfg.Log.Output = "   "
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid log output")
	}
	if !strings.Contains(err.Error(), "log output") {
		t.Errorf("error should mention log output, got: %v", err)
	}
}

func TestValidateRejectsNonLocalLogOutputPath(t *testing.T) {
	cfg := Defaults()
	cfg.Log.Output = "../sockguard.log"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for non-local log output path")
	}
	if !strings.Contains(err.Error(), "local file path") {
		t.Errorf("error should mention local file path validation, got: %v", err)
	}
}

func TestValidateRejectsInvalidAuditLogFormat(t *testing.T) {
	cfg := Defaults()
	cfg.Log.Audit.Enabled = true
	cfg.Log.Audit.Format = "text"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid audit log format")
	}
	if !strings.Contains(err.Error(), `log.audit.format must be json, got "text"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRejectsInvalidAuditLogOutput(t *testing.T) {
	cfg := Defaults()
	cfg.Log.Audit.Enabled = true
	cfg.Log.Audit.Output = "../audit.log"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid audit log output")
	}
	if !strings.Contains(err.Error(), "log.audit.output") {
		t.Fatalf("error should mention log.audit.output, got: %v", err)
	}
	if !strings.Contains(err.Error(), "local file path") {
		t.Fatalf("error should mention local path validation, got: %v", err)
	}
}

func TestValidateEmptyRules(t *testing.T) {
	cfg := Defaults()
	cfg.Rules = nil
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for empty rules")
	}
	if !strings.Contains(err.Error(), "rule") {
		t.Errorf("error should mention rule, got: %v", err)
	}
}

func TestValidateInvalidAction(t *testing.T) {
	cfg := Defaults()
	cfg.Rules = []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "permit"}}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
	if !strings.Contains(err.Error(), `rule 1: action must be allow or deny, got "permit"`) {
		t.Errorf("error should use normalized action phrasing, got: %v", err)
	}
}

func TestValidateMissingRuleFields(t *testing.T) {
	cfg := Defaults()
	cfg.Rules = []RuleConfig{{Match: MatchConfig{Method: "", Path: ""}, Action: "allow"}}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for missing rule fields")
	}
	if !strings.Contains(err.Error(), "match.method is required") {
		t.Fatalf("error should mention missing match.method, got: %v", err)
	}
	if !strings.Contains(err.Error(), "match.path is required") {
		t.Fatalf("error should mention missing match.path, got: %v", err)
	}
}

func TestValidateInvalidHealthPath(t *testing.T) {
	cfg := Defaults()
	cfg.Health.Path = "health"
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid health path")
	}
	if !strings.Contains(err.Error(), `health.path must start with /, got "health"`) {
		t.Errorf("error should use normalized health.path phrasing, got: %v", err)
	}
}

func TestValidateInvalidMetricsPath(t *testing.T) {
	cfg := Defaults()
	cfg.Metrics.Enabled = true
	cfg.Metrics.Path = "metrics"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid metrics path")
	}
	if !strings.Contains(err.Error(), `metrics.path must start with /, got "metrics"`) {
		t.Errorf("error should mention metrics.path, got: %v", err)
	}
}

func TestValidateMetricsHealthPathConflict(t *testing.T) {
	cfg := Defaults()
	cfg.Metrics.Enabled = true
	cfg.Metrics.Path = cfg.Health.Path

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for metrics and health path conflict")
	}
	if !strings.Contains(err.Error(), `metrics.path must not equal health.path when both endpoints are enabled, got "/health"`) {
		t.Errorf("error should mention metrics/health path conflict, got: %v", err)
	}
}

func TestValidateInvalidHealthWatchdogInterval(t *testing.T) {
	cfg := Defaults()
	cfg.Health.Watchdog.Enabled = true
	cfg.Health.Watchdog.Interval = "soon"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid health watchdog interval")
	}
	if !strings.Contains(err.Error(), `health.watchdog.interval must be a positive duration, got "soon"`) {
		t.Errorf("error should mention health.watchdog.interval, got: %v", err)
	}
}

func TestValidateNonPositiveHealthWatchdogInterval(t *testing.T) {
	cfg := Defaults()
	cfg.Health.Watchdog.Enabled = true
	cfg.Health.Watchdog.Interval = "0s"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for non-positive health watchdog interval")
	}
	if !strings.Contains(err.Error(), `health.watchdog.interval must be a positive duration, got "0s"`) {
		t.Errorf("error should mention positive health.watchdog.interval, got: %v", err)
	}
}

func TestValidateInvalidDenyResponseVerbosity(t *testing.T) {
	cfg := Defaults()
	cfg.Response.DenyVerbosity = "chatty"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid deny response verbosity")
	}
	if !strings.Contains(err.Error(), `response.deny_verbosity must be minimal or verbose, got "chatty"`) {
		t.Errorf("error should use normalized response.deny_verbosity phrasing, got: %v", err)
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	cfg := Defaults()
	cfg.Upstream.Socket = ""
	cfg.Log.Level = "verbose"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if len(ve.Errors) < 2 {
		t.Errorf("expected at least 2 errors, got %d", len(ve.Errors))
	}
}

func TestValidateCommaSeparatedMethods(t *testing.T) {
	cfg := Defaults()
	cfg.Rules = []RuleConfig{
		{Match: MatchConfig{Method: "GET,HEAD", Path: "/containers/**"}, Action: "allow"},
		{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	if err := Validate(&cfg); err != nil {
		t.Errorf("Validate() = %v, want nil for comma-separated methods", err)
	}
}

func TestValidateAllowsAbsoluteContainerCreateBindMountAllowlist(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = []string{"/srv/data", "/var/lib/sockguard"}
	cfg.RequestBody.ContainerCreate.AllowedDevices = []string{"/dev/kvm", "/dev/dri"}

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateRejectsRelativeContainerCreateBindMountAllowlist(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = []string{"srv/data"}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for relative bind mount allowlist entry")
	}
	if !strings.Contains(err.Error(), "request_body.container_create.allowed_bind_mounts") {
		t.Fatalf("expected request_body.container_create.allowed_bind_mounts in error, got: %v", err)
	}
}

func TestValidateRejectsRelativeContainerCreateDeviceAllowlist(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.ContainerCreate.AllowedDevices = []string{"dev/kvm"}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for relative device allowlist entry")
	}
	if !strings.Contains(err.Error(), "request_body.container_create.allowed_devices") {
		t.Fatalf("expected request_body.container_create.allowed_devices in error, got: %v", err)
	}
}

func TestValidateAllowsExecCommandAndImageRegistryAllowlists(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.Exec.AllowedCommands = [][]string{{"/usr/local/bin/pre-update", "--check"}}
	cfg.RequestBody.ImagePull.AllowedRegistries = []string{"ghcr.io", "registry.example.com:5000"}
	cfg.RequestBody.Service.AllowedBindMounts = []string{"/srv/services"}
	cfg.RequestBody.Service.AllowedRegistries = []string{"ghcr.io", "registry.example.com:5000"}
	cfg.RequestBody.Swarm.AllowedJoinRemoteAddrs = []string{"manager.internal:2377"}
	cfg.RequestBody.Plugin.AllowedBindMounts = []string{"/var/lib/plugins"}
	cfg.RequestBody.Plugin.AllowedDevices = []string{"/dev/fuse"}
	cfg.RequestBody.Plugin.AllowedRegistries = []string{"plugins.example.com"}
	cfg.RequestBody.Plugin.AllowedCapabilities = []string{"CAP_SYS_ADMIN"}
	cfg.RequestBody.Plugin.AllowedSetEnvPrefixes = []string{"DEBUG=", "LOG_LEVEL="}

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateRejectsEmptyExecCommandAllowlistEntry(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.Exec.AllowedCommands = [][]string{{""}}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for empty exec allowlist entry")
	}
	if !strings.Contains(err.Error(), "request_body.exec.allowed_commands") {
		t.Fatalf("expected request_body.exec.allowed_commands in error, got: %v", err)
	}
}

func TestValidateRejectsInvalidImageRegistryAllowlistEntry(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.ImagePull.AllowedRegistries = []string{"https://ghcr.io/acme"}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid image registry allowlist entry")
	}
	if !strings.Contains(err.Error(), "request_body.image_pull.allowed_registries") {
		t.Fatalf("expected request_body.image_pull.allowed_registries in error, got: %v", err)
	}
}

func TestValidateRejectsRelativeServiceBindMountAllowlist(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.Service.AllowedBindMounts = []string{"srv/services"}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for relative service bind mount allowlist entry")
	}
	if !strings.Contains(err.Error(), "request_body.service.allowed_bind_mounts") {
		t.Fatalf("expected request_body.service.allowed_bind_mounts in error, got: %v", err)
	}
}

func TestValidateRejectsInvalidServiceRegistryAllowlistEntry(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.Service.AllowedRegistries = []string{"https://ghcr.io/acme"}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid service registry allowlist entry")
	}
	if !strings.Contains(err.Error(), "request_body.service.allowed_registries") {
		t.Fatalf("expected request_body.service.allowed_registries in error, got: %v", err)
	}
}

func TestValidateRejectsInvalidPluginDeviceAllowlistEntry(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.Plugin.AllowedDevices = []string{"dev/fuse"}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid plugin device allowlist entry")
	}
	if !strings.Contains(err.Error(), "request_body.plugin.allowed_devices") {
		t.Fatalf("expected request_body.plugin.allowed_devices in error, got: %v", err)
	}
}

func TestValidateRejectsInvalidPluginRegistryAllowlistEntry(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.Plugin.AllowedRegistries = []string{"https://plugins.example.com/acme"}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid plugin registry allowlist entry")
	}
	if !strings.Contains(err.Error(), "request_body.plugin.allowed_registries") {
		t.Fatalf("expected request_body.plugin.allowed_registries in error, got: %v", err)
	}
}

func TestValidateRejectsEmptySwarmJoinRemoteAddrAllowlistEntry(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.Swarm.AllowedJoinRemoteAddrs = []string{""}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for empty swarm join remote address entry")
	}
	if !strings.Contains(err.Error(), "request_body.swarm.allowed_join_remote_addrs") {
		t.Fatalf("expected request_body.swarm.allowed_join_remote_addrs in error, got: %v", err)
	}
}

func TestValidateRejectsEmptyPluginSetEnvPrefixEntry(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.Plugin.AllowedSetEnvPrefixes = []string{""}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for empty plugin set env prefix entry")
	}
	if !strings.Contains(err.Error(), "request_body.plugin.allowed_set_env_prefixes") {
		t.Fatalf("expected request_body.plugin.allowed_set_env_prefixes in error, got: %v", err)
	}
}

func TestValidateRejectsOwnershipWithoutOwner(t *testing.T) {
	cfg := Defaults()
	cfg.Ownership.Owner = "ci-job-123"
	cfg.Ownership.LabelKey = ""

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for empty ownership label key")
	}
	if !strings.Contains(err.Error(), "ownership.label_key") {
		t.Fatalf("expected ownership.label_key in error, got: %v", err)
	}
}

func TestValidateAllowsClientCIDRACLs(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.AllowedCIDRs = []string{"10.0.0.0/8", "192.0.2.0/24"}

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateRejectsInvalidClientCIDRACLs(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.AllowedCIDRs = []string{"definitely-not-a-cidr"}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid client CIDR")
	}
	if !strings.Contains(err.Error(), "clients.allowed_cidrs") {
		t.Fatalf("expected clients.allowed_cidrs in error, got: %v", err)
	}
}

func TestValidateRejectsEnabledClientContainerLabelsWithoutPrefix(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.ContainerLabels.Enabled = true
	cfg.Clients.ContainerLabels.LabelPrefix = ""

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for empty client container label prefix")
	}
	if !strings.Contains(err.Error(), "clients.container_labels.label_prefix") {
		t.Fatalf("expected clients.container_labels.label_prefix in error, got: %v", err)
	}
}

func TestValidateRejectsClientACLsOnUnixSocketListener(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Socket = "/tmp/sockguard.sock"
	cfg.Listen.Address = ""
	cfg.Clients.AllowedCIDRs = []string{"10.0.0.0/8"}
	cfg.Clients.ContainerLabels.Enabled = true

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for client ACLs on unix socket listener")
	}
	if !strings.Contains(err.Error(), "clients.allowed_cidrs") && !strings.Contains(err.Error(), "clients.container_labels") {
		t.Fatalf("expected client ACL error, got: %v", err)
	}
}

func TestValidateAllowsNamedClientProfiles(t *testing.T) {
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}

	cfg := Defaults()
	cfg.Listen.TLS.CertFile = bundle.ServerCertFile
	cfg.Listen.TLS.KeyFile = bundle.ServerKeyFile
	cfg.Listen.TLS.ClientCAFile = bundle.CAFile
	cfg.Clients.DefaultProfile = "readonly"
	cfg.Clients.SourceIPProfiles = []ClientSourceIPProfileAssignmentConfig{
		{Profile: "watchtower", CIDRs: []string{"172.18.0.0/16"}},
	}
	cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{
		{Profile: "portainer", CommonNames: []string{"portainer-admin"}, PublicKeySHA256Pins: []string{strings.Repeat("a", 64)}},
	}
	cfg.Clients.Profiles = []ClientProfileConfig{
		{
			Name: "readonly",
			Rules: []RuleConfig{
				{Match: MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
				{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
		},
		{
			Name: "watchtower",
			RequestBody: RequestBodyConfig{
				Exec: ExecRequestBodyConfig{
					AllowedCommands: [][]string{{"/usr/local/bin/pre-update"}},
				},
			},
			Rules: []RuleConfig{
				{Match: MatchConfig{Method: http.MethodPost, Path: "/containers/*/exec"}, Action: "allow"},
				{Match: MatchConfig{Method: http.MethodPost, Path: "/exec/*/start"}, Action: "allow"},
				{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
		},
		{
			Name: "portainer",
			Rules: []RuleConfig{
				{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "allow"},
			},
		},
	}

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateRejectsUnknownClientProfileReference(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.DefaultProfile = "missing"
	cfg.Clients.Profiles = []ClientProfileConfig{
		{Name: "readonly", Rules: []RuleConfig{{Match: MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"}}},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for unknown profile reference")
	}
	if !strings.Contains(err.Error(), `clients.default_profile must match a configured client profile, got "missing"`) {
		t.Fatalf("expected normalized clients.default_profile error, got: %v", err)
	}
}

func TestValidateNormalizesClientProfileCollectionErrors(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.Profiles = []ClientProfileConfig{
		{
			Name:  "readonly",
			Rules: []RuleConfig{{Match: MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"}},
		},
		{
			Name:  "readonly",
			Rules: nil,
		},
	}
	cfg.Clients.SourceIPProfiles = []ClientSourceIPProfileAssignmentConfig{
		{Profile: "missing"},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid client profile collection config")
	}
	if !strings.Contains(err.Error(), `clients.profiles[1].name must be unique, got duplicate "readonly"`) {
		t.Fatalf("expected normalized duplicate-profile error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "clients.profiles[1].rules must contain at least one rule") {
		t.Fatalf("expected normalized empty-rules error, got: %v", err)
	}
	if !strings.Contains(err.Error(), `clients.source_ip_profiles[0].profile must match a configured client profile, got "missing"`) {
		t.Fatalf("expected normalized profile reference error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "clients.source_ip_profiles[0].cidrs must contain at least one CIDR") {
		t.Fatalf("expected normalized empty-cidrs error, got: %v", err)
	}
}

func TestValidateRejectsClientCertificateProfilesWithoutMutualTLS(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.Profiles = []ClientProfileConfig{
		{Name: "readonly", Rules: []RuleConfig{{Match: MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"}}},
	}
	cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{
		{Profile: "readonly", CommonNames: []string{"portainer-admin"}},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for client certificate profile assignment without mTLS")
	}
	if !strings.Contains(err.Error(), "clients.client_certificate_profiles") {
		t.Fatalf("expected clients.client_certificate_profiles in error, got: %v", err)
	}
}

func TestValidateRejectsInvalidExtendedClientIdentitySelectors(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Address = "127.0.0.1:2376"
	cfg.Listen.TLS.CertFile = "/certs/server.pem"
	cfg.Listen.TLS.KeyFile = "/certs/server-key.pem"
	cfg.Listen.TLS.ClientCAFile = "/certs/ca.pem"
	cfg.Clients.Profiles = []ClientProfileConfig{
		{Name: "readonly", Rules: []RuleConfig{{Match: MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"}}},
	}
	cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{
		{
			Profile:             "readonly",
			DNSNames:            []string{" "},
			IPAddresses:         []string{"not-an-ip"},
			URISANs:             []string{":"},
			SPIFFEIDs:           []string{"https://not-spiffe.example/test"},
			PublicKeySHA256Pins: []string{"not-a-pin"},
		},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid extended client identity selectors")
	}
	if !strings.Contains(err.Error(), "clients.client_certificate_profiles[0].dns_names") {
		t.Fatalf("expected dns_names validation error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "clients.client_certificate_profiles[0].ip_addresses") {
		t.Fatalf("expected ip_addresses validation error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "clients.client_certificate_profiles[0].uri_sans") {
		t.Fatalf("expected uri_sans validation error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "clients.client_certificate_profiles[0].spiffe_ids") {
		t.Fatalf("expected spiffe_ids validation error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "clients.client_certificate_profiles[0].public_key_sha256_pins") {
		t.Fatalf("expected public_key_sha256_pins validation error, got: %v", err)
	}
}

func TestValidateRejectsInvalidUnixPeerProfileSelectors(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Socket = ""
	cfg.Listen.Address = "127.0.0.1:2376"
	cfg.Clients.Profiles = []ClientProfileConfig{
		{Name: "readonly", Rules: []RuleConfig{{Match: MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"}}},
	}
	cfg.Clients.UnixPeerProfiles = []ClientUnixPeerProfileAssignmentConfig{
		{Profile: "readonly"},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid unix peer profile selectors")
	}
	if !strings.Contains(err.Error(), "clients.unix_peer_profiles") {
		t.Fatalf("expected clients.unix_peer_profiles in error, got: %v", err)
	}
}

func TestValidateRejectsInvalidVisibleResourceLabels(t *testing.T) {
	cfg := Defaults()
	cfg.Response.VisibleResourceLabels = []string{" "}
	cfg.Clients.Profiles = []ClientProfileConfig{
		{
			Name: "readonly",
			Response: ClientProfileResponseConfig{
				VisibleResourceLabels: []string{"bad,label"},
			},
			Rules: []RuleConfig{
				{Match: MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
				{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
		},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid visible resource labels")
	}
	if !strings.Contains(err.Error(), "response.visible_resource_labels") {
		t.Fatalf("expected response.visible_resource_labels in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "clients.profiles[0].response.visible_resource_labels") {
		t.Fatalf("expected clients.profiles[0].response.visible_resource_labels in error, got: %v", err)
	}
}

// TestMutantKills contains targeted tests that kill surviving mutation testing
// survivors. Each subtest name references the mutant it targets.
func TestMutantKills(t *testing.T) {
	// ── ARITHMETIC_BASE validate.go:121:74 and 124:72 ──────────────────────────
	// i+1 in rule error messages — if mutated to i-1, the first rule (i=0)
	// would report "rule -1" instead of "rule 1".
	t.Run("rule_index_arithmetic_first_rule_is_1", func(t *testing.T) {
		cfg := Defaults()
		cfg.Rules = []RuleConfig{
			{Match: MatchConfig{Method: "", Path: ""}, Action: "allow"},
		}
		err := Validate(&cfg)
		if err == nil {
			t.Fatal("expected error for rule with empty method and path")
		}
		if !strings.Contains(err.Error(), "rule 1:") {
			t.Fatalf("expected 'rule 1:' in error, got: %v", err)
		}
	})

	// Verify third rule also uses correct 1-based index.
	t.Run("rule_index_arithmetic_third_rule_is_3", func(t *testing.T) {
		cfg := Defaults()
		cfg.Rules = []RuleConfig{
			{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"},
			{Match: MatchConfig{Method: "GET", Path: "/version"}, Action: "allow"},
			{Match: MatchConfig{Method: "", Path: ""}, Action: "allow"},
		}
		err := Validate(&cfg)
		if err == nil {
			t.Fatal("expected error for third rule with empty fields")
		}
		if !strings.Contains(err.Error(), "rule 3:") {
			t.Fatalf("expected 'rule 3:' in error (1-based), got: %v", err)
		}
		if strings.Contains(err.Error(), "rule 2:") || strings.Contains(err.Error(), "rule 1:") {
			t.Fatalf("expected only 'rule 3:' error, got: %v", err)
		}
	})

	// ── ARITHMETIC_BASE validate.go:382:122 ────────────────────────────────────
	// i+1 in exec allowed_commands error message — first entry should say
	// "entry 1" not "entry -1" or "entry 0".
	t.Run("exec_allowed_commands_index_arithmetic", func(t *testing.T) {
		dir := t.TempDir()
		bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
		if err != nil {
			t.Fatalf("WriteMutualTLSBundle: %v", err)
		}
		cfg := Defaults()
		cfg.Listen.TLS.CertFile = bundle.ServerCertFile
		cfg.Listen.TLS.KeyFile = bundle.ServerKeyFile
		cfg.Listen.TLS.ClientCAFile = bundle.CAFile
		cfg.Clients.DefaultProfile = "prof"
		cfg.Clients.Profiles = []ClientProfileConfig{
			{
				Name: "prof",
				RequestBody: RequestBodyConfig{
					Exec: ExecRequestBodyConfig{
						AllowedCommands: [][]string{{""}}, // invalid first entry
					},
				},
				Rules: []RuleConfig{
					{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				},
			},
		}
		err = Validate(&cfg)
		if err == nil {
			t.Fatal("expected error for empty exec command entry")
		}
		if !strings.Contains(err.Error(), "entry 1") {
			t.Fatalf("expected 'entry 1' in error (1-based), got: %v", err)
		}
	})

	// ── CONDITIONALS_NEGATION validate.go:100:10 ───────────────────────────────
	// interval <= 0 guards against zero/negative watchdog interval.
	// A negative duration must also be rejected.
	t.Run("watchdog_negative_duration_rejected", func(t *testing.T) {
		cfg := Defaults()
		cfg.Health.Watchdog.Enabled = true
		cfg.Health.Watchdog.Interval = "-1s"
		err := Validate(&cfg)
		if err == nil {
			t.Fatal("expected error for negative watchdog interval")
		}
		if !strings.Contains(err.Error(), "health.watchdog.interval must be a positive duration") {
			t.Fatalf("expected positive-duration error, got: %v", err)
		}
	})

	// ── CONDITIONALS_NEGATION validate.go:193:23 ───────────────────────────────
	// cfg.Listen.Socket != "" — container labels on unix socket should error.
	// Complements the existing test: also verify no TCP-listener error on TCP.
	t.Run("container_labels_allowed_on_tcp_listener", func(t *testing.T) {
		cfg := Defaults()
		cfg.Listen.Socket = ""
		cfg.Listen.Address = "127.0.0.1:2376"
		cfg.Listen.InsecureAllowPlainTCP = true
		cfg.Clients.ContainerLabels.Enabled = true
		cfg.Clients.ContainerLabels.LabelPrefix = "com.example"
		err := Validate(&cfg)
		if err != nil && strings.Contains(err.Error(), "clients.container_labels requires a TCP listener") {
			t.Fatalf("unexpected container_labels TCP error on TCP listener: %v", err)
		}
	})

	// ── CONDITIONALS_NEGATION validate.go:302:27 and 302:56 ───────────────────
	// len(UIDs)==0 && len(GIDs)==0 — if one of these is negated, providing only
	// UIDs or only GIDs would still incorrectly trigger the error.
	t.Run("unix_peer_uids_only_is_sufficient", func(t *testing.T) {
		cfg := Defaults()
		cfg.Listen.Socket = "/tmp/sockguard.sock"
		cfg.Listen.Address = ""
		cfg.Clients.Profiles = []ClientProfileConfig{
			{Name: "prof", Rules: []RuleConfig{{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}},
		}
		cfg.Clients.UnixPeerProfiles = []ClientUnixPeerProfileAssignmentConfig{
			{Profile: "prof", UIDs: []uint32{1000}},
		}
		err := Validate(&cfg)
		if err != nil && strings.Contains(err.Error(), "unix peer credential selector") {
			t.Fatalf("expected UIDs alone to satisfy unix peer selector requirement, got: %v", err)
		}
	})

	t.Run("unix_peer_gids_only_is_sufficient", func(t *testing.T) {
		cfg := Defaults()
		cfg.Listen.Socket = "/tmp/sockguard.sock"
		cfg.Listen.Address = ""
		cfg.Clients.Profiles = []ClientProfileConfig{
			{Name: "prof", Rules: []RuleConfig{{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}},
		}
		cfg.Clients.UnixPeerProfiles = []ClientUnixPeerProfileAssignmentConfig{
			{Profile: "prof", GIDs: []uint32{1000}},
		}
		err := Validate(&cfg)
		if err != nil && strings.Contains(err.Error(), "unix peer credential selector") {
			t.Fatalf("expected GIDs alone to satisfy unix peer selector requirement, got: %v", err)
		}
	})

	// ── INCREMENT_DECREMENT validate.go:255/262/270/278 ────────────────────────
	// selectorCount++ at each valid identity selector. If mutated to --, then
	// N valid selectors would decrement from 0 to -N, and the selectorCount==0
	// guard would fire incorrectly (or not at all). Test: one valid entry per
	// field must NOT produce the "must contain at least one selector" error.
	t.Run("cert_profile_single_dns_name_valid", func(t *testing.T) {
		dir := t.TempDir()
		bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
		if err != nil {
			t.Fatalf("WriteMutualTLSBundle: %v", err)
		}
		cfg := Defaults()
		cfg.Listen.TLS.CertFile = bundle.ServerCertFile
		cfg.Listen.TLS.KeyFile = bundle.ServerKeyFile
		cfg.Listen.TLS.ClientCAFile = bundle.CAFile
		cfg.Clients.Profiles = []ClientProfileConfig{
			{Name: "prof", Rules: []RuleConfig{{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}},
		}
		cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{
			{Profile: "prof", DNSNames: []string{"client.example.com"}},
		}
		err = Validate(&cfg)
		if err != nil && strings.Contains(err.Error(), "must contain at least one client certificate identity selector") {
			t.Fatalf("single valid dns_name should count as a selector (selectorCount++), got: %v", err)
		}
	})

	t.Run("cert_profile_single_ip_address_valid", func(t *testing.T) {
		dir := t.TempDir()
		bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
		if err != nil {
			t.Fatalf("WriteMutualTLSBundle: %v", err)
		}
		cfg := Defaults()
		cfg.Listen.TLS.CertFile = bundle.ServerCertFile
		cfg.Listen.TLS.KeyFile = bundle.ServerKeyFile
		cfg.Listen.TLS.ClientCAFile = bundle.CAFile
		cfg.Clients.Profiles = []ClientProfileConfig{
			{Name: "prof", Rules: []RuleConfig{{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}},
		}
		cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{
			{Profile: "prof", IPAddresses: []string{"10.0.0.1"}},
		}
		err = Validate(&cfg)
		if err != nil && strings.Contains(err.Error(), "must contain at least one client certificate identity selector") {
			t.Fatalf("single valid ip_address should count as a selector (selectorCount++), got: %v", err)
		}
	})

	t.Run("cert_profile_single_uri_san_valid", func(t *testing.T) {
		dir := t.TempDir()
		bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
		if err != nil {
			t.Fatalf("WriteMutualTLSBundle: %v", err)
		}
		cfg := Defaults()
		cfg.Listen.TLS.CertFile = bundle.ServerCertFile
		cfg.Listen.TLS.KeyFile = bundle.ServerKeyFile
		cfg.Listen.TLS.ClientCAFile = bundle.CAFile
		cfg.Clients.Profiles = []ClientProfileConfig{
			{Name: "prof", Rules: []RuleConfig{{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}},
		}
		cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{
			{Profile: "prof", URISANs: []string{"https://example.com/client"}},
		}
		err = Validate(&cfg)
		if err != nil && strings.Contains(err.Error(), "must contain at least one client certificate identity selector") {
			t.Fatalf("single valid uri_san should count as a selector (selectorCount++), got: %v", err)
		}
	})

	t.Run("cert_profile_single_spiffe_id_valid", func(t *testing.T) {
		dir := t.TempDir()
		bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
		if err != nil {
			t.Fatalf("WriteMutualTLSBundle: %v", err)
		}
		cfg := Defaults()
		cfg.Listen.TLS.CertFile = bundle.ServerCertFile
		cfg.Listen.TLS.KeyFile = bundle.ServerKeyFile
		cfg.Listen.TLS.ClientCAFile = bundle.CAFile
		cfg.Clients.Profiles = []ClientProfileConfig{
			{Name: "prof", Rules: []RuleConfig{{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}},
		}
		cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{
			{Profile: "prof", SPIFFEIDs: []string{"spiffe://example.org/service"}},
		}
		err = Validate(&cfg)
		if err != nil && strings.Contains(err.Error(), "must contain at least one client certificate identity selector") {
			t.Fatalf("single valid spiffe_id should count as a selector (selectorCount++), got: %v", err)
		}
	})

	// Empty cert profile (no selectors at all) must still error.
	t.Run("cert_profile_no_selectors_errors", func(t *testing.T) {
		dir := t.TempDir()
		bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
		if err != nil {
			t.Fatalf("WriteMutualTLSBundle: %v", err)
		}
		cfg := Defaults()
		cfg.Listen.TLS.CertFile = bundle.ServerCertFile
		cfg.Listen.TLS.KeyFile = bundle.ServerKeyFile
		cfg.Listen.TLS.ClientCAFile = bundle.CAFile
		cfg.Clients.Profiles = []ClientProfileConfig{
			{Name: "prof", Rules: []RuleConfig{{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}},
		}
		cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{
			{Profile: "prof"},
		}
		err = Validate(&cfg)
		if err == nil {
			t.Fatal("expected error for cert profile with no selectors")
		}
		if !strings.Contains(err.Error(), "must contain at least one client certificate identity selector") {
			t.Fatalf("expected selector-required error, got: %v", err)
		}
	})
}

func TestNormalizeAllowedBindMount(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{name: "empty", input: "", want: "", ok: false},
		{name: "relative", input: "srv/data", want: "", ok: false},
		{name: "root", input: "/", want: "/", ok: true},
		{name: "absolute clean", input: "/srv/data", want: "/srv/data", ok: true},
		{name: "absolute cleaned", input: "/srv/../srv/data", want: "/srv/data", ok: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeAllowedBindMount(tt.input)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("normalizeAllowedBindMount(%q) = (%q, %v), want (%q, %v)", tt.input, got, ok, tt.want, tt.ok)
			}
		})
	}
}
