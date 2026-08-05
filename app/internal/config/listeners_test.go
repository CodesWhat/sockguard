package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/testcert"
)

func listenerTestConfig(entries ...ListenerConfig) Config {
	cfg := Defaults()
	cfg.Listeners = entries
	profileRules := []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}}
	cfg.Clients.Profiles = []ClientProfileConfig{
		{Name: "ci", Rules: profileRules},
		{Name: "ops", Rules: profileRules},
	}
	return cfg
}

func unixListener(name, socket string, profiles ...string) ListenerConfig {
	return ListenerConfig{
		Name: name,
		ListenConfig: ListenConfig{
			Socket:     socket,
			SocketMode: HardenedListenSocketMode,
		},
		AllowedProfiles: profiles,
	}
}

func tcpListener(name, address string, profiles ...string) ListenerConfig {
	return ListenerConfig{
		Name:            name,
		ListenConfig:    ListenConfig{Address: address, SocketMode: HardenedListenSocketMode},
		AllowedProfiles: profiles,
	}
}

func requireValidationContains(t *testing.T, cfg *Config, want string) {
	t.Helper()
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate() = %v, want error containing %q", err, want)
	}
}

func TestEffectiveListenersLegacyAndExplicitModes(t *testing.T) {
	t.Parallel()

	legacy := Defaults()
	legacy.Listen = ListenConfig{Socket: "/run/legacy.sock", SocketMode: HardenedListenSocketMode}
	got := legacy.EffectiveListeners()
	if len(got) != 1 || got[0].Name != DefaultListenerName || got[0].Socket != legacy.Listen.Socket || !got[0].Wildcard() {
		t.Fatalf("EffectiveListeners(legacy) = %#v, want one wildcard default listener", got)
	}

	explicit := []ListenerConfig{
		unixListener("ci", "/run/ci.sock", "ci"),
		unixListener("ops", "/run/ops.sock", "ops"),
	}
	cfg := listenerTestConfig(explicit...)
	got = cfg.EffectiveListeners()
	if len(got) != 2 || got[0].Name != "ci" || got[1].Name != "ops" {
		t.Fatalf("EffectiveListeners(explicit) = %#v, want declared list", got)
	}

}

func TestValidateListenerNamesAndCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{
			name: "empty",
			edit: func(cfg *Config) { cfg.Listeners[0].Name = "" },
			want: "listeners[0].name is required",
		},
		{
			name: "starts with digit",
			edit: func(cfg *Config) { cfg.Listeners[0].Name = "1ci" },
			want: "must match ^[a-z][a-z0-9-]{0,62}$",
		},
		{
			name: "uppercase",
			edit: func(cfg *Config) { cfg.Listeners[0].Name = "CI" },
			want: "must match ^[a-z][a-z0-9-]{0,62}$",
		},
		{
			name: "surrounding whitespace",
			edit: func(cfg *Config) { cfg.Listeners[0].Name = " ci " },
			want: "must match ^[a-z][a-z0-9-]{0,62}$",
		},
		{
			name: "too long",
			edit: func(cfg *Config) { cfg.Listeners[0].Name = "a" + strings.Repeat("b", 63) },
			want: "must match ^[a-z][a-z0-9-]{0,62}$",
		},
		{
			name: "reserved admin",
			edit: func(cfg *Config) { cfg.Listeners[0].Name = AdminListenerName },
			want: `must not be "admin"`,
		},
		{
			name: "duplicate",
			edit: func(cfg *Config) {
				cfg.Listeners = append(cfg.Listeners, unixListener("ci", "/run/other.sock", "ci"))
			},
			want: `listeners[*].name must be unique, got duplicate "ci"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := listenerTestConfig(unixListener("ci", "/run/ci.sock", "ci"))
			tc.edit(&cfg)
			requireValidationContains(t, &cfg, tc.want)
		})
	}

	entries := make([]ListenerConfig, MaxListeners)
	for i := range entries {
		entries[i] = unixListener(fmt.Sprintf("listener-%02d", i), fmt.Sprintf("/run/listener-%02d.sock", i), WildcardProfile)
	}
	atCap := listenerTestConfig(entries...)
	if err := Validate(&atCap); err != nil {
		t.Fatalf("Validate(%d listeners) = %v, want nil", MaxListeners, err)
	}
	overCap := listenerTestConfig(append(entries, unixListener("overflow", "/run/overflow.sock", WildcardProfile))...)
	requireValidationContains(t, &overCap, "listeners must contain at most 32 entries, got 33")
}

func TestValidateExplicitListenerEndpointAndTLSMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		edit func(*ListenerConfig)
		want string
	}{
		{
			name: "neither endpoint",
			edit: func(l *ListenerConfig) { l.Socket = "" },
			want: "exactly one of socket or address is required",
		},
		{
			name: "both endpoints",
			edit: func(l *ListenerConfig) { l.Address = "127.0.0.1:2375" },
			want: "exactly one of socket or address is required, got both",
		},
		{
			name: "TLS on unix",
			edit: func(l *ListenerConfig) { l.TLS.CertFile = "/tmp/server.pem" },
			want: "listeners[ci].tls is only valid for TCP listeners",
		},
		{
			name: "ownership on TCP",
			edit: func(l *ListenerConfig) {
				l.Socket = ""
				l.Address = "127.0.0.1:2375"
				uid := 1000
				l.SocketUID = &uid
			},
			want: "listeners[ci].socket_uid is only valid for unix listeners",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := unixListener("ci", "/run/ci.sock", "ci")
			tc.edit(&entry)
			cfg := listenerTestConfig(entry)
			requireValidationContains(t, &cfg, tc.want)
		})
	}

	partial := listenerTestConfig(tcpListener("ci", "127.0.0.1:2376", "ci"))
	partial.Listeners[0].TLS.CertFile = "/tmp/server.pem"
	requireValidationContains(t, &partial, "listeners[ci].tls requires cert_file, key_file, and client_ca_file together")
}

func TestValidateCompleteListenerTLS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}
	cfg := listenerTestConfig(tcpListener("ci", "0.0.0.0:2376", "ci"))
	cfg.Listeners[0].TLS = ListenTLSConfig{
		CertFile:     bundle.ServerCertFile,
		KeyFile:      bundle.ServerKeyFile,
		ClientCAFile: bundle.CAFile,
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate(complete listener TLS) = %v, want nil", err)
	}
}

func TestValidateListenerTLSRejectsEveryIncompleteCredentialSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tls  ListenTLSConfig
	}{
		{name: "cert only", tls: ListenTLSConfig{CertFile: "cert"}},
		{name: "key only", tls: ListenTLSConfig{KeyFile: "key"}},
		{name: "CA only", tls: ListenTLSConfig{ClientCAFile: "ca"}},
		{name: "cert and key", tls: ListenTLSConfig{CertFile: "cert", KeyFile: "key"}},
		{name: "cert and CA", tls: ListenTLSConfig{CertFile: "cert", ClientCAFile: "ca"}},
		{name: "key and CA", tls: ListenTLSConfig{KeyFile: "key", ClientCAFile: "ca"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := listenerTestConfig(tcpListener("ci", "127.0.0.1:2376", "ci"))
			cfg.Listeners[0].TLS = tc.tls
			requireValidationContains(t, &cfg, "listeners[ci].tls requires cert_file, key_file, and client_ca_file together")
		})
	}
}

func TestValidateListenerSocketOwnershipIsPerEntry(t *testing.T) {
	t.Parallel()

	gid := 1000
	valid := listenerTestConfig(
		unixListener("ci", "/run/ci.sock", "ci"),
		unixListener("ops", "/run/ops.sock", "ops"),
	)
	valid.Listeners[1].SocketMode = GroupReadableListenSocketMode
	valid.Listeners[1].SocketGID = &gid
	if err := Validate(&valid); err != nil {
		t.Fatalf("Validate(per-entry 0660 with gid) = %v, want nil", err)
	}

	missingGID := valid
	missingGID.Listeners = append([]ListenerConfig(nil), valid.Listeners...)
	missingGID.Listeners[1].SocketGID = nil
	requireValidationContains(t, &missingGID, "listeners[ops].socket_mode \"0660\" requires listeners[ops].socket_gid")

	negativeUID := valid
	negativeUID.Listeners = append([]ListenerConfig(nil), valid.Listeners...)
	uid := -1
	negativeUID.Listeners[0].SocketUID = &uid
	requireValidationContains(t, &negativeUID, "listeners[ci].socket_uid must be >= 0")

	invalidMode := valid
	invalidMode.Listeners = append([]ListenerConfig(nil), valid.Listeners...)
	invalidMode.Listeners[0].SocketMode = "0640"
	requireValidationContains(t, &invalidMode, "listeners[ci].socket_mode must be \"0600\" or \"0660\"")
}

func TestValidatePlaintextAcknowledgementsArePerListener(t *testing.T) {
	t.Parallel()

	ci := tcpListener("ci", "10.0.0.1:2375", "ci")
	ci.InsecureAllowPlainTCP = true
	ci.InsecureAllowUnauthenticatedClients = true
	ops := tcpListener("ops", "10.0.0.2:2375", "ops")
	ops.InsecureAllowPlainTCP = true
	cfg := listenerTestConfig(ci, ops)
	requireValidationContains(t, &cfg, "listeners[ops].insecure_allow_unauthenticated_clients=true")

	cfg.Listeners[1].InsecureAllowUnauthenticatedClients = true
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate(two independently acknowledged listeners) = %v, want nil", err)
	}
}

func TestValidateListenerBindTargetsAreUniqueAcrossAllPairs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "nonadjacent main sockets",
			cfg: listenerTestConfig(
				unixListener("one", "/run/shared.sock", WildcardProfile),
				unixListener("two", "/run/two.sock", WildcardProfile),
				unixListener("three", "/run/shared.sock", WildcardProfile),
			),
			want: `listeners[one].socket and listeners[three].socket must be distinct`,
		},
		{
			name: "main addresses",
			cfg: listenerTestConfig(
				tcpListener("one", "127.0.0.1:2375", WildcardProfile),
				tcpListener("two", "127.0.0.1:2375", WildcardProfile),
			),
			want: `listeners[one].address and listeners[two].address must be distinct`,
		},
		{
			name: "normalized IPv6 addresses",
			cfg: listenerTestConfig(
				tcpListener("one", "[0:0:0:0:0:0:0:1]:2375", WildcardProfile),
				tcpListener("two", "[::1]:2375", WildcardProfile),
			),
			want: `listeners[one].address and listeners[two].address must be distinct`,
		},
		{
			name: "normalized numeric ports",
			cfg: listenerTestConfig(
				tcpListener("one", "127.0.0.1:02375", WildcardProfile),
				tcpListener("two", "127.0.0.1:2375", WildcardProfile),
			),
			want: `listeners[one].address and listeners[two].address must be distinct`,
		},
	}

	adminCollision := listenerTestConfig(
		unixListener("one", "/run/one.sock", WildcardProfile),
		unixListener("two", "/run/two.sock", WildcardProfile),
	)
	adminCollision.Admin.Enabled = true
	adminCollision.Admin.Listen.Socket = "/run/two.sock"
	tests = append(tests, struct {
		name string
		cfg  Config
		want string
	}{
		name: "main and admin",
		cfg:  adminCollision,
		want: `listeners[two].socket and admin.listen.socket must be distinct`,
	})

	adminAddressCollision := listenerTestConfig(
		tcpListener("one", "127.0.0.1:2375", WildcardProfile),
		tcpListener("two", "127.0.0.1:2376", WildcardProfile),
	)
	adminAddressCollision.Admin.Enabled = true
	adminAddressCollision.Admin.Listen.Address = "127.0.0.1:2375"
	tests = append(tests, struct {
		name string
		cfg  Config
		want string
	}{
		name: "main and admin address",
		cfg:  adminAddressCollision,
		want: `listeners[one].address and admin.listen.address must be distinct`,
	})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requireValidationContains(t, &tc.cfg, tc.want)
		})
	}
}

func TestValidateAllowedProfiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		profiles []string
		want     string
	}{
		{name: "empty", profiles: nil, want: "allowed_profiles must contain at least one"},
		{name: "unknown", profiles: []string{"missing"}, want: `must match a configured client profile, got "missing"`},
		{name: "duplicate", profiles: []string{"ci", "ci"}, want: `must be unique, got duplicate "ci"`},
		{name: "wildcard mixed", profiles: []string{WildcardProfile, "ci"}, want: `"*" cannot be combined`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := listenerTestConfig(unixListener("ci", "/run/ci.sock", tc.profiles...))
			requireValidationContains(t, &cfg, tc.want)
		})
	}

	for _, profiles := range [][]string{{"ci"}, {WildcardProfile}} {
		cfg := listenerTestConfig(unixListener("ci", "/run/ci.sock", profiles...))
		if err := Validate(&cfg); err != nil {
			t.Fatalf("Validate(allowed_profiles=%v) = %v, want nil", profiles, err)
		}
	}
}

func TestValidateDefaultProfileExcludedIsWarningNotError(t *testing.T) {
	t.Parallel()

	cfg := listenerTestConfig(unixListener("ci", "/run/ci.sock", "ci"))
	cfg.Clients.DefaultProfile = "ops"
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate(default profile excluded from listener) = %v, want nil warning-only behavior", err)
	}
}

func TestValidateLegacyAndListenersMutualExclusionTracksProvenance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "socket",
			yaml: `listen:
  socket: /run/legacy.sock
listeners:
  - name: ci
    socket: /run/ci.sock
    socket_mode: "0600"
    allowed_profiles: ["*"]
`,
		},
		{
			name: "default-valued address is still explicit",
			yaml: `listen:
  address: 127.0.0.1:2375
listeners:
  - name: ci
    address: 127.0.0.1:2376
    allowed_profiles: ["*"]
`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("LoadBytes: %v", err)
			}
			if !cfg.ExplicitLegacyListen() {
				t.Fatal("ExplicitLegacyListen() = false, want true")
			}
			requireValidationContains(t, cfg, "listen and listeners are mutually exclusive; migrate the listen: block")
		})
	}

	listOnly, err := LoadBytes([]byte(`listeners:
  - name: ci
    socket: /run/ci.sock
    socket_mode: "0600"
    allowed_profiles: ["*"]
`))
	if err != nil {
		t.Fatalf("LoadBytes(list only): %v", err)
	}
	if listOnly.ExplicitLegacyListen() {
		t.Fatal("defaulted listen block was incorrectly marked explicit")
	}
	if err := Validate(listOnly); err != nil {
		t.Fatalf("Validate(list only) = %v, want nil", err)
	}
}

func TestLoadTracksEnvironmentLegacyListenerProvenance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sockguard.yaml")
	if err := os.WriteFile(path, []byte(`listeners:
  - name: ci
    socket: /run/ci.sock
    socket_mode: "0600"
    allowed_profiles: ["*"]
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("SOCKGUARD_LISTEN_SOCKET", "/run/from-env.sock")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.ExplicitLegacyListen() {
		t.Fatal("SOCKGUARD_LISTEN_SOCKET did not mark the legacy listener explicit")
	}
	requireValidationContains(t, cfg, "listen and listeners are mutually exclusive")
}

func TestValidateClientTransportCapabilitiesWithListeners(t *testing.T) {
	t.Parallel()

	base := listenerTestConfig(
		unixListener("local", "/run/local.sock", WildcardProfile),
		tcpListener("remote", "127.0.0.1:2375", WildcardProfile),
	)
	base.Clients.AllowedCIDRs = []string{"127.0.0.0/8"}
	base.Clients.ContainerLabels.Enabled = true
	base.Clients.SourceIPProfiles = []ClientSourceIPProfileAssignmentConfig{{Profile: "ci", CIDRs: []string{"127.0.0.0/8"}}}
	base.Clients.UnixPeerProfiles = []ClientUnixPeerProfileAssignmentConfig{{Profile: "ops", UIDs: []uint32{1000}}}
	if errs := validateClientsListenerExclusions(&base); len(errs) != 0 {
		t.Fatalf("validateClientsListenerExclusions(mixed listeners) = %v, want nil", errs)
	}

	unixOnly := base
	unixOnly.Listeners = []ListenerConfig{unixListener("local", "/run/local.sock", WildcardProfile)}
	got := strings.Join(validateClientsListenerExclusions(&unixOnly), "\n")
	for _, want := range []string{"clients.allowed_cidrs", "clients.container_labels", "clients.source_ip_profiles"} {
		if !strings.Contains(got, want) {
			t.Errorf("unix-only exclusions = %q, want %q", got, want)
		}
	}

	tcpOnly := base
	tcpOnly.Listeners = []ListenerConfig{tcpListener("remote", "127.0.0.1:2375", WildcardProfile)}
	if got := strings.Join(validateClientsListenerExclusions(&tcpOnly), "\n"); !strings.Contains(got, "clients.unix_peer_profiles") {
		t.Fatalf("tcp-only exclusions = %q, want unix_peer_profiles error", got)
	}
}

func TestValidateCertificateProfilesUsesAnyMTLSListener(t *testing.T) {
	t.Parallel()

	cfg := listenerTestConfig(
		unixListener("local", "/run/local.sock", WildcardProfile),
		tcpListener("remote", "127.0.0.1:2376", WildcardProfile),
	)
	cfg.Listeners[1].TLS = ListenTLSConfig{CertFile: "cert", KeyFile: "key", ClientCAFile: "ca"}
	cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{{Profile: "ci", CommonNames: []string{"ci-client"}}}
	profiles := clientProfileNameSet(&cfg)
	if errs := validateClientsCertificateProfiles(&cfg, profiles); len(errs) != 0 {
		t.Fatalf("validateClientsCertificateProfiles(mixed with mTLS) = %v, want nil", errs)
	}

	cfg.Listeners[1].TLS = ListenTLSConfig{}
	got := strings.Join(validateClientsCertificateProfiles(&cfg, profiles), "\n")
	if !strings.Contains(got, "clients.client_certificate_profiles requires a listen/listeners[*] entry with mutual TLS configured") {
		t.Fatalf("validateClientsCertificateProfiles(no mTLS) = %q, want mTLS requirement", got)
	}
}

func TestValidateAdminMountOnForListenerSets(t *testing.T) {
	t.Parallel()

	multi := listenerTestConfig(
		unixListener("ci", "/run/ci.sock", WildcardProfile),
		unixListener("ops", "/run/ops.sock", WildcardProfile),
	)
	multi.Admin.Enabled = true
	requireValidationContains(t, &multi, "admin.mount_on is required")

	unknown := multi
	unknown.Admin.MountOn = "missing"
	requireValidationContains(t, &unknown, `admin.mount_on must match a configured listener name, got "missing"`)

	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{name: "matching listener", cfg: func() Config { c := multi; c.Admin.MountOn = "ci"; return c }()},
		{name: "single listener", cfg: func() Config {
			c := listenerTestConfig(unixListener("ci", "/run/ci.sock", WildcardProfile))
			c.Admin.Enabled = true
			return c
		}()},
		{name: "dedicated admin", cfg: func() Config {
			c := multi
			c.Admin.Listen.Socket = "/run/admin.sock"
			return c
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(&tc.cfg); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}
