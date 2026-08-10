package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/buildkitproxy"
)

// TestBuildkitDefaultsAreAllDenied confirms the zero-value
// BuildkitRequestBodyConfig (what a config that never mentions
// "buildkit:" decodes to) translates into a Policy that denies
// everything — presence, not an enabled flag, is what governs #185
// phase 1's posture.
func TestBuildkitDefaultsAreAllDenied(t *testing.T) {
	cfg := Defaults()

	if cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build).Configured() {
		t.Fatal("Defaults().RequestBody.Buildkit.ToPolicy(Build).Configured() = true, want false")
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate(Defaults()) = %v, want nil", err)
	}
}

// TestBuildkitToPolicyTranslation asserts a fully populated
// BuildkitRequestBodyConfig maps field-for-field into buildkitproxy.Policy,
// so a future phase can trust ToPolicy without re-deriving the mapping.
// Since issue #185 phase 3, this also covers ToPolicy's build parameter: the
// sibling request_body.build block's AllowHostNetwork/AllowRemoteContext
// must land on SolvePolicy verbatim (see BuildkitSolveRequestBodyConfig's
// doc comment for why those two aren't fields of their own here), and the
// new Solve cache/exporter allowlists must map straight across.
func TestBuildkitToPolicyTranslation(t *testing.T) {
	cfg := BuildkitRequestBodyConfig{
		Control: BuildkitControlRequestBodyConfig{
			AllowInfo:        true,
			AllowListWorkers: true,
			AllowStatus:      true,
			Solve: BuildkitSolveRequestBodyConfig{
				Allow:                     true,
				AllowedCacheImportTypes:   []string{"registry"},
				AllowedCacheExportTypes:   []string{"inline"},
				AllowedCacheRegistries:    []string{"ghcr.io"},
				AllowedExporters:          []string{"image"},
				AllowedExporterRegistries: []string{"registry.example.com"},
			},
		},
		Session: BuildkitSessionRequestBodyConfig{
			Health: true,
			Auth: BuildkitAuthRequestBodyConfig{
				Allow:             true,
				AllowedRegistries: []string{"ghcr.io"},
				AllowedRealms:     []string{"realm-a"},
				AllowedScopes:     []string{"scope-a"},
			},
			Secrets:  BuildkitSecretsRequestBodyConfig{Allow: true, AllowedIDs: []string{"secret-a"}},
			SSH:      BuildkitSSHRequestBodyConfig{Allow: true, AllowedIDs: []string{"ssh-a"}},
			FileSync: BuildkitFileSyncRequestBodyConfig{Allow: true},
			FileSend: BuildkitFileSendRequestBodyConfig{Allow: true},
			Upload:   BuildkitUploadRequestBodyConfig{Allow: true},
		},
	}
	build := BuildRequestBodyConfig{AllowHostNetwork: true, AllowRemoteContext: true, AllowRunInstructions: true}

	want := buildkitproxy.Policy{
		Control: buildkitproxy.ControlPolicy{
			AllowInfo:        true,
			AllowListWorkers: true,
			AllowStatus:      true,
			Solve: buildkitproxy.SolvePolicy{
				Allow:                     true,
				AllowHostNetwork:          true,
				AllowRemoteContext:        true,
				AllowedCacheImportTypes:   []string{"registry"},
				AllowedCacheExportTypes:   []string{"inline"},
				AllowedCacheRegistries:    []string{"ghcr.io"},
				AllowedExporters:          []string{"image"},
				AllowedExporterRegistries: []string{"registry.example.com"},
			},
		},
		Session: buildkitproxy.SessionPolicy{
			Health: true,
			Auth: buildkitproxy.AuthPolicy{
				Allow:             true,
				AllowedRegistries: []string{"ghcr.io"},
				AllowedRealms:     []string{"realm-a"},
				AllowedScopes:     []string{"scope-a"},
			},
			Secrets:  buildkitproxy.SecretsPolicy{Allow: true, AllowedIDs: []string{"secret-a"}},
			SSH:      buildkitproxy.SSHPolicy{Allow: true, AllowedIDs: []string{"ssh-a"}},
			FileSync: buildkitproxy.FileSyncPolicy{Allow: true},
			FileSend: buildkitproxy.FileSendPolicy{Allow: true},
			Upload:   buildkitproxy.UploadPolicy{Allow: true},
		},
	}

	got := cfg.ToPolicy(build)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ToPolicy() = %#v, want %#v", got, want)
	}
	if !got.Configured() {
		t.Fatal("populated Policy.Configured() = false, want true")
	}
}

// TestBuildkitToPolicyNormalizesRegistryHostCase confirms Solve's cache/
// exporter registry allowlists are normalized (lowercased, and
// index.docker.io canonicalized to docker.io) at ToPolicy time — see
// normalizeRegistryHostList's doc comment for why: buildkitproxy's
// registryHostFromImageRef always lowercases the host it extracts from a
// client-supplied ref, so a config entry that kept whatever case the
// operator typed would otherwise never match at runtime (a CodeRabbit #226
// finding: "Registry:5000" in config silently never matched "registry:5000"
// extracted from a live request).
func TestBuildkitToPolicyNormalizesRegistryHostCase(t *testing.T) {
	cfg := BuildkitRequestBodyConfig{
		Control: BuildkitControlRequestBodyConfig{
			Solve: BuildkitSolveRequestBodyConfig{
				Allow:                     true,
				AllowedCacheRegistries:    []string{"Registry.Example.COM:5000", "INDEX.DOCKER.IO"},
				AllowedExporterRegistries: []string{"Other.Example.COM"},
			},
		},
	}

	got := cfg.ToPolicy(BuildRequestBodyConfig{})
	wantCache := []string{"registry.example.com:5000", "docker.io"}
	wantExporter := []string{"other.example.com"}

	if !reflect.DeepEqual(got.Control.Solve.AllowedCacheRegistries, wantCache) {
		t.Fatalf("AllowedCacheRegistries = %v, want %v", got.Control.Solve.AllowedCacheRegistries, wantCache)
	}
	if !reflect.DeepEqual(got.Control.Solve.AllowedExporterRegistries, wantExporter) {
		t.Fatalf("AllowedExporterRegistries = %v, want %v", got.Control.Solve.AllowedExporterRegistries, wantExporter)
	}
}

// TestBuildkitToPolicyNormalizesAuthRegistryHostCase confirms Session.Auth's
// registry allowlist is normalized (lowercased, and index.docker.io
// canonicalized to docker.io) at ToPolicy time, same as Solve's cache/
// exporter registry allowlists (TestBuildkitToPolicyNormalizesRegistryHostCase)
// — see normalizeRegistryHostList's doc comment: buildkitproxy's
// session_mediation.go normalizeAuthHost (issue #185 phase 4) always
// lowercases the Host it reads off an Auth request, so a config entry that
// kept whatever case the operator typed would otherwise never match at
// runtime.
func TestBuildkitToPolicyNormalizesAuthRegistryHostCase(t *testing.T) {
	cfg := BuildkitRequestBodyConfig{
		Session: BuildkitSessionRequestBodyConfig{
			Auth: BuildkitAuthRequestBodyConfig{
				Allow:             true,
				AllowedRegistries: []string{"Registry-1.Docker.IO", "INDEX.DOCKER.IO"},
			},
		},
	}

	got := cfg.ToPolicy(BuildRequestBodyConfig{})
	want := []string{"registry-1.docker.io", "docker.io"}

	if !reflect.DeepEqual(got.Session.Auth.AllowedRegistries, want) {
		t.Fatalf("Session.Auth.AllowedRegistries = %v, want %v", got.Session.Auth.AllowedRegistries, want)
	}
}

// TestBuildkitToPolicyDoesNotCountBuildFlagsAsConfigured pins the
// deliberate asymmetry documented on buildkitproxy.Policy.Configured: a
// Solve policy whose ONLY non-zero fields are the ones reused from
// request_body.build (AllowHostNetwork/AllowRemoteContext) must not itself
// make Configured() true — those two fields describe intent from an
// unrelated block, not "this operator wrote a request_body.buildkit
// section". If this regressed, an operator who sets
// request_body.build.allow_host_network for classic POST /build alone would
// be unable to also set insecure_accept_opaque_buildkit_tunnels: true,
// tripping validateBuildkitAckMutualExclusion for a combination that has
// nothing to do with BuildKit mediation.
func TestBuildkitToPolicyDoesNotCountBuildFlagsAsConfigured(t *testing.T) {
	var cfg BuildkitRequestBodyConfig
	build := BuildRequestBodyConfig{AllowHostNetwork: true, AllowRemoteContext: true}

	got := cfg.ToPolicy(build)
	if !got.Control.Solve.AllowHostNetwork || !got.Control.Solve.AllowRemoteContext {
		t.Fatalf("ToPolicy(build) = %#v, want AllowHostNetwork/AllowRemoteContext threaded through from build", got)
	}
	if got.Configured() {
		t.Fatal("Policy.Configured() = true from build-only flags alone, want false")
	}
}

// TestValidateAllowsFullyPopulatedBuildkitConfig confirms a legitimately
// configured request_body.buildkit block (well-formed allowlists throughout)
// passes validation.
func TestValidateAllowsFullyPopulatedBuildkitConfig(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.Buildkit = BuildkitRequestBodyConfig{
		Control: BuildkitControlRequestBodyConfig{
			AllowInfo:        true,
			AllowListWorkers: true,
			AllowStatus:      true,
			Solve:            BuildkitSolveRequestBodyConfig{Allow: true},
		},
		Session: BuildkitSessionRequestBodyConfig{
			Health: true,
			Auth: BuildkitAuthRequestBodyConfig{
				Allow:             true,
				AllowedRegistries: []string{"ghcr.io", "registry.example.com:5000"},
				AllowedRealms:     []string{"realm-a"},
				AllowedScopes:     []string{"repository:foo/bar:pull"},
			},
			Secrets:  BuildkitSecretsRequestBodyConfig{Allow: true, AllowedIDs: []string{"my-secret"}},
			SSH:      BuildkitSSHRequestBodyConfig{Allow: true, AllowedIDs: []string{"default"}},
			FileSync: BuildkitFileSyncRequestBodyConfig{Allow: true},
			FileSend: BuildkitFileSendRequestBodyConfig{Allow: true},
			Upload:   BuildkitUploadRequestBodyConfig{Allow: true},
		},
	}

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

// TestValidateRejectsBadBuildkitAllowlistEntries table-drives every
// allowlist field validateBuildkitConfig checks, confirming each rejects
// malformed entries with a dotted-path error mentioning the offending field.
func TestValidateRejectsBadBuildkitAllowlistEntries(t *testing.T) {
	tests := []struct {
		name  string
		apply func(cfg *Config)
		field string
	}{
		{
			name: "allowed_registries not a bare host",
			apply: func(cfg *Config) {
				cfg.RequestBody.Buildkit.Session.Auth.AllowedRegistries = []string{"https://ghcr.io/"}
			},
			field: "buildkit.session.auth.allowed_registries",
		},
		{
			name:  "allowed_realms empty string",
			apply: func(cfg *Config) { cfg.RequestBody.Buildkit.Session.Auth.AllowedRealms = []string{""} },
			field: "buildkit.session.auth.allowed_realms",
		},
		{
			name:  "allowed_realms whitespace padded",
			apply: func(cfg *Config) { cfg.RequestBody.Buildkit.Session.Auth.AllowedRealms = []string{" realm-a "} },
			field: "buildkit.session.auth.allowed_realms",
		},
		{
			name:  "allowed_scopes empty string",
			apply: func(cfg *Config) { cfg.RequestBody.Buildkit.Session.Auth.AllowedScopes = []string{""} },
			field: "buildkit.session.auth.allowed_scopes",
		},
		{
			name:  "secrets allowed_ids whitespace padded",
			apply: func(cfg *Config) { cfg.RequestBody.Buildkit.Session.Secrets.AllowedIDs = []string{"secret-a "} },
			field: "buildkit.session.secrets.allowed_ids",
		},
		{
			name:  "ssh allowed_ids empty string",
			apply: func(cfg *Config) { cfg.RequestBody.Buildkit.Session.SSH.AllowedIDs = []string{""} },
			field: "buildkit.session.ssh.allowed_ids",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.apply(&cfg)

			err := Validate(&cfg)
			if err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("expected %q in error, got: %v", tt.field, err)
			}
		})
	}
}

// TestValidateBuildkitAckMutualExclusionTopLevel confirms
// insecure_accept_opaque_buildkit_tunnels: true and a configured top-level
// request_body.buildkit block are rejected together, but each is accepted
// alone.
func TestValidateBuildkitAckMutualExclusionTopLevel(t *testing.T) {
	t.Run("both set is rejected", func(t *testing.T) {
		cfg := Defaults()
		cfg.InsecureAcceptOpaqueBuildkitTunnels = true
		cfg.RequestBody.Buildkit.Control.Solve.Allow = true

		err := Validate(&cfg)
		if err == nil {
			t.Fatal("expected error when ack and request_body.buildkit are both set")
		}
		if !strings.Contains(err.Error(), "insecure_accept_opaque_buildkit_tunnels") || !strings.Contains(err.Error(), "request_body.buildkit") {
			t.Fatalf("expected mutual-exclusion message naming both settings, got: %v", err)
		}
	})

	t.Run("ack alone is accepted", func(t *testing.T) {
		cfg := Defaults()
		cfg.InsecureAcceptOpaqueBuildkitTunnels = true

		if err := Validate(&cfg); err != nil {
			t.Fatalf("Validate() error = %v, want nil (ack alone)", err)
		}
	})

	t.Run("request_body.buildkit alone is accepted", func(t *testing.T) {
		cfg := Defaults()
		cfg.RequestBody.Buildkit.Control.Solve.Allow = true

		if err := Validate(&cfg); err != nil {
			t.Fatalf("Validate() error = %v, want nil (buildkit config alone)", err)
		}
	})
}

// TestValidateBuildkitAckMutualExclusionPerProfile confirms a client
// profile configuring request_body.buildkit is rejected when the top-level
// ack is also set, even though the ack is a global setting the profile
// itself never touches — the ack would otherwise silently admit /session
// and /grpc opaquely for that profile too.
func TestValidateBuildkitAckMutualExclusionPerProfile(t *testing.T) {
	cfg := Defaults()
	cfg.InsecureAcceptOpaqueBuildkitTunnels = true
	cfg.Clients.Profiles = []ClientProfileConfig{
		{
			Name:  "builders",
			Rules: []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}},
			RequestBody: RequestBodyConfig{
				Buildkit: BuildkitRequestBodyConfig{
					Control: BuildkitControlRequestBodyConfig{Solve: BuildkitSolveRequestBodyConfig{Allow: true}},
				},
			},
		},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for profile request_body.buildkit vs top-level ack")
	}
	if !strings.Contains(err.Error(), `"builders"`) {
		t.Fatalf("expected error to name the offending profile, got: %v", err)
	}
	if !strings.Contains(err.Error(), "insecure_accept_opaque_buildkit_tunnels") {
		t.Fatalf("expected error to mention insecure_accept_opaque_buildkit_tunnels, got: %v", err)
	}
}

// TestValidateBuildkitAckMutualExclusionPerProfileWithoutAck confirms a
// profile-level request_body.buildkit block is accepted when the top-level
// ack is left false.
func TestValidateBuildkitAckMutualExclusionPerProfileWithoutAck(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.Profiles = []ClientProfileConfig{
		{
			Name:  "builders",
			Rules: []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}},
			RequestBody: RequestBodyConfig{
				Buildkit: BuildkitRequestBodyConfig{
					Control: BuildkitControlRequestBodyConfig{Solve: BuildkitSolveRequestBodyConfig{Allow: true}},
				},
			},
		},
	}

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil (profile buildkit config without global ack)", err)
	}
}

// TestLoadHonorsBuildkitEnvVars confirms the request_body.buildkit surface
// is reachable purely through SOCKGUARD_REQUEST_BODY_BUILDKIT_* env vars —
// both a plain nested bool two levels deep (control.allow_info) and a
// slice field on a doubly nested struct (session.secrets.allowed_ids) —
// through the existing Viper reflection-based default registration, with
// no additional SetDefault wiring required.
func TestLoadHonorsBuildkitEnvVars(t *testing.T) {
	t.Setenv("SOCKGUARD_REQUEST_BODY_BUILDKIT_CONTROL_ALLOW_INFO", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_BUILDKIT_CONTROL_ALLOW_LIST_WORKERS", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_BUILDKIT_CONTROL_ALLOW_STATUS", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_BUILDKIT_CONTROL_SOLVE_ALLOW", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_BUILDKIT_CONTROL_SOLVE_ALLOWED_EXPORTERS", "image,oci")
	t.Setenv("SOCKGUARD_REQUEST_BODY_BUILDKIT_SESSION_HEALTH", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_BUILDKIT_SESSION_SECRETS_ALLOWED_IDS", "a,b,c")

	cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	bk := cfg.RequestBody.Buildkit
	if !bk.Control.AllowInfo {
		t.Error("Control.AllowInfo = false, want true from env")
	}
	if !bk.Control.AllowListWorkers {
		t.Error("Control.AllowListWorkers = false, want true from env")
	}
	if !bk.Control.AllowStatus {
		t.Error("Control.AllowStatus = false, want true from env")
	}
	if !bk.Control.Solve.Allow {
		t.Error("Control.Solve.Allow = false, want true from env")
	}
	if !bk.Session.Health {
		t.Error("Session.Health = false, want true from env")
	}
	if got := bk.Session.Secrets.AllowedIDs; len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("Session.Secrets.AllowedIDs = %#v, want [a b c] from env", got)
	}
	if got := bk.Control.Solve.AllowedExporters; len(got) != 2 || got[0] != "image" || got[1] != "oci" {
		t.Fatalf("Control.Solve.AllowedExporters = %#v, want [image oci] from env", got)
	}
	if !bk.ToPolicy(cfg.RequestBody.Build).Configured() {
		t.Fatal("env-configured Buildkit.ToPolicy(Build).Configured() = false, want true")
	}
}
