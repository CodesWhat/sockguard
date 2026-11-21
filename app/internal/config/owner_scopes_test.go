package config

import (
	"slices"
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }

func ownerScopesProfiles(t *testing.T) []ClientProfileConfig {
	t.Helper()
	rules := []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}}
	return []ClientProfileConfig{
		{Name: "a", Rules: rules},
		{Name: "b", Rules: rules},
	}
}

func TestLoadBytesDecodesProfileOwnership(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
ownership:
  owner: root
  label_key: com.sockguard.owner
  allow_unowned_images: true
  insecure_allow_weak_owner_selection: true
clients:
  profiles:
    - name: a
      rules: [{match: {method: GET, path: /_ping}, action: allow}]
      ownership:
        owner: app-a
        allow_unowned_images: false
        scope: all
    - name: b
      rules: [{match: {method: GET, path: /_ping}, action: allow}]
    - name: c
      rules: [{match: {method: GET, path: /_ping}, action: allow}]
      ownership:
        owner: ""
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if !cfg.Ownership.InsecureAllowWeakOwnerSelection {
		t.Error("insecure_allow_weak_owner_selection not decoded")
	}
	a := cfg.EffectiveOwnership(&cfg.Clients.Profiles[0])
	if a.Owner != "app-a" || a.AllowUnownedImages || !a.AllOwners {
		t.Errorf("profile a effective = %+v, want owner app-a, unowned images off, all owners", a)
	}
	b := cfg.EffectiveOwnership(&cfg.Clients.Profiles[1])
	if b.Owner != "root" || !b.AllowUnownedImages || b.AllOwners {
		t.Errorf("profile b effective = %+v, want root inherited", b)
	}
	if o := cfg.Clients.Profiles[2].Ownership.Owner; o == nil || *o != "" {
		t.Errorf("explicit empty owner decoded as %v, want pointer to empty string", o)
	}
	if root := cfg.EffectiveOwnership(nil); root.Owner != "root" || root.AllOwners {
		t.Errorf("nil profile effective = %+v, want root", root)
	}
}

func TestProfileOwnershipLabelKeyIsAnUnknownKey(t *testing.T) {
	got, err := UnknownKeysBytes([]byte("clients:\n  profiles:\n    - name: a\n      ownership:\n        owner: x\n        label_key: other\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"clients.profiles[0].ownership.label_key"}; !slices.Equal(got, want) {
		t.Fatalf("unknown keys = %v, want %v", got, want)
	}
}

func TestOwnershipActive(t *testing.T) {
	cfg := Defaults()
	if cfg.OwnershipActive() {
		t.Fatal("defaults report ownership active")
	}
	cfg.Clients.Profiles = ownerScopesProfiles(t)
	cfg.Clients.Profiles[1].Ownership.Owner = ptr("b")
	if !cfg.OwnershipActive() {
		t.Fatal("a profile owner alone should activate ownership")
	}
}

func TestValidateClientProfileOwnerships(t *testing.T) {
	type tweak func(cfg *Config)
	tests := []struct {
		name    string
		tweak   tweak
		wantErr string // empty means valid
	}{
		{"inherit only", func(cfg *Config) {}, ""},
		{"distinct owner by strong selectors", func(cfg *Config) {
			cfg.Clients.Profiles[0].Ownership.Owner = ptr("a")
			cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{{Profile: "a"}}
			cfg.Clients.UnixPeerProfiles = []ClientUnixPeerProfileAssignmentConfig{{Profile: "b"}}
		}, ""},
		{"empty owner refused", func(cfg *Config) {
			cfg.Clients.Profiles[0].Ownership.Owner = ptr("")
		}, "clients.profiles[0].ownership.owner must not be empty when set"},
		{"unknown scope refused", func(cfg *Config) {
			cfg.Ownership.Owner = "root"
			cfg.Clients.Profiles[1].Ownership.Scope = "everything"
		}, `clients.profiles[1].ownership.scope must be empty or "all", got "everything"`},
		{"scope all without any owner", func(cfg *Config) {
			cfg.Clients.Profiles[0].Ownership.Scope = "all"
		}, `clients.profiles[0].ownership.scope "all" requires an owner`},
		{"scope all inherits the root owner", func(cfg *Config) {
			cfg.Ownership.Owner = "root"
			cfg.Clients.Profiles[0].Ownership.Scope = "all"
		}, ""},
		{"scope all by strong selector", func(cfg *Config) {
			cfg.Clients.Profiles[0].Ownership = ClientProfileOwnershipConfig{Owner: ptr("adm"), Scope: "all"}
			cfg.Clients.UnixPeerProfiles = []ClientUnixPeerProfileAssignmentConfig{{Profile: "a"}}
		}, ""},
		{"owner via source ip refused", func(cfg *Config) {
			cfg.Clients.Profiles[0].Ownership.Owner = ptr("a")
			cfg.Clients.SourceIPProfiles = []ClientSourceIPProfileAssignmentConfig{{Profile: "a"}}
		}, "clients.profiles[0].ownership.owner \"a\" differs from ownership.owner and the profile is reachable through a weak selector (clients.source_ip_profiles[0])"},
		{"owner via default profile refused", func(cfg *Config) {
			cfg.Clients.Profiles[1].Ownership.Owner = ptr("b")
			cfg.Clients.DefaultProfile = "b"
		}, "weak selector (clients.default_profile)"},
		{"owner via source ip acknowledged", func(cfg *Config) {
			cfg.Ownership.InsecureAllowWeakOwnerSelection = true
			cfg.Clients.Profiles[0].Ownership.Owner = ptr("a")
			cfg.Clients.SourceIPProfiles = []ClientSourceIPProfileAssignmentConfig{{Profile: "a"}}
			cfg.Clients.DefaultProfile = "a"
		}, ""},
		{"owner equal to root on a weak selector is fine", func(cfg *Config) {
			cfg.Ownership.Owner = "root"
			cfg.Clients.Profiles[0].Ownership.Owner = ptr("root")
			cfg.Clients.SourceIPProfiles = []ClientSourceIPProfileAssignmentConfig{{Profile: "a"}}
		}, ""},
		{"profile without owner override on a weak selector is fine", func(cfg *Config) {
			cfg.Ownership.Owner = "root"
			cfg.Clients.DefaultProfile = "a"
		}, ""},
		{"owner reachable both ways is refused through the weak one", func(cfg *Config) {
			cfg.Clients.Profiles[0].Ownership.Owner = ptr("a")
			cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{{Profile: "a"}}
			cfg.Clients.SourceIPProfiles = []ClientSourceIPProfileAssignmentConfig{{Profile: "a"}}
		}, "weak selector (clients.source_ip_profiles[0])"},
		{"scope all via source ip refused", func(cfg *Config) {
			cfg.Clients.Profiles[0].Ownership = ClientProfileOwnershipConfig{Owner: ptr("adm"), Scope: "all"}
			cfg.Clients.SourceIPProfiles = []ClientSourceIPProfileAssignmentConfig{{Profile: "a"}}
		}, `clients.profiles[0].ownership.scope "all" must not be reachable through a weak selector (clients.source_ip_profiles[0])`},
		{"scope all via default profile refused even when acknowledged", func(cfg *Config) {
			cfg.Ownership.InsecureAllowWeakOwnerSelection = true
			cfg.Clients.Profiles[0].Ownership = ClientProfileOwnershipConfig{Owner: ptr("adm"), Scope: "all"}
			cfg.Clients.DefaultProfile = "a"
		}, `clients.profiles[0].ownership.scope "all" must not be reachable through a weak selector (clients.default_profile)`},
		{"scope all with root owner equal on a weak selector is still refused", func(cfg *Config) {
			cfg.Ownership.Owner = "adm"
			cfg.Ownership.InsecureAllowWeakOwnerSelection = true
			cfg.Clients.Profiles[0].Ownership = ClientProfileOwnershipConfig{Scope: "all"}
			cfg.Clients.SourceIPProfiles = []ClientSourceIPProfileAssignmentConfig{{Profile: "a"}}
		}, "insecure_allow_weak_owner_selection does not apply to scope all"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Clients.Profiles = ownerScopesProfiles(t)
			tt.tweak(&cfg)
			errs := validateClientProfileOwnerships(&cfg)
			joined := strings.Join(errs, "\n")
			if tt.wantErr == "" {
				if len(errs) != 0 {
					t.Fatalf("unexpected errors: %v", errs)
				}
				return
			}
			if !strings.Contains(joined, tt.wantErr) {
				t.Fatalf("errors = %q, want substring %q", joined, tt.wantErr)
			}
		})
	}
}

func TestValidateRequiresLabelKeyForProfileOwner(t *testing.T) {
	cfg := Defaults()
	cfg.Ownership.LabelKey = ""
	cfg.Clients.Profiles = ownerScopesProfiles(t)
	cfg.Clients.Profiles[0].Ownership.Owner = ptr("a")
	cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{{Profile: "a"}}
	errs := validateRequestBody(&cfg)
	if !strings.Contains(strings.Join(errs, "\n"), "ownership.label_key is required when ownership.owner or a client profile ownership.owner is set") {
		t.Fatalf("errors = %v, want the label_key requirement", errs)
	}
}
