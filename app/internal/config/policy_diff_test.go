package config

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestPolicyChanges(t *testing.T) {
	rules := []RuleConfig{
		{Match: MatchConfig{Method: "GET", Path: "/version"}, Action: "allow"},
		{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "deny"},
	}
	tests := []struct {
		name   string
		change func(*Config, *Config)
		want   []PolicyChange
	}{
		{name: "unchanged", want: []PolicyChange{}},
		{name: "scalar", change: func(_, b *Config) { b.Response.RedactContainerEnv = false }, want: []PolicyChange{{"response.redact_container_env", "modified"}}},
		{name: "ordered rules", change: func(a, b *Config) {
			a.Rules = slices.Clone(rules)
			b.Rules = slices.Clone(rules)
			slices.Reverse(b.Rules)
		}, want: []PolicyChange{{"rules[0].action", "modified"}, {"rules[0].match.path", "modified"}, {"rules[1].action", "modified"}, {"rules[1].match.path", "modified"}}},
		{name: "added rule", change: func(a, b *Config) { a.Rules = rules[:1]; b.Rules = rules }, want: []PolicyChange{{"rules[1]", "added"}}},
		{name: "removed rule", change: func(a, b *Config) { a.Rules = rules; b.Rules = rules[:1] }, want: []PolicyChange{{"rules[1]", "removed"}}},
		{name: "profile scope", change: func(a, b *Config) {
			a.Clients.Profiles = []ClientProfileConfig{{Name: "ci", Rules: rules[:1]}}
			b.Clients.Profiles = []ClientProfileConfig{{Name: "ci", Rules: rules}}
		}, want: []PolicyChange{{"clients.profiles[0].rules[1]", "added"}}},
		{name: "listener scope", change: func(a, b *Config) {
			a.Listeners = []ListenerConfig{{Name: "private", AllowedProfiles: []string{"ci"}}}
			b.Listeners = []ListenerConfig{{Name: "private", AllowedProfiles: []string{"ops"}}}
		}, want: []PolicyChange{{"listeners[0].allowed_profiles[0]", "modified"}}},
		{name: "embedded listener", change: func(a, b *Config) {
			a.Listeners = []ListenerConfig{{Name: "private", ListenConfig: ListenConfig{Socket: "/old"}}}
			b.Listeners = []ListenerConfig{{Name: "private", ListenConfig: ListenConfig{Socket: "/new"}}}
		}, want: []PolicyChange{{"listeners[0].socket", "modified"}}},
		{name: "nil and empty lists", change: func(a, b *Config) { a.Listeners = nil; b.Listeners = []ListenerConfig{} }, want: []PolicyChange{}},
		{name: "optional pointer", change: func(_, b *Config) { value := 100; b.Listen.SocketUID = &value }, want: []PolicyChange{{"listen.socket_uid", "added"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := Defaults(), Defaults()
			if tt.change != nil {
				tt.change(&a, &b)
			}
			if got := PolicyChanges(&a, &b); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("changes = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPolicyChangesNeverExposeValuesOrMapKeys(t *testing.T) {
	a, b := Defaults(), Defaults()
	a.Listen.TLS.KeyFile, b.Listen.TLS.KeyFile = "/private/old-secret", "/private/new-secret"
	a.Mutations.Rules = []MutationRuleConfig{{ID: "labels", InjectLabels: &InjectLabelsMutationConfig{Labels: map[string]string{"private-key": "old-secret"}}}}
	b.Mutations.Rules = []MutationRuleConfig{{ID: "labels", InjectLabels: &InjectLabelsMutationConfig{Labels: map[string]string{"private-key": "new-secret"}}}}
	changes := PolicyChanges(&a, &b)
	want := []PolicyChange{{"listen.tls.key_file", "modified"}, {"mutations.rules[0].inject_labels.labels", "modified"}}
	if !reflect.DeepEqual(changes, want) {
		t.Fatalf("changes = %+v, want %+v", changes, want)
	}
	body, err := json.Marshal(changes)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-key", "old-secret", "new-secret", "/private/"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("response exposes %q", secret)
		}
	}
}

func TestPolicyChangesIgnoreYAMLFormatting(t *testing.T) {
	a, err := LoadBytes([]byte("response: {redact_container_env: false}\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadBytes([]byte("# same effective defaults\nresponse:\n  redact_container_env: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := PolicyChanges(a, b); len(got) != 0 {
		t.Fatalf("formatting produced changes: %+v", got)
	}
}

func TestValidatePolicyDiffPath(t *testing.T) {
	for _, endpoint := range []string{"relative", "/admin/validate", "/admin//validate", "/admin/policy/version", "/health", "/metrics", "/ready"} {
		t.Run(endpoint, func(t *testing.T) {
			cfg := Defaults()
			cfg.Admin.Enabled, cfg.Metrics.Enabled, cfg.Health.Readiness.Enabled = true, true, true
			cfg.Admin.PolicyDiffPath = endpoint
			if err := ValidateStructural(&cfg); err == nil || !strings.Contains(err.Error(), "admin.policy_diff_path") {
				t.Fatalf("validation = %v, want policy diff path rejection", err)
			}
		})
	}
}
