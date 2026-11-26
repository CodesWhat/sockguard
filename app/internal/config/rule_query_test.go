package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

const killQueryYAML = `
rules:
  - match: { method: POST, path: "/containers/*/kill", query: { signal: ["USR1", "SIGUSR1"] } }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
`

func TestLoadBytesDecodesRuleQuery(t *testing.T) {
	cfg, err := LoadBytes([]byte(killQueryYAML))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	want := map[string][]string{"signal": {"USR1", "SIGUSR1"}}
	if got := cfg.Rules[0].Match.Query; !reflect.DeepEqual(got, want) {
		t.Fatalf("rules[0].match.query = %#v, want %#v", got, want)
	}
	if cfg.Rules[1].Match.Query != nil {
		t.Fatalf("rules[1].match.query = %#v, want nil", cfg.Rules[1].Match.Query)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// Viper lowercases every map key it reads. A query key is case-sensitive on
// the wire, so the loader has to hand back the spelling the operator wrote.
func TestLoadBytesPreservesRuleQueryKeyCase(t *testing.T) {
	yaml := `
rules:
  - match: { method: POST, path: "/a", query: { Signal: "USR1", X_Mixed-Key: [a, "", 7, true] } }
    action: allow
clients:
  profiles:
    - name: ci
      rules:
        - match: { method: GET, path: "/b" }
          action: allow
        - match: { method: GET, path: "/c", query: { FILTERS: ["*"] } }
          action: deny
`
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	want := map[string][]string{"Signal": {"USR1"}, "X_Mixed-Key": {"a", "", "7", "true"}}
	if got := cfg.Rules[0].Match.Query; !reflect.DeepEqual(got, want) {
		t.Errorf("top-level query = %#v, want %#v", got, want)
	}
	profileWant := map[string][]string{"FILTERS": {"*"}}
	if got := cfg.Clients.Profiles[0].Rules[1].Match.Query; !reflect.DeepEqual(got, profileWant) {
		t.Errorf("profile query = %#v, want %#v", got, profileWant)
	}
}

func TestLoadFilePreservesRuleQueryKeyCase(t *testing.T) {
	path := t.TempDir() + "/sockguard.yaml"
	if err := os.WriteFile(path, []byte("rules:\n  - match: { method: GET, path: /a, query: { Foo: [bar] } }\n    action: deny\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := cfg.Rules[0].Match.Query, (map[string][]string{"Foo": {"bar"}}); !reflect.DeepEqual(got, want) {
		t.Fatalf("query = %#v, want %#v", got, want)
	}
}

func TestUnknownKeysAcceptsRuleQuery(t *testing.T) {
	unknown, err := UnknownKeysBytes([]byte(killQueryYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) != 0 {
		t.Fatalf("unknown keys = %v, want none", unknown)
	}
}

func TestValidateRuleQuery(t *testing.T) {
	tests := []struct {
		name  string
		query map[string][]string
		want  string // substring of the error; "" means valid
	}{
		{name: "valid", query: map[string][]string{"signal": {"USR1"}}},
		{name: "valid empty pattern", query: map[string][]string{"signal": {""}}},
		{name: "valid glob", query: map[string][]string{"signal": {"SIG*"}}},
		{name: "empty key", query: map[string][]string{"": {"x"}}, want: "match.query must not have an empty key"},
		{name: "no patterns", query: map[string][]string{"signal": {}}, want: "match.query.signal needs at least one pattern"},
		{name: "nil patterns", query: map[string][]string{"signal": nil}, want: "match.query.signal needs at least one pattern"},
		{name: "control in pattern", query: map[string][]string{"signal": {"ok", "a\tb"}}, want: `match.query.signal[1] must not contain control characters, got "a\tb"`},
		{name: "keys differing only in case", query: map[string][]string{"signal": {"a"}, "Signal": {"b"}}, want: "match.query keys \"Signal\" and \"signal\" differ only in letter case"},
		{name: "control in key", query: map[string][]string{"si\x00g": {"x"}}, want: "match.query key \"si\\x00g\" must not contain control characters"},
	}
	for _, tt := range tests {
		t.Run("top-level "+tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Rules = []RuleConfig{{Match: MatchConfig{Method: "POST", Path: "/containers/*/kill", Query: tt.query}, Action: "allow"}}
			assertQueryValidation(t, Validate(&cfg), "rule 1: "+tt.want, tt.want)
		})
		t.Run("profile "+tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Clients.Profiles = []ClientProfileConfig{{Name: "ci", Rules: []RuleConfig{
				{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"},
				{Match: MatchConfig{Method: "POST", Path: "/containers/*/kill", Query: tt.query}, Action: "allow"},
			}}}
			assertQueryValidation(t, Validate(&cfg), "clients.profiles[0].rules[1]."+tt.want, tt.want)
		})
	}
}

func assertQueryValidation(t *testing.T, err error, wantFull, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("Validate = %v, want nil", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), wantFull) {
		t.Fatalf("Validate = %v, want error containing %q", err, wantFull)
	}
}

func TestRuleQueryNullValuesRejected(t *testing.T) {
	cases := map[string]string{
		"null":       "signal: null",
		"tilde":      "signal: ~",
		"null array": "signal: [null]",
		"mixed null": `signal: ["KILL", null]`,
	}
	for name, query := range cases {
		for _, where := range []string{"top", "profile"} {
			t.Run(name+"/"+where, func(t *testing.T) {
				rule := `{ match: { method: POST, path: "/containers/*/kill", query: { ` + query + ` } }, action: deny }`
				yaml := "rules:\n  - " + rule + "\n"
				if where == "profile" {
					yaml = "clients:\n  profiles:\n    - name: ci\n      rules:\n        - " + rule + "\n"
				}
				cfg, err := LoadBytes([]byte(yaml))
				if err == nil {
					err = Validate(cfg)
				}
				if err == nil || !strings.Contains(err.Error(), "needs at least one pattern") {
					t.Fatalf("err = %v, want 'needs at least one pattern'", err)
				}
			})
		}
	}

	cfg, err := LoadBytes([]byte(`rules:
  - { match: { method: GET, path: "/a", query: { name: "" } }, action: deny }
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if got := cfg.Rules[0].Match.Query["name"]; !reflect.DeepEqual(got, []string{""}) {
		t.Fatalf("quoted empty = %#v, want [\"\"]", got)
	}
}

func TestRuleQueryKeysRestoredWithMixedCaseSchemaKeys(t *testing.T) {
	yaml := `
Rules:
  - Match: { method: POST, path: "/a", Query: { Signal: "USR1" } }
    action: allow
Clients:
  Profiles:
    - name: ci
      rules:
        - Match: { method: GET, path: "/c", Query: { FILTERS: ["*"] } }
          action: deny
`
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if got, want := cfg.Rules[0].Match.Query, map[string][]string{"Signal": {"USR1"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("top-level query = %#v, want %#v", got, want)
	}
	if got, want := cfg.Clients.Profiles[0].Rules[0].Match.Query, map[string][]string{"FILTERS": {"*"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("profile query = %#v, want %#v", got, want)
	}
}

func TestRuleBodyKeysRestoredWithMixedCaseSchemaKeys(t *testing.T) {
	yaml := `
Rules:
  - Match: { method: POST, path: "/a", Body: { Image: ["approved/*"] } }
    action: allow
Clients:
  Profiles:
    - name: ci
      rules:
        - Match: { method: POST, path: "/c", Body: { Labels: ["*"] } }
          action: deny
`
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if got, want := cfg.Rules[0].Match.Body, map[string][]string{"Image": {"approved/*"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("top-level body = %#v, want %#v", got, want)
	}
	if got, want := cfg.Clients.Profiles[0].Rules[0].Match.Body, map[string][]string{"Labels": {"*"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("profile body = %#v, want %#v", got, want)
	}
}

func TestRuleQueryCaseDuplicatesSurviveMixedCaseSchema(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
Rules:
  - Match: { method: POST, path: "/a", Query: { Signal: "USR1", signal: "KILL" } }
    action: deny
`))
	if err == nil {
		err = Validate(cfg)
	}
	if err == nil || !strings.Contains(err.Error(), "differ only in letter case") {
		t.Fatalf("err = %v, want duplicate-case rejection", err)
	}
}

func TestRuleBodyCaseDuplicatesSurviveMixedCaseSchema(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
Rules:
  - Match: { method: POST, path: "/a", Body: { Name: ["a*"], name: ["b*"] } }
    action: deny
`))
	if err == nil {
		err = Validate(cfg)
	}
	if err == nil || !strings.Contains(err.Error(), "differ only in letter case") {
		t.Fatalf("err = %v, want duplicate-case rejection", err)
	}
}
