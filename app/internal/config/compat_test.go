package config

import (
	"log/slog"
	"testing"
)

var discardLogger = slog.New(slog.NewTextHandler(
	devNull{}, &slog.HandlerOptions{Level: slog.LevelError + 1},
))

type devNull struct{}

func (devNull) Write(b []byte) (int, error) { return len(b), nil }

func TestCompatNoEnvVars(t *testing.T) {
	cfg := Defaults()
	if ApplyCompat(&cfg, discardLogger) {
		t.Error("expected no-op when no env vars set")
	}
}

func TestCompatCustomRulesNoOp(t *testing.T) {
	cfg := Defaults()
	cfg.Rules = []RuleConfig{
		{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"},
	}
	t.Setenv("CONTAINERS", "1")
	if ApplyCompat(&cfg, discardLogger) {
		t.Error("expected no-op when custom rules are present")
	}
}

func TestCompatContainers(t *testing.T) {
	cfg := Defaults()
	t.Setenv("CONTAINERS", "1")

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate")
	}

	// Should have: ping, version, events, containers GET, catch-all deny
	found := false
	for _, r := range cfg.Rules {
		if r.Match.Path == "/containers/**" && r.Match.Method == "GET" && r.Action == "allow" {
			found = true
		}
	}
	if !found {
		t.Error("expected GET /containers/** allow rule")
	}

	// Should end with catch-all deny
	last := cfg.Rules[len(cfg.Rules)-1]
	if last.Action != "deny" || last.Match.Method != "*" {
		t.Error("expected catch-all deny as last rule")
	}
}

func TestCompatPostGranular(t *testing.T) {
	cfg := Defaults()
	t.Setenv("POST", "1")
	t.Setenv("ALLOW_START", "1")

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate")
	}

	found := false
	for _, r := range cfg.Rules {
		if r.Match.Path == "/containers/*/start" && r.Match.Method == "POST" {
			found = true
		}
	}
	if !found {
		t.Error("expected POST /containers/*/start rule")
	}

	// Should NOT have blanket POST allow
	for _, r := range cfg.Rules {
		if r.Match.Method == "POST,PUT,DELETE" && r.Match.Path == "/**" {
			t.Error("expected no blanket POST allow when granular vars set")
		}
	}
}

func TestCompatPostBlanket(t *testing.T) {
	cfg := Defaults()
	t.Setenv("POST", "1")

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate")
	}

	found := false
	for _, r := range cfg.Rules {
		if r.Match.Method == "POST,PUT,DELETE" && r.Match.Path == "/**" && r.Action == "allow" {
			found = true
		}
	}
	if !found {
		t.Error("expected blanket POST,PUT,DELETE /** allow rule")
	}
}

func TestCompatPingDisabled(t *testing.T) {
	cfg := Defaults()
	t.Setenv("PING", "0")
	// Need at least one other var to trigger compat
	t.Setenv("CONTAINERS", "1")

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate")
	}

	for _, r := range cfg.Rules {
		if r.Match.Path == "/_ping" {
			t.Error("expected ping rule to be removed when PING=0")
		}
	}
}

func TestLookupEnvBool(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantVal   bool
		wantFound bool
	}{
		{"1", "1", true, true},
		{"true", "true", true, true},
		{"yes", "yes", true, true},
		{"TRUE", "TRUE", true, true},
		{"0", "0", false, true},
		{"false", "false", false, true},
		{"no", "no", false, true},
		{"invalid", "maybe", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TEST_BOOL", tt.value)
			// Override the function to look up TEST_BOOL by temporarily setting
			// the real env var name
			t.Setenv("COMPAT_TEST", tt.value)

			val, found := lookupEnvBool("COMPAT_TEST")
			if val != tt.wantVal || found != tt.wantFound {
				t.Errorf("lookupEnvBool(%q) = (%v, %v), want (%v, %v)",
					tt.value, val, found, tt.wantVal, tt.wantFound)
			}
		})
	}
}

func TestCompatGranularWithoutPost(t *testing.T) {
	cfg := Defaults()
	t.Setenv("ALLOW_START", "1")
	t.Setenv("ALLOW_STOP", "1")
	// POST is NOT set, so granular rules should NOT be generated

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate")
	}

	for _, r := range cfg.Rules {
		if r.Match.Path == "/containers/*/start" || r.Match.Path == "/containers/*/stop" {
			t.Errorf("unexpected granular rule generated without POST=1: %s %s", r.Match.Method, r.Match.Path)
		}
	}
}

func TestCompatMultipleGranularVars(t *testing.T) {
	cfg := Defaults()
	t.Setenv("POST", "1")
	t.Setenv("ALLOW_START", "1")
	t.Setenv("ALLOW_STOP", "1")
	t.Setenv("ALLOW_RESTART", "1")

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate")
	}

	wantPaths := map[string]bool{
		"/containers/*/start":   false,
		"/containers/*/stop":    false,
		"/containers/*/restart": false,
	}

	for _, r := range cfg.Rules {
		if _, ok := wantPaths[r.Match.Path]; ok {
			wantPaths[r.Match.Path] = true
		}
	}

	for path, found := range wantPaths {
		if !found {
			t.Errorf("expected granular rule for %s but it was not generated", path)
		}
	}

	// Should NOT have blanket POST allow since granular vars are set
	for _, r := range cfg.Rules {
		if r.Match.Method == "POST,PUT,DELETE" && r.Match.Path == "/**" {
			t.Error("expected no blanket POST allow when granular vars set")
		}
	}
}

func TestCompatInvalidEnvValue(t *testing.T) {
	cfg := Defaults()
	t.Setenv("CONTAINERS", "maybe")

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate (env var is set, even if unparseable)")
	}

	// "maybe" is not a valid boolean, so CONTAINERS should be treated as not set
	// and no containers rule should be generated
	for _, r := range cfg.Rules {
		if r.Match.Path == "/containers/**" && r.Match.Method == "GET" && r.Action == "allow" {
			t.Error("expected no GET /containers/** rule when CONTAINERS=maybe (unparseable value)")
		}
	}
}

func TestLookupEnvBoolNotSet(t *testing.T) {
	val, found := lookupEnvBool("DEFINITELY_NOT_SET_" + t.Name())
	if found {
		t.Error("expected not found for unset env var")
	}
	if val {
		t.Error("expected false for unset env var")
	}
}

func TestRulesMatchDefaults(t *testing.T) {
	t.Run("matching rules", func(t *testing.T) {
		rules := append([]RuleConfig(nil), Defaults().Rules...)
		if !rulesMatchDefaults(rules) {
			t.Fatal("expected defaults clone to match default rules")
		}
	})

	t.Run("mismatched field", func(t *testing.T) {
		rules := append([]RuleConfig(nil), Defaults().Rules...)
		rules[0].Match.Path = "/ping"
		if rulesMatchDefaults(rules) {
			t.Fatal("expected changed rule field to break default match")
		}
	})

	t.Run("mismatched length", func(t *testing.T) {
		rules := Defaults().Rules[:len(Defaults().Rules)-1]
		if rulesMatchDefaults(rules) {
			t.Fatal("expected truncated rules to break default match")
		}
	})
}

func TestGeneratePingRules(t *testing.T) {
	t.Run("default enabled when unset", func(t *testing.T) {
		rules := generatePingRules()
		if len(rules) != 2 {
			t.Fatalf("generatePingRules() len = %d, want 2", len(rules))
		}
		if rules[0].Match.Method != "GET" || rules[0].Match.Path != "/_ping" {
			t.Fatalf("first ping rule = %+v, want GET /_ping", rules[0])
		}
		if rules[1].Match.Method != "HEAD" || rules[1].Match.Path != "/_ping" {
			t.Fatalf("second ping rule = %+v, want HEAD /_ping", rules[1])
		}
	})

	t.Run("disabled with zero", func(t *testing.T) {
		t.Setenv("PING", "0")
		rules := generatePingRules()
		if len(rules) != 0 {
			t.Fatalf("generatePingRules() len = %d, want 0", len(rules))
		}
	})
}

func TestGenerateVersionRulesDisabled(t *testing.T) {
	t.Setenv("VERSION", "0")
	if rules := generateVersionRules(); len(rules) != 0 {
		t.Fatalf("generateVersionRules() len = %d, want 0", len(rules))
	}
}

func TestGenerateEventsRulesDisabled(t *testing.T) {
	t.Setenv("EVENTS", "0")
	if rules := generateEventsRules(); len(rules) != 0 {
		t.Fatalf("generateEventsRules() len = %d, want 0", len(rules))
	}
}

func TestGeneratePostRules(t *testing.T) {
	t.Run("blanket allow without granular vars", func(t *testing.T) {
		t.Setenv("POST", "1")

		rules := generatePostRules()
		if len(rules) != 1 {
			t.Fatalf("generatePostRules() len = %d, want 1", len(rules))
		}
		if rules[0].Match.Method != "POST,PUT,DELETE" || rules[0].Match.Path != "/**" {
			t.Fatalf("blanket post rule = %+v, want POST,PUT,DELETE /**", rules[0])
		}
	})

	t.Run("granular allow suppresses blanket rule", func(t *testing.T) {
		t.Setenv("POST", "1")
		t.Setenv("ALLOW_START", "1")
		t.Setenv("ALLOW_STOP", "1")

		rules := generatePostRules()
		if len(rules) != 2 {
			t.Fatalf("generatePostRules() len = %d, want 2", len(rules))
		}
		if rules[0].Match.Path != "/containers/*/start" || rules[1].Match.Path != "/containers/*/stop" {
			t.Fatalf("granular post rules = %+v, want start/stop in deterministic order", rules)
		}
		for _, rule := range rules {
			if rule.Match.Method == "POST,PUT,DELETE" && rule.Match.Path == "/**" {
				t.Fatalf("unexpected blanket rule alongside granular rules: %+v", rules)
			}
		}
	})

	t.Run("ignored when POST disabled", func(t *testing.T) {
		t.Setenv("ALLOW_START", "1")

		rules := generatePostRules()
		if len(rules) != 0 {
			t.Fatalf("generatePostRules() len = %d, want 0", len(rules))
		}
	})
}
