package config

import (
	"bytes"
	"log/slog"
	"strings"
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

	// Should have: read-only containers section and catch-all deny.
	found := false
	for _, r := range cfg.Rules {
		if r.Match.Path == "/containers/**" && r.Match.Method == "GET,HEAD" && r.Action == "allow" {
			found = true
		}
	}
	if !found {
		t.Error("expected GET,HEAD /containers/** allow rule")
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

func TestCompatPostDoesNotGrantBlanketWriteFallback(t *testing.T) {
	cfg := Defaults()
	t.Setenv("POST", "1")

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate")
	}

	for _, r := range cfg.Rules {
		if r.Match.Method == "POST,PUT,DELETE" && r.Match.Path == "/**" && r.Action == "allow" {
			t.Fatalf("expected no blanket POST fallback, got rule: %+v", r)
		}
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

func TestCompatDefaultOnSectionEnvSemantics(t *testing.T) {
	tests := []struct {
		name      string
		envKey    string
		envValue  string
		trigger   bool
		path      string
		wantAllow bool
	}{
		{name: "unset uses default allow", envKey: "PING", trigger: true, path: "/_ping", wantAllow: true},
		{name: "true keeps section enabled", envKey: "PING", envValue: "1", path: "/_ping", wantAllow: true},
		{name: "false disables section", envKey: "PING", envValue: "0", path: "/_ping", wantAllow: false},
		{name: "malformed fails closed", envKey: "PING", envValue: "maybe", path: "/_ping", wantAllow: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			if tt.trigger {
				t.Setenv("CONTAINERS", "1")
			}
			if tt.envValue != "" {
				t.Setenv(tt.envKey, tt.envValue)
			}

			if !ApplyCompat(&cfg, discardLogger) {
				t.Fatal("expected compat to activate")
			}

			found := false
			for _, r := range cfg.Rules {
				if r.Match.Path == tt.path && r.Action == "allow" {
					found = true
					break
				}
			}
			if found != tt.wantAllow {
				t.Fatalf("allow rule for %s present = %v, want %v; rules: %+v", tt.path, found, tt.wantAllow, cfg.Rules)
			}
		})
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

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate")
	}

	foundStart := false
	foundStop := false
	for _, r := range cfg.Rules {
		switch {
		case r.Match.Method == "POST" && r.Match.Path == "/containers/*/start":
			foundStart = true
		case r.Match.Method == "POST" && r.Match.Path == "/containers/*/stop":
			foundStop = true
		}
	}
	if !foundStart || !foundStop {
		t.Fatalf("expected granular start/stop rules without POST=1, got rules: %+v", cfg.Rules)
	}
}

func TestCompatMultipleGranularVars(t *testing.T) {
	cfg := Defaults()
	t.Setenv("ALLOW_START", "1")
	t.Setenv("ALLOW_STOP", "1")
	t.Setenv("ALLOW_RESTARTS", "1")

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate")
	}

	wantPaths := map[string]bool{
		"/containers/*/start":   false,
		"/containers/*/stop":    false,
		"/containers/*/restart": false,
		"/containers/*/kill":    false,
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

func TestCompatCategoryAndGranularFlagsTogether(t *testing.T) {
	cfg := Defaults()
	t.Setenv("CONTAINERS", "1")
	t.Setenv("IMAGES", "0")
	t.Setenv("POST", "1")
	t.Setenv("ALLOW_START", "1")
	t.Setenv("ALLOW_STOP", "1")

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate")
	}

	foundContainers := false
	foundImages := false
	foundStart := false
	foundStop := false
	foundBlanketPost := false

	for _, r := range cfg.Rules {
		switch {
		case r.Match.Method == "*" && r.Match.Path == "/containers/**" && r.Action == "allow":
			foundContainers = true
		case r.Match.Method == "*" && r.Match.Path == "/images/**" && r.Action == "allow":
			foundImages = true
		case r.Match.Method == "POST" && r.Match.Path == "/containers/*/start" && r.Action == "allow":
			foundStart = true
		case r.Match.Method == "POST" && r.Match.Path == "/containers/*/stop" && r.Action == "allow":
			foundStop = true
		case r.Match.Method == "POST,PUT,DELETE" && r.Match.Path == "/**" && r.Action == "allow":
			foundBlanketPost = true
		}
	}

	if !foundContainers {
		t.Fatal("expected * /containers/** allow rule when CONTAINERS=1 and POST=1")
	}
	if foundImages {
		t.Fatal("expected no /images/** allow rule when IMAGES=0")
	}
	if !foundStart || !foundStop {
		t.Fatalf("expected granular start/stop rules, got rules: %+v", cfg.Rules)
	}
	if foundBlanketPost {
		t.Fatalf("expected no blanket POST fallback when granular ALLOW_* flags are set, got rules: %+v", cfg.Rules)
	}
}

func TestCompatInvalidEnvValue(t *testing.T) {
	cfg := Defaults()
	t.Setenv("CONTAINERS", "maybe")

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate (env var is set, even if unparseable)")
	}

	// "maybe" is not a valid boolean, so CONTAINERS should fail closed and
	// generate no containers allow rule.
	for _, r := range cfg.Rules {
		if r.Match.Path == "/containers/**" && r.Action == "allow" {
			t.Error("expected no GET /containers/** rule when CONTAINERS=maybe (unparseable value)")
		}
	}
}

func TestCompatMalformedDefaultOnValuesFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		envKey string
		path   string
	}{
		{name: "ping", envKey: "PING", path: "/_ping"},
		{name: "version", envKey: "VERSION", path: "/version"},
		{name: "events", envKey: "EVENTS", path: "/events"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			t.Setenv(tt.envKey, "maybe")

			if !ApplyCompat(&cfg, discardLogger) {
				t.Fatal("expected compat to activate")
			}

			for _, r := range cfg.Rules {
				if r.Match.Path == tt.path && r.Action == "allow" {
					t.Fatalf("expected no allow rule for %s when %s=maybe, got %+v", tt.path, tt.envKey, r)
				}
			}
		})
	}
}

func TestCompatMalformedDefaultOnValueStillWarnsAndActivates(t *testing.T) {
	cfg := Defaults()
	t.Setenv("PING", "maybe")

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	if !ApplyCompat(&cfg, logger) {
		t.Fatal("expected compat to activate when malformed env var is present")
	}

	if !strings.Contains(logBuf.String(), "ignoring compat env var with unparseable boolean value") {
		t.Fatalf("expected malformed compat warning, got logs: %s", logBuf.String())
	}
}

func TestCompatSupportsExtendedTecnativaSections(t *testing.T) {
	cfg := Defaults()
	t.Setenv("AUTH", "1")
	t.Setenv("SERVICES", "1")
	t.Setenv("SYSTEM", "1")

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate")
	}

	wantRules := map[string]string{
		"/auth/**":     "GET,HEAD",
		"/services/**": "GET,HEAD",
		"/system/**":   "GET,HEAD",
	}

	for _, r := range cfg.Rules {
		wantMethod, ok := wantRules[r.Match.Path]
		if !ok || r.Action != "allow" {
			continue
		}
		if r.Match.Method != wantMethod {
			t.Fatalf("rule %s method = %q, want %q", r.Match.Path, r.Match.Method, wantMethod)
		}
		delete(wantRules, r.Match.Path)
	}

	if len(wantRules) > 0 {
		t.Fatalf("missing expected compat section rules: %+v", wantRules)
	}
}

func TestCompatAllowRestartAliasStillWorks(t *testing.T) {
	cfg := Defaults()
	t.Setenv("ALLOW_RESTART", "1")

	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatal("expected compat to activate")
	}

	wantPaths := map[string]bool{
		"/containers/*/stop":    false,
		"/containers/*/restart": false,
		"/containers/*/kill":    false,
	}

	for _, r := range cfg.Rules {
		if _, ok := wantPaths[r.Match.Path]; ok && r.Match.Method == "POST" && r.Action == "allow" {
			wantPaths[r.Match.Path] = true
		}
	}

	for path, found := range wantPaths {
		if !found {
			t.Fatalf("expected restart alias to allow %s, got rules: %+v", path, cfg.Rules)
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

func TestGenerateSectionRules(t *testing.T) {
	t.Run("default enabled when unset", func(t *testing.T) {
		rules := generateSectionRules()
		if len(rules) != 3 {
			t.Fatalf("generateSectionRules() len = %d, want 3", len(rules))
		}
		if rules[0].Match.Method != "GET,HEAD" || rules[0].Match.Path != "/_ping" {
			t.Fatalf("first section rule = %+v, want GET,HEAD /_ping", rules[0])
		}
		if rules[1].Match.Method != "GET,HEAD" || rules[1].Match.Path != "/version" {
			t.Fatalf("second section rule = %+v, want GET,HEAD /version", rules[1])
		}
		if rules[2].Match.Method != "GET,HEAD" || rules[2].Match.Path != "/events" {
			t.Fatalf("third section rule = %+v, want GET,HEAD /events", rules[2])
		}
	})

	t.Run("post broadens methods on enabled sections", func(t *testing.T) {
		t.Setenv("POST", "1")
		t.Setenv("SERVICES", "1")

		rules := generateSectionRules()
		foundServices := false
		for _, rule := range rules {
			if rule.Match.Path == "/services/**" {
				foundServices = true
				if rule.Match.Method != "*" {
					t.Fatalf("service rule method = %q, want *", rule.Match.Method)
				}
			}
		}
		if !foundServices {
			t.Fatalf("expected /services/** rule in %+v", rules)
		}
	})

	t.Run("disabled with zero", func(t *testing.T) {
		t.Setenv("PING", "0")
		t.Setenv("VERSION", "0")
		t.Setenv("EVENTS", "0")
		rules := generateSectionRules()
		if len(rules) != 0 {
			t.Fatalf("generateSectionRules() len = %d, want 0", len(rules))
		}
	})
}

// TestCompatRuleIndexArithmetic kills the ARITHMETIC_BASE mutant at
// compat.go:97:14 (i+1 in debug log). The debug log emits "index=<N>" for each
// generated rule; if mutated to i-1 the first rule logs "index=-1" instead of
// "index=1".
func TestCompatRuleIndexArithmetic(t *testing.T) {
	cfg := Defaults()
	t.Setenv("PING", "1")

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	if !ApplyCompat(&cfg, logger) {
		t.Fatal("expected compat to activate")
	}

	logOutput := logBuf.String()
	// The first rule must log index=1 (not index=0 or index=-1).
	if !strings.Contains(logOutput, "index=1") {
		t.Fatalf("expected 'index=1' in debug log (1-based), got: %s", logOutput)
	}
	if strings.Contains(logOutput, "index=0") || strings.Contains(logOutput, "index=-1") {
		t.Fatalf("unexpected 0-based or negative index in debug log: %s", logOutput)
	}
}

func TestCompatAllowPruneDeleteKillGeneratedRules(t *testing.T) {
	tests := []struct {
		name      string
		envKey    string
		wantRules []struct{ method, path string }
	}{
		{
			name:   "ALLOW_PRUNE",
			envKey: "ALLOW_PRUNE",
			wantRules: []struct{ method, path string }{
				{"POST", "/containers/prune"},
			},
		},
		{
			name:   "ALLOW_DELETE",
			envKey: "ALLOW_DELETE",
			wantRules: []struct{ method, path string }{
				{"DELETE", "/containers/*"},
			},
		},
		{
			name:   "ALLOW_KILL",
			envKey: "ALLOW_KILL",
			wantRules: []struct{ method, path string }{
				{"POST", "/containers/*/kill"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			t.Setenv(tt.envKey, "1")

			if !ApplyCompat(&cfg, discardLogger) {
				t.Fatal("expected compat to activate")
			}

			for _, want := range tt.wantRules {
				found := false
				for _, r := range cfg.Rules {
					if r.Match.Method == want.method && r.Match.Path == want.path && r.Action == "allow" {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected allow rule %s %s not found in rules: %+v", want.method, want.path, cfg.Rules)
				}
			}

			last := cfg.Rules[len(cfg.Rules)-1]
			if last.Action != "deny" || last.Match.Method != "*" {
				t.Error("expected catch-all deny as last rule")
			}
		})
	}
}

func TestGenerateGranularPostRules(t *testing.T) {
	t.Run("restarts env allows stop restart and kill", func(t *testing.T) {
		t.Setenv("ALLOW_RESTARTS", "1")

		rules := generateGranularPostRules()
		if len(rules) != 3 {
			t.Fatalf("generateGranularPostRules() len = %d, want 3", len(rules))
		}
		if rules[0].Match.Path != "/containers/*/kill" ||
			rules[1].Match.Path != "/containers/*/restart" ||
			rules[2].Match.Path != "/containers/*/stop" {
			t.Fatalf("granular restart rules = %+v, want kill/restart/stop in deterministic order", rules)
		}
	})

	t.Run("works without post enabled", func(t *testing.T) {
		t.Setenv("ALLOW_START", "1")

		rules := generateGranularPostRules()
		if len(rules) != 1 {
			t.Fatalf("generateGranularPostRules() len = %d, want 1", len(rules))
		}
		if rules[0].Match.Method != "POST" || rules[0].Match.Path != "/containers/*/start" {
			t.Fatalf("granular rule = %+v, want POST /containers/*/start", rules[0])
		}
	})
}
