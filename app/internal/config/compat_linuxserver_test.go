package config

import (
	"bytes"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"
)

// clearCompatEnv unsets every compat and recognized-but-unmapped variable the
// process inherited, restoring them when the test ends, so a contributor's
// exported shell cannot decide the outcome.
func clearCompatEnv(t *testing.T) {
	t.Helper()
	keys := append([]string(nil), compatVars...)
	for _, v := range unmappedCompatVars {
		keys = append(keys, v.name)
	}
	for _, key := range keys {
		value, ok := os.LookupEnv(key)
		if !ok {
			continue
		}
		t.Setenv(key, value)
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("Unsetenv(%q): %v", key, err)
		}
	}
}

func ruleStrings(rules []RuleConfig) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Action+" "+r.Match.Method+" "+r.Match.Path)
	}
	return out
}

func applyCompatEnv(t *testing.T, env map[string]string) []RuleConfig {
	t.Helper()
	clearCompatEnv(t)
	for k, v := range env {
		t.Setenv(k, v)
	}
	cfg := Defaults()
	if !ApplyCompat(&cfg, discardLogger) {
		t.Fatalf("expected compat to activate for %v", env)
	}
	return cfg.Rules
}

func TestLinuxServerFlavorDetection(t *testing.T) {
	lsioOnly := []string{
		"ALLOW_ARCHIVE", "ALLOW_CHANGES", "ALLOW_EXPORT", "ALLOW_LOGS", "ALLOW_TOP",
		"LIBPOD_CONTAINERS", "LIBPOD_EVENTS", "LIBPOD_EXEC", "LIBPOD_GENERATE", "LIBPOD_IMAGES",
		"LIBPOD_INFO", "LIBPOD_MANIFESTS", "LIBPOD_NETWORKS", "LIBPOD_PING", "LIBPOD_PLAY",
		"LIBPOD_PODS", "LIBPOD_SECRETS", "LIBPOD_SYSTEM", "LIBPOD_VERSION", "LIBPOD_VOLUMES",
		"LIBPOD_ALLOW_START", "LIBPOD_ALLOW_STOP", "LIBPOD_ALLOW_RESTARTS", "LIBPOD_ALLOW_PAUSE", "LIBPOD_ALLOW_UNPAUSE",
		"LIBPOD_ALLOW_POD_START", "LIBPOD_ALLOW_POD_STOP", "LIBPOD_ALLOW_POD_RESTARTS", "LIBPOD_ALLOW_POD_PAUSE", "LIBPOD_ALLOW_POD_UNPAUSE",
	}
	for _, key := range lsioOnly {
		for _, value := range []string{"0", "1", "garbage"} {
			t.Run(key+"="+value, func(t *testing.T) {
				clearCompatEnv(t)
				t.Setenv(key, value)
				if !linuxServerFlavorActive() {
					t.Fatalf("%s=%s should select the linuxserver flavor", key, value)
				}
				if !containsString(CompatEnvironmentVariables(), key) {
					t.Fatalf("CompatEnvironmentVariables() missing %s", key)
				}
			})
		}
	}

	tecnativa := []string{"CONTAINERS", "POST", "ALLOW_START", "ALLOW_RESTARTS", "ALLOW_PAUSE", "EXEC", "PING", "VERSION", "EVENTS"}
	for _, key := range tecnativa {
		t.Run("tecnativa "+key, func(t *testing.T) {
			clearCompatEnv(t)
			t.Setenv(key, "1")
			if linuxServerFlavorActive() {
				t.Fatalf("%s must not select the linuxserver flavor", key)
			}
		})
	}

	for _, key := range []string{"TIMEOUT_CLIENT", "TIMEOUT_SERVER", "DISABLE_IPV6"} {
		t.Run("unmapped "+key, func(t *testing.T) {
			clearCompatEnv(t)
			t.Setenv(key, "1")
			if linuxServerFlavorActive() {
				t.Fatalf("%s must not select the linuxserver flavor", key)
			}
			if hasCompatEnvVars() {
				t.Fatalf("%s must not activate compat", key)
			}
		})
	}
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// TestTecnativaFlavorRulesUnchanged pins the rules the Tecnativa flavor has
// always generated, so adding the LinuxServer flavor cannot move them.
func TestTecnativaFlavorRulesUnchanged(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{
			name: "defaults plus containers",
			env:  map[string]string{"CONTAINERS": "1"},
			want: []string{
				"allow GET,HEAD /_ping", "allow GET,HEAD /version", "allow GET,HEAD /events",
				"allow GET,HEAD /containers/**", "deny * /**",
			},
		},
		{
			name: "post with granular",
			env:  map[string]string{"CONTAINERS": "1", "POST": "1", "ALLOW_START": "1", "ALLOW_RESTARTS": "1", "ALLOW_PAUSE": "1"},
			want: []string{
				"allow * /_ping", "allow * /version", "allow * /events",
				"allow * /containers/**",
				"allow POST /containers/*/kill", "allow POST /containers/*/pause",
				"allow POST /containers/*/restart", "allow POST /containers/*/start",
				"allow POST /containers/*/stop", "deny * /**",
			},
		},
		{
			name: "exec section",
			env:  map[string]string{"EXEC": "1", "PING": "0"},
			want: []string{
				"allow GET,HEAD /version", "allow GET,HEAD /events",
				"allow GET,HEAD /exec/**", "allow GET,HEAD /containers/*/exec", "deny * /**",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleStrings(applyCompatEnv(t, tt.env))
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("rules =\n%v\nwant\n%v", got, tt.want)
			}
			for _, r := range applyCompatEnv(t, tt.env) {
				if strings.Contains(r.Match.Path, "libpod") || strings.Contains(r.Reason, "linuxserver") {
					t.Fatalf("tecnativa flavor leaked a linuxserver rule: %+v", r)
				}
			}
		})
	}
}

func TestLinuxServerGuardDenies(t *testing.T) {
	// Every guard is off by default, so an LSIO-only var alone yields all of them.
	rules := applyCompatEnv(t, map[string]string{"LIBPOD_PING": "1"})

	var wantGuards []string
	for _, sub := range []string{"archive", "changes", "export", "logs", "top", "pause"} {
		wantGuards = append(wantGuards,
			"deny * /containers/*/"+sub,
			"deny * /libpod/containers/*/"+sub,
			"deny * /libpod/pods/*/"+sub,
		)
	}
	wantGuards = append(wantGuards, "deny * /containers/*/exec", "deny * /libpod/containers/*/exec")

	got := ruleStrings(rules)
	if len(got) < len(wantGuards) || !reflect.DeepEqual(got[:len(wantGuards)], wantGuards) {
		t.Fatalf("leading rules =\n%v\nwant guards\n%v", got, wantGuards)
	}
	for _, r := range rules[:len(wantGuards)] {
		if !strings.HasPrefix(r.Reason, "linuxserver compat: ") || !strings.HasSuffix(r.Reason, " is not enabled") {
			t.Fatalf("guard reason = %q", r.Reason)
		}
	}
	if rules[len(wantGuards)-1].Reason != "linuxserver compat: EXEC is not enabled" {
		t.Fatalf("exec guard reason = %q", rules[len(wantGuards)-1].Reason)
	}
	if rules[9].Reason != "linuxserver compat: ALLOW_LOGS is not enabled" {
		t.Fatalf("logs guard reason = %q", rules[9].Reason)
	}
}

func TestLinuxServerGuardsLiftedPerVariable(t *testing.T) {
	tests := []struct {
		envKey  string
		paths   []string
		enabled string
	}{
		{"ALLOW_ARCHIVE", []string{"/containers/*/archive", "/libpod/containers/*/archive", "/libpod/pods/*/archive"}, "1"},
		{"ALLOW_CHANGES", []string{"/containers/*/changes", "/libpod/containers/*/changes", "/libpod/pods/*/changes"}, "true"},
		{"ALLOW_EXPORT", []string{"/containers/*/export", "/libpod/containers/*/export", "/libpod/pods/*/export"}, "yes"},
		{"ALLOW_LOGS", []string{"/containers/*/logs", "/libpod/containers/*/logs", "/libpod/pods/*/logs"}, "1"},
		{"ALLOW_TOP", []string{"/containers/*/top", "/libpod/containers/*/top", "/libpod/pods/*/top"}, "1"},
		{"ALLOW_PAUSE", []string{"/containers/*/pause", "/libpod/containers/*/pause", "/libpod/pods/*/pause"}, "1"},
		{"EXEC", []string{"/containers/*/exec", "/libpod/containers/*/exec"}, "1"},
	}
	for _, tt := range tests {
		t.Run(tt.envKey, func(t *testing.T) {
			rules := applyCompatEnv(t, map[string]string{tt.envKey: tt.enabled, "LIBPOD_PING": "1"})
			denied := map[string]bool{}
			for _, r := range rules {
				if r.Action == "deny" && r.Match.Method == "*" && r.Match.Path != "/**" {
					denied[r.Match.Path] = true
				}
			}
			for _, p := range tt.paths {
				if denied[p] {
					t.Fatalf("%s=%s should lift the deny on %s", tt.envKey, tt.enabled, p)
				}
			}
			// Every other guard stays.
			if tt.envKey != "ALLOW_TOP" && !denied["/containers/*/top"] {
				t.Fatalf("top guard should remain when only %s is set", tt.envKey)
			}
		})
	}
}

func TestLinuxServerMalformedGuardValueFailsClosed(t *testing.T) {
	rules := applyCompatEnv(t, map[string]string{"ALLOW_LOGS": "maybe"})
	got := ruleStrings(rules)
	if !containsString(got, "deny * /containers/*/logs") {
		t.Fatalf("unparseable ALLOW_LOGS must keep the guard, got %v", got)
	}
}

func TestLinuxServerGranularRules(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"allow start covers docker and libpod", map[string]string{"ALLOW_START": "1"},
			[]string{"allow POST /containers/*/start", "allow POST /libpod/containers/*/start", "allow POST /libpod/pods/*/start"}},
		{"allow stop", map[string]string{"ALLOW_STOP": "1"},
			[]string{"allow POST /containers/*/stop", "allow POST /libpod/containers/*/stop", "allow POST /libpod/pods/*/stop"}},
		{"allow restarts is stop restart kill", map[string]string{"ALLOW_RESTARTS": "1"},
			[]string{
				"allow POST /containers/*/kill", "allow POST /containers/*/restart", "allow POST /containers/*/stop",
				"allow POST /libpod/containers/*/stop", "allow POST /libpod/containers/*/restart", "allow POST /libpod/containers/*/kill",
				"allow POST /libpod/pods/*/stop", "allow POST /libpod/pods/*/restart", "allow POST /libpod/pods/*/kill",
			}},
		{"allow pause with guard lifted", map[string]string{"ALLOW_PAUSE": "1"},
			[]string{"allow POST /containers/*/pause", "allow POST /libpod/containers/*/pause", "allow POST /libpod/pods/*/pause"}},
		{"allow unpause", map[string]string{"ALLOW_UNPAUSE": "1"},
			[]string{"allow POST /containers/*/unpause", "allow POST /libpod/containers/*/unpause", "allow POST /libpod/pods/*/unpause"}},
		{"libpod start only touches containers", map[string]string{"LIBPOD_ALLOW_START": "1"},
			[]string{"allow POST /libpod/containers/*/start"}},
		{"libpod restarts", map[string]string{"LIBPOD_ALLOW_RESTARTS": "1"},
			[]string{"allow POST /libpod/containers/*/stop", "allow POST /libpod/containers/*/restart", "allow POST /libpod/containers/*/kill"}},
		{"libpod pod start only touches pods", map[string]string{"LIBPOD_ALLOW_POD_START": "1"},
			[]string{"allow POST /libpod/pods/*/start"}},
		{"libpod pod restarts", map[string]string{"LIBPOD_ALLOW_POD_RESTARTS": "1"},
			[]string{"allow POST /libpod/pods/*/stop", "allow POST /libpod/pods/*/restart", "allow POST /libpod/pods/*/kill"}},
		{"libpod pod stop", map[string]string{"LIBPOD_ALLOW_POD_STOP": "1"},
			[]string{"allow POST /libpod/pods/*/stop"}},
		{"libpod pod unpause", map[string]string{"LIBPOD_ALLOW_POD_UNPAUSE": "1"},
			[]string{"allow POST /libpod/pods/*/unpause"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := map[string]string{"LIBPOD_PING": "0"}
			for k, v := range tt.env {
				env[k] = v
			}
			got := ruleStrings(applyCompatEnv(t, env))
			for _, want := range tt.want {
				if !containsString(got, want) {
					t.Fatalf("missing %q in %v", want, got)
				}
			}
			posts := 0
			for _, g := range got {
				if strings.HasPrefix(g, "allow POST ") {
					posts++
				}
			}
			if posts != len(tt.want) {
				t.Fatalf("got %d POST allows, want %d: %v", posts, len(tt.want), got)
			}
		})
	}
}

func TestLinuxServerGranularNoDuplicates(t *testing.T) {
	got := ruleStrings(applyCompatEnv(t, map[string]string{"ALLOW_START": "1", "LIBPOD_ALLOW_START": "1"}))
	count := 0
	for _, g := range got {
		if g == "allow POST /libpod/containers/*/start" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected one libpod start allow, got %d in %v", count, got)
	}
}

func TestLinuxServerLibpodSections(t *testing.T) {
	sections := map[string]string{
		"LIBPOD_CONTAINERS": "/libpod/containers/**",
		"LIBPOD_EVENTS":     "/libpod/events",
		"LIBPOD_EXEC":       "/libpod/exec/**",
		"LIBPOD_GENERATE":   "/libpod/generate/**",
		"LIBPOD_IMAGES":     "/libpod/images/**",
		"LIBPOD_INFO":       "/libpod/info",
		"LIBPOD_MANIFESTS":  "/libpod/manifests/**",
		"LIBPOD_NETWORKS":   "/libpod/networks/**",
		"LIBPOD_PING":       "/libpod/_ping",
		"LIBPOD_PLAY":       "/libpod/play/**",
		"LIBPOD_PODS":       "/libpod/pods/**",
		"LIBPOD_SECRETS":    "/libpod/secrets/**",
		"LIBPOD_SYSTEM":     "/libpod/system/**",
		"LIBPOD_VERSION":    "/libpod/version",
		"LIBPOD_VOLUMES":    "/libpod/volumes/**",
	}
	for key, path := range sections {
		t.Run(key+" read only", func(t *testing.T) {
			got := ruleStrings(applyCompatEnv(t, map[string]string{key: "1"}))
			if !containsString(got, "allow GET,HEAD "+path) {
				t.Fatalf("missing read-only allow for %s in %v", path, got)
			}
		})
		t.Run(key+" with POST", func(t *testing.T) {
			got := ruleStrings(applyCompatEnv(t, map[string]string{key: "1", "POST": "1"}))
			if !containsString(got, "allow * "+path) {
				t.Fatalf("missing POST-enabled allow for %s in %v", path, got)
			}
		})
		t.Run(key+" disabled", func(t *testing.T) {
			got := ruleStrings(applyCompatEnv(t, map[string]string{key: "0"}))
			for _, g := range got {
				if strings.HasSuffix(g, " "+path) && strings.HasPrefix(g, "allow") {
					t.Fatalf("%s=0 still allows %s", key, path)
				}
			}
		})
	}

	t.Run("ping and version default on, the rest off", func(t *testing.T) {
		got := ruleStrings(applyCompatEnv(t, map[string]string{"ALLOW_LOGS": "0"}))
		for _, want := range []string{"allow GET,HEAD /libpod/_ping", "allow GET,HEAD /libpod/version"} {
			if !containsString(got, want) {
				t.Fatalf("missing default %q in %v", want, got)
			}
		}
		for _, g := range got {
			if strings.HasPrefix(g, "allow") && strings.Contains(g, "/libpod/") &&
				!strings.HasSuffix(g, "/libpod/_ping") && !strings.HasSuffix(g, "/libpod/version") {
				t.Fatalf("unexpected default libpod allow %q", g)
			}
		}
	})
}

func TestLinuxServerRuleOrder(t *testing.T) {
	got := ruleStrings(applyCompatEnv(t, map[string]string{
		"CONTAINERS": "1", "ALLOW_START": "1", "LIBPOD_PODS": "1", "ALLOW_LOGS": "1",
	}))
	index := func(rule string) int {
		for i, g := range got {
			if g == rule {
				return i
			}
		}
		t.Fatalf("rule %q missing from %v", rule, got)
		return -1
	}
	guard := index("deny * /containers/*/top")
	granular := index("allow POST /containers/*/start")
	section := index("allow GET,HEAD /containers/**")
	libpodSection := index("allow GET,HEAD /libpod/pods/**")
	if guard >= granular || granular >= section || section >= libpodSection {
		t.Fatalf("order wrong: guard=%d granular=%d section=%d libpod=%d in %v", guard, granular, section, libpodSection, got)
	}
	if got[len(got)-1] != "deny * /**" {
		t.Fatalf("last rule = %q, want catch-all deny", got[len(got)-1])
	}
}

func TestLinuxServerPauseGuardBeatsLibpodAllow(t *testing.T) {
	rules := applyCompatEnv(t, map[string]string{"LIBPOD_ALLOW_PAUSE": "1", "LIBPOD_ALLOW_POD_PAUSE": "1"})
	got := ruleStrings(rules)
	deny := indexOf(got, "deny * /libpod/containers/*/pause")
	allow := indexOf(got, "allow POST /libpod/containers/*/pause")
	if deny < 0 || allow < 0 || deny > allow {
		t.Fatalf("pause guard must precede LIBPOD_ALLOW_PAUSE allow: deny=%d allow=%d", deny, allow)
	}
	podDeny := indexOf(got, "deny * /libpod/pods/*/pause")
	podAllow := indexOf(got, "allow POST /libpod/pods/*/pause")
	if podDeny < 0 || podAllow < 0 || podDeny > podAllow {
		t.Fatalf("pause guard must precede LIBPOD_ALLOW_POD_PAUSE allow: deny=%d allow=%d", podDeny, podAllow)
	}
}

func indexOf(list []string, want string) int {
	for i, v := range list {
		if v == want {
			return i
		}
	}
	return -1
}

func TestCompatActivationLogFlavor(t *testing.T) {
	tests := []struct {
		name       string
		env        map[string]string
		wantFlavor string
		wantMsg    string
	}{
		{"tecnativa", map[string]string{"CONTAINERS": "1"}, "flavor=tecnativa", "tecnativa compatibility mode active"},
		{"linuxserver", map[string]string{"CONTAINERS": "1", "ALLOW_LOGS": "0"}, "flavor=linuxserver", "linuxserver compatibility mode active"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearCompatEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
			cfg := Defaults()
			if !ApplyCompat(&cfg, logger) {
				t.Fatal("expected compat to activate")
			}
			out := buf.String()
			if !strings.Contains(out, tt.wantFlavor) || !strings.Contains(out, tt.wantMsg) {
				t.Fatalf("log = %s, want %q and %q", out, tt.wantFlavor, tt.wantMsg)
			}
		})
	}
}

func TestCompatWarnsOnUnparseableLinuxServerVar(t *testing.T) {
	clearCompatEnv(t)
	t.Setenv("LIBPOD_PODS", "maybe")
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg := Defaults()
	ApplyCompat(&cfg, logger)
	if !strings.Contains(buf.String(), "unparseable boolean") || !strings.Contains(buf.String(), "LIBPOD_PODS") {
		t.Fatalf("expected unparseable warning for LIBPOD_PODS, got %s", buf.String())
	}
}

func TestCompatUnmappedVarWarnings(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"TIMEOUT_CLIENT", "upstream.request_timeout"},
		{"TIMEOUT_SERVER", "upstream.hijack_inactivity_timeout"},
		{"DISABLE_IPV6", "listen.address"},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			clearCompatEnv(t)
			t.Setenv(tt.key, "sekrit-value-30")
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
			cfg := Defaults()
			if ApplyCompat(&cfg, logger) {
				t.Fatalf("%s alone must not activate compat", tt.key)
			}
			out := buf.String()
			if !strings.Contains(out, "level=WARN") || !strings.Contains(out, tt.key) || !strings.Contains(out, tt.want) {
				t.Fatalf("expected warning naming %s and %s, got %s", tt.key, tt.want, out)
			}
			if strings.Contains(out, "sekrit-value-30") {
				t.Fatalf("warning must not echo the value: %s", out)
			}
		})
	}

	t.Run("does not select linuxserver flavor", func(t *testing.T) {
		rules := applyCompatEnv(t, map[string]string{"CONTAINERS": "1", "TIMEOUT_CLIENT": "5"})
		for _, r := range ruleStrings(rules) {
			if strings.Contains(r, "libpod") {
				t.Fatalf("TIMEOUT_CLIENT must not switch flavor, got %s", r)
			}
		}
	})
}

func TestCompatWarnsWhenIgnoredBecauseRulesConfigured(t *testing.T) {
	clearCompatEnv(t)
	t.Setenv("CONTAINERS", "1")
	t.Setenv("ALLOW_LOGS", "1")
	cfg := Defaults()
	cfg.Rules = []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if ApplyCompat(&cfg, logger) {
		t.Fatal("custom rules must keep compat off")
	}
	out := buf.String()
	if !strings.Contains(out, "compat env vars ignored because rules are configured") ||
		!strings.Contains(out, "CONTAINERS") || !strings.Contains(out, "ALLOW_LOGS") {
		t.Fatalf("expected ignored warning listing the vars, got %s", out)
	}
}

func TestCompatEnvironmentVariablesListsLinuxServerVars(t *testing.T) {
	clearCompatEnv(t)
	t.Setenv("ALLOW_LOGS", "0")
	t.Setenv("LIBPOD_ALLOW_POD_PAUSE", "0")
	t.Setenv("TIMEOUT_CLIENT", "5")
	got := CompatEnvironmentVariables()
	want := []string{"ALLOW_LOGS", "LIBPOD_ALLOW_POD_PAUSE"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CompatEnvironmentVariables() = %v, want %v", got, want)
	}
}

func TestTecnativaFlavorLogsMissingLinuxServerGuards(t *testing.T) {
	run := func(env map[string]string) string {
		clearCompatEnv(t)
		for k, v := range env {
			t.Setenv(k, v)
		}
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		cfg := Defaults()
		if !ApplyCompat(&cfg, logger) {
			t.Fatal("expected compat to activate")
		}
		return buf.String()
	}

	out := run(map[string]string{"CONTAINERS": "1"})
	if strings.Count(out, "LinuxServer guards are not applied") != 1 || !strings.Contains(out, "ALLOW_LOGS=0") {
		t.Fatalf("expected one guards-not-applied line naming ALLOW_LOGS=0, got %s", out)
	}
	if !strings.Contains(out, "level=INFO") {
		t.Fatalf("expected Info level, got %s", out)
	}

	for name, env := range map[string]map[string]string{
		"containers off":     {"CONTAINERS": "0", "POST": "1"},
		"no containers":      {"IMAGES": "1"},
		"linuxserver flavor": {"CONTAINERS": "1", "ALLOW_LOGS": "0"},
	} {
		if out := run(env); strings.Contains(out, "guards are not applied") {
			t.Fatalf("%s: unexpected guards-not-applied line: %s", name, out)
		}
	}
}

func TestLinuxServerExecSectionDoesNotOpenContainerExec(t *testing.T) {
	got := ruleStrings(applyCompatEnv(t, map[string]string{"EXEC": "1", "ALLOW_LOGS": "0", "POST": "1"}))
	if containsString(got, "allow * /containers/*/exec") {
		t.Fatalf("EXEC=1 alone must not allow /containers/*/exec: %v", got)
	}
	if !containsString(got, "allow * /exec/**") {
		t.Fatalf("EXEC=1 should still allow /exec/**: %v", got)
	}
}
