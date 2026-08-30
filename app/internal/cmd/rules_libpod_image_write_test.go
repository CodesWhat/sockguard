package cmd

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

func findBodySensitiveWriteEndpoint(t *testing.T, method, path string) bodySensitiveWriteEndpoint {
	t.Helper()

	for _, candidate := range bodySensitiveWriteEndpoints {
		if candidate.method == method && candidate.path == path {
			return candidate
		}
	}
	t.Fatalf("%s %s is missing from the body-sensitive write catalog", method, path)
	return bodySensitiveWriteEndpoint{}
}

// TestBodySensitiveWriteCatalogCoversLibpodImageWrites pins the
// config-validation half of the libpod image-write gap. The two endpoints
// that reuse an existing request_body gate must be recognized as inspected,
// so allowing them does not spuriously demand
// insecure_allow_body_blind_writes; the three whose input never crosses the
// socket must NOT be, so allowing them always does.
func TestBodySensitiveWriteCatalogCoversLibpodImageWrites(t *testing.T) {
	tests := []struct {
		path          string
		wantInspected bool
	}{
		// Same archive body as POST /images/load, read by the same
		// imageLoadPolicy against request_body.image_load.
		{path: "/libpod/images/load", wantInspected: true},
		// Gated by request_body.image_pull.allow_imports, false by default —
		// the same flag that gates the Docker-compat fromSrc import.
		{path: "/libpod/images/import", wantInspected: true},
		// Input is a daemon-host path (`localcontextdir` / `path`), so there
		// is nothing on the wire to inspect.
		{path: "/libpod/local/build", wantInspected: false},
		{path: "/libpod/local/images/load", wantInspected: false},
		// Source is a path segment and destination is an SSH endpoint; no
		// body, and no registry to allowlist.
		{path: "/libpod/images/scp/sockguard-test", wantInspected: false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			endpoint := findBodySensitiveWriteEndpoint(t, http.MethodPost, tt.path)
			// An empty RequestBodyConfig is the fail-closed default posture:
			// whatever protection these report has to hold without the
			// operator configuring anything.
			if got := bodyInspectionConfiguredForEndpoint(config.RequestBodyConfig{}, endpoint); got != tt.wantInspected {
				t.Fatalf("bodyInspectionConfiguredForEndpoint(%s) = %v, want %v", tt.path, got, tt.wantInspected)
			}
		})
	}
}

// TestValidateAndCompileRulesAllowsLibpodImageLoadAndImport is the positive
// half: a rule opening the two inspected libpod image writes validates clean
// under the default config, exactly as the Docker-compat spellings do.
func TestValidateAndCompileRulesAllowsLibpodImageLoadAndImport(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/load"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/import"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
	}
}

// TestValidateAndCompileRulesRejectsLibpodLocalApiWrites pins that the two
// "local API" routes cannot be opened silently. A realistic operator rule —
// one that reaches for the whole libpod image surface — has to name them.
func TestValidateAndCompileRulesRejectsLibpodLocalApiWrites(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/local/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("validateAndCompileRules() returned no error, want the blind-write acknowledgment demanded")
	}
	for _, want := range []string{
		"POST /libpod/local/build",
		"POST /libpod/local/images/load",
		"insecure_allow_body_blind_writes=true",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to mention %q", err, want)
		}
	}

	cfg.InsecureAllowBodyBlindWrites = true
	if _, err := validateAndCompileRules(&cfg); err != nil {
		t.Fatalf("validateAndCompileRules() error = %v once acknowledged, want nil", err)
	}
}

// TestValidateAndCompileRulesRejectsLibpodImageScpTwice pins the deliberate
// double-gating of POST /libpod/images/scp/{name}. It moves a local image to
// a caller-named SSH host (egress) AND materializes a local image from one
// (ingest that no registry allowlist can see), so it sits in both catalogs
// and clearing one acknowledgment is not enough to open it.
func TestValidateAndCompileRulesRejectsLibpodImageScpTwice(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	err := errorFromValidate(t, &cfg)
	if !strings.Contains(err.Error(), "POST /libpod/images/scp/sockguard-test") ||
		!strings.Contains(err.Error(), "insecure_allow_body_blind_writes=true") {
		t.Fatalf("error = %q, want the uninspected-write acknowledgment demanded first", err)
	}

	cfg.InsecureAllowBodyBlindWrites = true
	err = errorFromValidate(t, &cfg)
	if !strings.Contains(err.Error(), "POST /libpod/images/scp/sockguard-test") ||
		!strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
		t.Fatalf("error = %q, want the exfiltration acknowledgment demanded second", err)
	}

	cfg.InsecureAllowReadExfiltration = true
	if _, err := validateAndCompileRules(&cfg); err != nil {
		t.Fatalf("validateAndCompileRules() error = %v once both are acknowledged, want nil", err)
	}
}

func TestValidateAndCompileRulesRejectsExactLibpodImageScpTwice(t *testing.T) {
	const exactPath = "/libpod/images/scp/alpine"
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: exactPath}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	err := errorFromValidate(t, &cfg)
	if !strings.Contains(err.Error(), "POST "+exactPath) ||
		!strings.Contains(err.Error(), "insecure_allow_body_blind_writes=true") {
		t.Fatalf("error = %q, want the exact path to demand the uninspected-write acknowledgment", err)
	}

	cfg.InsecureAllowBodyBlindWrites = true
	err = errorFromValidate(t, &cfg)
	if !strings.Contains(err.Error(), "POST "+exactPath) ||
		!strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
		t.Fatalf("error = %q, want the exact path to demand the exfiltration acknowledgment", err)
	}

	cfg.InsecureAllowReadExfiltration = true
	if _, err := validateAndCompileRules(&cfg); err != nil {
		t.Fatalf("validateAndCompileRules() error = %v once both are acknowledged, want nil", err)
	}
}

func TestValidateAndCompileRulesReportsExactLibpodImagePushRepresentativeOnce(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		profile string
	}{
		{
			name: "top-level representative",
			path: "/libpod/images/sockguard-test/push",
		},
		{
			name:    "named-profile scp-prefix representative",
			path:    "/libpod/images/scp/sockguard-test/push",
			profile: "publisher",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: tt.path}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			}
			cfg := config.Defaults()
			if tt.profile == "" {
				cfg.Rules = rules
			} else {
				cfg.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}
				cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: tt.profile, Rules: rules}}
			}

			err := errorFromValidate(t, &cfg)
			endpoint := http.MethodPost + " " + tt.path
			if got := strings.Count(err.Error(), endpoint); got != 1 {
				t.Fatalf("startup refusal count for %q = %d, want 1; error: %v", endpoint, got, err)
			}
			if tt.profile != "" && !strings.Contains(err.Error(), tt.profile) {
				t.Fatalf("startup refusal omitted profile %q: %v", tt.profile, err)
			}
		})
	}
}

func TestValidateAndCompileRulesPreservesExactLibpodImageScpPathBytes(t *testing.T) {
	const exactPath = "/libpod/images/scp/alpine "
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: exactPath}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	err := errorFromValidate(t, &cfg)
	if !strings.Contains(err.Error(), "POST "+exactPath) ||
		!strings.Contains(err.Error(), "insecure_allow_body_blind_writes=true") {
		t.Fatalf("error = %q, want the byte-exact SCP path to demand the uninspected-write acknowledgment", err)
	}

	cfg.InsecureAllowBodyBlindWrites = true
	err = errorFromValidate(t, &cfg)
	if !strings.Contains(err.Error(), "POST "+exactPath) ||
		!strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
		t.Fatalf("error = %q, want the byte-exact SCP path to demand the exfiltration acknowledgment", err)
	}

	cfg.InsecureAllowReadExfiltration = true
	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v once both are acknowledged, want nil", err)
	}
	request := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: exactPath}}
	if action, _, _ := filter.Evaluate(compiled, request); action != filter.ActionAllow {
		t.Fatalf("Evaluate(%q) action = %q, want %q", exactPath, action, filter.ActionAllow)
	}
}

func TestValidateAndCompileRulesRejectsLibpodImageScpWhenSentinelIsShadowed(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/sockguard-test"}, Action: "deny"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	err := errorFromValidate(t, &cfg)
	if !strings.Contains(err.Error(), "insecure_allow_body_blind_writes=true") {
		t.Fatalf("error = %q, want the reachable wildcard SCP route to demand the blind-write acknowledgment", err)
	}

	cfg.InsecureAllowBodyBlindWrites = true
	err = errorFromValidate(t, &cfg)
	if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
		t.Fatalf("error = %q, want the reachable wildcard SCP route to demand the exfiltration acknowledgment", err)
	}
}

func TestValidateAndCompileRulesRejectsConstrainedLibpodImageScpWildcard(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/alpine-*"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	err := errorFromValidate(t, &cfg)
	if !strings.Contains(err.Error(), "insecure_allow_body_blind_writes=true") {
		t.Fatalf("error = %q, want the constrained wildcard SCP route to demand the blind-write acknowledgment", err)
	}
}

func TestValidateAndCompileRulesIgnoresUnreachableLibpodImageScpAllow(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/**"}, Action: "deny"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	if _, err := validateAndCompileRules(&cfg); err != nil {
		t.Fatalf("validateAndCompileRules() error = %v, want the fully shadowed allow ignored", err)
	}
}

func TestValidateAndCompileRulesUsesGlobLanguageForLibpodImageScpShadowing(t *testing.T) {
	t.Run("earlier deep-glob deny fully shadows the later allow", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Rules = []config.RuleConfig{
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/**/scp/**"}, Action: "deny"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/alpine-*"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}

		if _, err := validateAndCompileRules(&cfg); err != nil {
			t.Fatalf("validateAndCompileRules() error = %v, want the fully shadowed allow ignored", err)
		}
	})

	t.Run("partial earlier glob does not hide a reachable SCP allow", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Rules = []config.RuleConfig{
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/**/scp/*/push"}, Action: "deny"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/alpine-*"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}

		err := errorFromValidate(t, &cfg)
		if !strings.Contains(err.Error(), "insecure_allow_body_blind_writes=true") {
			t.Fatalf("error = %q, want the reachable SCP allow acknowledged", err)
		}
	})

	t.Run("a different method does not shadow POST", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Rules = []config.RuleConfig{
			{Match: config.MatchConfig{Method: http.MethodGet, Path: "/libpod/**/scp/**"}, Action: "deny"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/alpine-*"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}

		err := errorFromValidate(t, &cfg)
		if !strings.Contains(err.Error(), "insecure_allow_body_blind_writes=true") {
			t.Fatalf("error = %q, want the POST SCP allow acknowledged", err)
		}
	})
}

func TestValidateAndCompileRulesPreservesOrderedWildcardPathBytes(t *testing.T) {
	t.Run("SCP deny with trailing whitespace does not shadow", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Rules = []config.RuleConfig{
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/sockguard-test"}, Action: "deny"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/sockguard-test/push"}, Action: "deny"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/** "}, Action: "deny"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/**"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}

		err := errorFromValidate(t, &cfg)
		if !strings.Contains(err.Error(), "insecure_allow_body_blind_writes=true") {
			t.Fatalf("error = %q, want the reachable SCP wildcard to demand the uninspected-write acknowledgment", err)
		}

		cfg.InsecureAllowBodyBlindWrites = true
		err = errorFromValidate(t, &cfg)
		if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
			t.Fatalf("error = %q, want the reachable SCP wildcard to demand the exfiltration acknowledgment", err)
		}

		cfg.InsecureAllowReadExfiltration = true
		compiled, err := validateAndCompileRules(&cfg)
		if err != nil {
			t.Fatalf("validateAndCompileRules() error = %v once both are acknowledged, want nil", err)
		}
		const path = "/libpod/images/scp/alpine"
		request := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: path}}
		if action, _, _ := filter.Evaluate(compiled, request); action != filter.ActionAllow {
			t.Fatalf("Evaluate(%q) action = %q, want %q", path, action, filter.ActionAllow)
		}
	})

	t.Run("slash-push deny with trailing whitespace does not shadow", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Rules = []config.RuleConfig{
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/**/push "}, Action: "deny"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/team/**"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}

		err := errorFromValidate(t, &cfg)
		if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
			t.Fatalf("error = %q, want the reachable slash-bearing push to demand the exfiltration acknowledgment", err)
		}

		cfg.InsecureAllowReadExfiltration = true
		compiled, err := validateAndCompileRules(&cfg)
		if err != nil {
			t.Fatalf("validateAndCompileRules() error = %v once acknowledged, want nil", err)
		}
		const path = "/libpod/images/team/acme/app/push"
		request := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: path}}
		if action, _, _ := filter.Evaluate(compiled, request); action != filter.ActionAllow {
			t.Fatalf("Evaluate(%q) action = %q, want %q", path, action, filter.ActionAllow)
		}
	})
}

func TestValidateAndCompileRulesMatchesRelativeSegmentGlobsLikeRuntime(t *testing.T) {
	for _, profile := range []bool{false, true} {
		name := "default policy"
		if profile {
			name = "named profile"
		}
		t.Run(name, func(t *testing.T) {
			t.Run("slash-bearing image push", func(t *testing.T) {
				const pattern = "*/images/team/*/push"
				const requestPath = "/libpod/images/team/acme/push"
				rules := []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: pattern}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg := config.Defaults()
				if profile {
					cfg.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}
					cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "publisher", Rules: rules}}
				} else {
					cfg.Rules = rules
				}

				err := errorFromValidate(t, &cfg)
				if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
					t.Fatalf("error = %q, want the relative segment glob to demand the exfiltration acknowledgment", err)
				}

				cfg.InsecureAllowReadExfiltration = true
				if _, err := validateAndCompileRules(&cfg); err != nil {
					t.Fatalf("validateAndCompileRules() error = %v once acknowledged, want nil", err)
				}
				compiled, err := compileConfiguredRules(rules)
				if err != nil {
					t.Fatalf("compileConfiguredRules() error = %v", err)
				}
				request := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: requestPath}}
				if action, _, _ := filter.Evaluate(compiled, request); action != filter.ActionAllow {
					t.Fatalf("Evaluate(%q) action = %q, want %q for pattern %q", requestPath, action, filter.ActionAllow, pattern)
				}
			})

			t.Run("image SCP", func(t *testing.T) {
				const pattern = "*libpod/images/scp/team/*"
				const requestPath = "/libpod/images/scp/team/alpine"
				rules := []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: pattern}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg := config.Defaults()
				if profile {
					cfg.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}
					cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "transfer", Rules: rules}}
				} else {
					cfg.Rules = rules
				}

				err := errorFromValidate(t, &cfg)
				if !strings.Contains(err.Error(), "insecure_allow_body_blind_writes=true") {
					t.Fatalf("error = %q, want the relative segment glob to demand the blind-write acknowledgment", err)
				}

				cfg.InsecureAllowBodyBlindWrites = true
				err = errorFromValidate(t, &cfg)
				if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
					t.Fatalf("error = %q, want the relative segment glob to demand the exfiltration acknowledgment", err)
				}

				cfg.InsecureAllowReadExfiltration = true
				if _, err := validateAndCompileRules(&cfg); err != nil {
					t.Fatalf("validateAndCompileRules() error = %v once acknowledged, want nil", err)
				}
				compiled, err := compileConfiguredRules(rules)
				if err != nil {
					t.Fatalf("compileConfiguredRules() error = %v", err)
				}
				request := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: requestPath}}
				if action, _, _ := filter.Evaluate(compiled, request); action != filter.ActionAllow {
					t.Fatalf("Evaluate(%q) action = %q, want %q for pattern %q", requestPath, action, filter.ActionAllow, pattern)
				}
			})
		})
	}
}

func TestValidateAndCompileRulesRejectsSlashBearingLibpodImagePush(t *testing.T) {
	for _, path := range []string{
		"/libpod/images/scp/acme/app/push",
		"/libpod/images/scp/**/push",
		"/libpod/images/team/**/push",
	} {
		t.Run(path, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Rules = []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: path}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			}

			err := errorFromValidate(t, &cfg)
			if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
				t.Fatalf("error = %q, want the slash-bearing image push to require the read-exfiltration acknowledgment", err)
			}
		})
	}

	t.Run("wildcard remains reachable after its representative is denied", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Rules = []config.RuleConfig{
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/sockguard-test/push"}, Action: "deny"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/**/push"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}

		err := errorFromValidate(t, &cfg)
		if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
			t.Fatalf("error = %q, want the still-reachable slash-bearing image push to require the read-exfiltration acknowledgment", err)
		}
	})

	t.Run("non-scp wildcard remains reachable after the generic representative is denied", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Rules = []config.RuleConfig{
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/sockguard-test/push"}, Action: "deny"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/team/**/push"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}

		err := errorFromValidate(t, &cfg)
		if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
			t.Fatalf("error = %q, want the still-reachable non-SCP image push to require the read-exfiltration acknowledgment", err)
		}
	})
}

// TestServePolicyConfigWiresImageLoadBlindWriteAck pins the wiring half of
// the local-image-load guard. insecure_allow_body_blind_writes is a
// top-level flag, not part of a request_body block, so it reaches
// filter.ImageLoadOptions only because attachRuntimeInspectors copies it —
// and the inspector's deny for POST /libpod/local/images/load is unreachable
// to acknowledge if that copy goes missing. Driven through
// servePolicyConfig, the production path, rather than the helper directly.
func TestServePolicyConfigWiresImageLoadBlindWriteAck(t *testing.T) {
	cfg := config.Defaults()
	if got := servePolicyConfig(&cfg, nil).ImageLoad.AllowBlindWrites; got {
		t.Fatalf("ImageLoad.AllowBlindWrites = %v by default, want false", got)
	}

	cfg.InsecureAllowBodyBlindWrites = true
	if got := servePolicyConfig(&cfg, nil).ImageLoad.AllowBlindWrites; !got {
		t.Fatal("ImageLoad.AllowBlindWrites = false after insecure_allow_body_blind_writes: true, want true")
	}
}

func errorFromValidate(t *testing.T, cfg *config.Config) error {
	t.Helper()

	_, err := validateAndCompileRules(cfg)
	if err == nil {
		t.Fatal("validateAndCompileRules() returned no error, want one")
	}
	return err
}
