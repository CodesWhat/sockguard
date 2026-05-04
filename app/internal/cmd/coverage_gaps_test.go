package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/ui"
)

// ---- invalidClientProfileHandler (was 0%) ----------------------------------

func TestInvalidClientProfileHandler(t *testing.T) {
	handler := invalidClientProfileHandler()

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	meta := &logging.RequestMeta{}
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(rec.Body.String(), "client profile config invalid") {
		t.Fatalf("body = %q, want message containing 'client profile config invalid'", rec.Body.String())
	}
	if meta.Decision != "deny" || meta.Reason != "client profile config invalid" {
		t.Fatalf("meta = %+v, want deny/client profile config invalid", meta)
	}
}

// ---- buildServeHandler: invalid profile config → invalidClientProfileHandler

func TestBuildServeHandler_InvalidClientProfileConfig(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "missing-profile")
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	// A profile that allows exec endpoints without AllowedCommands set
	// triggers validateBodyBlindWriteRulesForPolicy to return an error.
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "bad-profile",
			Rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/**"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
			// No RequestBody.Exec.AllowedCommands → blind-write validation fails.
		},
	}

	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, nil, newServeTestDeps())

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "client profile config invalid") {
		t.Fatalf("body = %q, want client profile config invalid", rec.Body.String())
	}
}

// ---- compileClientProfiles: validation error ----

func TestCompileClientProfiles_ValidationError(t *testing.T) {
	cfg := config.Defaults()
	// Profile allows POST /containers/** (covers exec/start) without
	// AllowedCommands, so validateBodyBlindWriteRulesForPolicy returns an
	// error naming the profile.
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "bad-profile",
			Rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/**"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
		},
	}

	_, err := compileClientProfiles(&cfg)
	if err == nil {
		t.Fatal("expected compileClientProfiles() to fail for blind-write validation")
	}
	if !strings.Contains(err.Error(), "bad-profile") {
		t.Fatalf("expected profile name in error, got: %v", err)
	}
}

// ---- buildServeClientProfiles: propagates error ----

func TestBuildServeClientProfiles_Error(t *testing.T) {
	cfg := config.Defaults()
	// Same trigger: exec allowed without AllowedCommands.
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "bad",
			Rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/**"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
		},
	}

	_, err := buildServeClientProfiles(&cfg)
	if err == nil {
		t.Fatal("expected buildServeClientProfiles() to fail")
	}
}

// ---- clientCertificateProfiles: non-empty input ----

func TestClientCertificateProfiles_NonEmpty(t *testing.T) {
	input := []config.ClientCertificateProfileAssignmentConfig{
		{
			Profile:     "cert-profile",
			CommonNames: []string{"client-1"},
			DNSNames:    []string{"client.internal"},
			IPAddresses: []string{"10.0.0.1"},
			URISANs:     []string{"urn:example:client"},
			SPIFFEIDs:   []string{"spiffe://example.com/client"},
		},
	}

	result := clientCertificateProfiles(input)
	if len(result) != 1 {
		t.Fatalf("got %d assignments, want 1", len(result))
	}
	a := result[0]
	if a.Profile != "cert-profile" {
		t.Fatalf("Profile = %q, want cert-profile", a.Profile)
	}
	if len(a.CommonNames) != 1 || a.CommonNames[0] != "client-1" {
		t.Fatalf("CommonNames = %v, want [client-1]", a.CommonNames)
	}
	if len(a.IPAddresses) != 1 || a.IPAddresses[0] != "10.0.0.1" {
		t.Fatalf("IPAddresses = %v, want [10.0.0.1]", a.IPAddresses)
	}
}

// ---- clientUnixPeerProfiles: non-empty input ----

func TestClientUnixPeerProfiles_NonEmpty(t *testing.T) {
	input := []config.ClientUnixPeerProfileAssignmentConfig{
		{
			Profile: "peer-profile",
			UIDs:    []uint32{1001, 1002},
			GIDs:    []uint32{2001},
			PIDs:    []int32{3001},
		},
	}

	result := clientUnixPeerProfiles(input)
	if len(result) != 1 {
		t.Fatalf("got %d assignments, want 1", len(result))
	}
	a := result[0]
	if a.Profile != "peer-profile" {
		t.Fatalf("Profile = %q, want peer-profile", a.Profile)
	}
	if len(a.UIDs) != 2 || a.UIDs[0] != 1001 || a.UIDs[1] != 1002 {
		t.Fatalf("UIDs = %v, want [1001 1002]", a.UIDs)
	}
}

// ---- printRules: deny action and empty method (wildcard) ----

func TestPrintRules_DenyAndWildcardMethod(t *testing.T) {
	cfg := &config.Config{
		Rules: []config.RuleConfig{
			// Empty method must render as "*"
			{Match: config.MatchConfig{Method: "", Path: "/**"}, Action: "deny"},
			{Match: config.MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"},
		},
	}

	var out bytes.Buffer
	p := ui.New(&out)
	printRules(&out, p, cfg, 2)

	output := out.String()
	if !strings.Contains(output, "deny") {
		t.Fatalf("expected 'deny' in output, got: %s", output)
	}
	if !strings.Contains(output, "*") {
		t.Fatalf("expected wildcard method '*' in output, got: %s", output)
	}
}

// ---- printClientProfiles: non-default profile and deny rule ----

func TestPrintClientProfiles_NonDefaultAndDenyRule(t *testing.T) {
	cfg := &config.Config{
		Clients: config.ClientsConfig{
			DefaultProfile: "readonly",
			Profiles: []config.ClientProfileConfig{
				{
					Name: "readonly",
					Rules: []config.RuleConfig{
						{Match: config.MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"},
					},
				},
				{
					Name: "admin",
					Rules: []config.RuleConfig{
						// Empty method + deny to exercise both new branches.
						{Match: config.MatchConfig{Method: "", Path: "/**"}, Action: "deny"},
					},
				},
			},
		},
	}

	var out bytes.Buffer
	p := ui.New(&out)
	printClientProfiles(&out, p, cfg)

	output := out.String()
	if !strings.Contains(output, "readonly (default)") {
		t.Fatalf("expected '(default)' label, got: %s", output)
	}
	if !strings.Contains(output, "admin") {
		t.Fatalf("expected admin profile, got: %s", output)
	}
	if !strings.Contains(output, "deny") {
		t.Fatalf("expected deny action in output, got: %s", output)
	}
	if !strings.Contains(output, "*") {
		t.Fatalf("expected wildcard method in output, got: %s", output)
	}
}

// ---- runVersion: json output and unknown format ----

func TestRunVersion_JSONOutput(t *testing.T) {
	var out bytes.Buffer
	cmd := newVersionCmdForTest()
	cmd.SetOut(&out)

	oldVersionOutput := versionOutput
	versionOutput = "json"
	t.Cleanup(func() { versionOutput = oldVersionOutput })

	if err := runVersion(cmd, nil); err != nil {
		t.Fatalf("runVersion(json) error = %v", err)
	}

	output := out.String()
	if !strings.Contains(output, `"version"`) {
		t.Fatalf("expected version field in JSON output, got: %s", output)
	}
	if !strings.Contains(output, `"commit"`) {
		t.Fatalf("expected commit field in JSON output, got: %s", output)
	}
	if !strings.Contains(output, `"built"`) {
		t.Fatalf("expected built field in JSON output, got: %s", output)
	}
}

func TestRunVersion_UnknownFormat(t *testing.T) {
	cmd := newVersionCmdForTest()
	cmd.SetOut(io.Discard)

	oldVersionOutput := versionOutput
	versionOutput = "yaml"
	t.Cleanup(func() { versionOutput = oldVersionOutput })

	err := runVersion(cmd, nil)
	if err == nil {
		t.Fatal("expected runVersion(yaml) to fail for unknown format")
	}
	if !strings.Contains(err.Error(), "unknown output format") {
		t.Fatalf("error = %v, want 'unknown output format'", err)
	}
}

// ---- shortCommit: all branches ----

func TestShortCommit_AllBranches(t *testing.T) {
	// Exactly 7 chars: no truncation.
	if got := shortCommit("abcdefg"); got != "abcdefg" {
		t.Fatalf("shortCommit(7) = %q, want %q", got, "abcdefg")
	}
	// Longer than 7: truncated.
	if got := shortCommit("abcdefgh"); got != "abcdefg" {
		t.Fatalf("shortCommit(8) = %q, want %q", got, "abcdefg")
	}
	// Shorter than 7: returned as-is.
	if got := shortCommit("abc"); got != "abc" {
		t.Fatalf("shortCommit(3) = %q, want %q", got, "abc")
	}
	// Empty: returned as-is.
	if got := shortCommit(""); got != "" {
		t.Fatalf("shortCommit(empty) = %q, want %q", got, "")
	}
}

// ---- runMatch: invalid output format and compat mode output ----

func TestRunMatch_InvalidOutputFormat(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	if err := os.WriteFile(cfgPath, []byte("upstream:\n  socket: /var/run/docker.sock\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, _, err := executeRootCommand(t,
		"-c", cfgPath,
		"match",
		"--method", "GET",
		"--path", "/_ping",
		"-o", "yaml",
	)
	if err == nil {
		t.Fatal("expected match to fail for unsupported output format")
	}
	if !strings.Contains(err.Error(), "unsupported output format") {
		t.Fatalf("error = %v, want 'unsupported output format'", err)
	}
}

func TestRunMatch_CompatModeOutput(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	if err := os.WriteFile(cfgPath, []byte("upstream:\n  socket: /var/run/docker.sock\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Setenv("CONTAINERS", "1")
	t.Setenv("SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION", "true")

	stdout, _, err := executeRootCommand(t,
		"-c", cfgPath,
		"match",
		"--method", "GET",
		"--path", "/containers/json",
	)
	if err != nil {
		t.Fatalf("runMatch() error = %v", err)
	}
	if !strings.Contains(stdout, "tecnativa compatibility") {
		t.Fatalf("expected compat mode in output, got: %s", stdout)
	}
}

// ---- writeMatchText: compat mode line, deny decision, matched deny rule ----

func TestWriteMatchText_CompatAndDenyRule(t *testing.T) {
	var buf bytes.Buffer
	// writeMatchText prints result.Reason (not MatchedRule.Reason), so place
	// the reason at the top-level field.
	writeMatchText(&buf, matchResult{
		Config:         "test.yaml",
		Method:         "POST",
		Path:           "/containers/create",
		NormalizedPath: "/containers/create",
		Decision:       string(filter.ActionDeny),
		Reason:         "deny all",
		CompatMode:     true,
		MatchedRule: &matchedRuleInfo{
			Index:  2,
			Method: "*",
			Path:   "/**",
			Action: string(filter.ActionDeny),
		},
	})

	output := buf.String()
	if !strings.Contains(output, "tecnativa compatibility") {
		t.Fatalf("expected compat mode line, got: %s", output)
	}
	if !strings.Contains(output, "#2") {
		t.Fatalf("expected matched rule index in output, got: %s", output)
	}
	if !strings.Contains(output, "deny all") {
		t.Fatalf("expected deny reason in output, got: %s", output)
	}
}

// ---- runMatch: method/path empty and config-load error ----
//
// These guards inside runMatch are unreachable via cobra (required flags),
// but the package-level vars are accessible in-package so we call runMatch
// directly with controlled state.

func TestRunMatch_EmptyMethod(t *testing.T) {
	oldMethod, oldPath, oldOutput := matchMethod, matchPath, matchOutput
	t.Cleanup(func() { matchMethod, matchPath, matchOutput = oldMethod, oldPath, oldOutput })

	matchMethod = "   " // trimmed → ""
	matchPath = "/_ping"
	matchOutput = "text"

	cmd := &cobra.Command{Use: "match"}
	cmd.SetOut(io.Discard)
	err := runMatch(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "method is required") {
		t.Fatalf("expected 'method is required' error, got: %v", err)
	}
}

func TestRunMatch_EmptyPath(t *testing.T) {
	oldMethod, oldPath, oldOutput := matchMethod, matchPath, matchOutput
	t.Cleanup(func() { matchMethod, matchPath, matchOutput = oldMethod, oldPath, oldOutput })

	matchMethod = "GET"
	matchPath = "   " // trimmed → ""
	matchOutput = "text"

	cmd := &cobra.Command{Use: "match"}
	cmd.SetOut(io.Discard)
	err := runMatch(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "path is required") {
		t.Fatalf("expected 'path is required' error, got: %v", err)
	}
}

func TestRunMatch_ConfigLoadError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")
	// Write invalid YAML that will cause config.Load to return an error.
	if err := os.WriteFile(cfgPath, []byte("upstream: [invalid: yaml\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, _, err := executeRootCommand(t,
		"-c", cfgPath,
		"match",
		"--method", "GET",
		"--path", "/_ping",
	)
	if err == nil {
		t.Fatal("expected runMatch to fail for invalid YAML config")
	}
	if !strings.Contains(err.Error(), "config load") {
		t.Fatalf("error = %v, want 'config load'", err)
	}
}

func TestRunMatch_MissingConfigWithoutChangedFlag(t *testing.T) {
	oldCfgFile := cfgFile
	oldMethod, oldPath, oldOutput := matchMethod, matchPath, matchOutput
	t.Cleanup(func() {
		cfgFile = oldCfgFile
		matchMethod, matchPath, matchOutput = oldMethod, oldPath, oldOutput
	})

	cfgFile = filepath.Join(t.TempDir(), "missing.yaml")
	matchMethod = "GET"
	matchPath = "/_ping"
	matchOutput = "text"

	cmd := &cobra.Command{Use: "match"}
	cmd.SetOut(io.Discard)

	err := runMatch(cmd, nil)
	if err == nil {
		t.Fatal("expected runMatch() to fail for missing config")
	}
	if !strings.Contains(err.Error(), "config file:") {
		t.Fatalf("error = %v, want config file stat error", err)
	}
}

func TestRunMatch_ValidateAndCompileError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	// A config that passes config.Validate but fails validateBodyBlindWriteRules
	// because it allows exec endpoints without inspection and without the insecure override.
	yaml := "upstream:\n  socket: /var/run/docker.sock\nrules:\n  - match: {method: POST, path: \"/containers/**\"}\n    action: allow\n  - match: {method: \"*\", path: \"/**\"}\n    action: deny\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, _, err := executeRootCommand(t,
		"-c", cfgPath,
		"match",
		"--method", "GET",
		"--path", "/_ping",
	)
	if err == nil {
		t.Fatal("expected runMatch to fail for config validation error")
	}
	if !strings.Contains(err.Error(), "config validation") {
		t.Fatalf("error = %v, want 'config validation'", err)
	}
}

// ---- compileClientProfiles: compileConfiguredRules error via compileFilterRule swap ----

func TestCompileClientProfiles_CompileRuleError(t *testing.T) {
	// Temporarily replace compileFilterRule to force a compile error.
	oldFn := compileFilterRule
	t.Cleanup(func() { compileFilterRule = oldFn })
	compileFilterRule = func(r filter.Rule) (*filter.CompiledRule, error) {
		return nil, fmt.Errorf("injected compile error")
	}

	cfg := config.Defaults()
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name:  "any-profile",
			Rules: []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}},
		},
	}

	_, err := compileClientProfiles(&cfg)
	if err == nil {
		t.Fatal("expected compileClientProfiles to fail when compileFilterRule errors")
	}
	if !strings.Contains(err.Error(), "any-profile") {
		t.Fatalf("expected profile name in error, got: %v", err)
	}
}

// ---- helpers ----------------------------------------------------------------

func newVersionCmdForTest() *cobra.Command {
	cmd := cobra.Command{Use: "version"}
	c := &cmd
	c.Flags().StringVarP(&versionOutput, "output", "o", "text", "")
	return c
}
