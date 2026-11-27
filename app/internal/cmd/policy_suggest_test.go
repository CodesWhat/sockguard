package cmd

import (
	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"os"
	"strings"
	"testing"
)

func TestPolicySuggestGolden(t *testing.T) {
	stdout, stderr, err := executeRootCommand(t, "policy", "suggest", "--from", "testdata/suggest_access.jsonl")
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
	}
	goldenPath := "testdata/suggest_access.golden.yaml"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(goldenPath, []byte(stdout), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != string(want) {
		t.Fatalf("output differs from golden:\n%s", stdout)
	}
	for _, leak := range []string{"hunter2", "10.0.0.9", "r1", "secret", "t=5"} {
		if strings.Contains(stdout, leak) {
			t.Errorf("output leaks %q", leak)
		}
	}
	if !strings.Contains(stderr, "skipped") {
		t.Errorf("stderr summary missing: %q", stderr)
	}
}

func TestPolicySuggestMissingFile(t *testing.T) {
	if _, _, err := executeRootCommand(t, "policy", "suggest", "--from", "testdata/nope.jsonl"); err == nil {
		t.Fatal("expected error for a missing file")
	}
}

func TestPolicySuggestFromStdin(t *testing.T) {
	rootCmd.SetIn(strings.NewReader(`{"msg":"request_would_deny","method":"GET","normalized_path":"/info","decision":"would_deny"}` + "\n"))
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	stdout, _, err := executeRootCommand(t, "policy", "suggest", "--from", "-")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, `path: "/info"`) {
		t.Fatalf("missing rule:\n%s", stdout)
	}
}

func TestPolicySuggestNoWouldDeny(t *testing.T) {
	rules, stats, err := collectSuggestions(strings.NewReader(`{"msg":"request","method":"GET","normalized_path":"/info"}` + "\n"))
	if err != nil || len(rules) != 0 || stats.WouldDeny != 0 {
		t.Fatalf("rules=%v stats=%+v err=%v", rules, stats, err)
	}
	out, err := renderSuggestions(rules, stats)
	if err != nil || !strings.Contains(out, "rules: []") {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestCollectSuggestionsBounds(t *testing.T) {
	long := `{"msg":"request_would_deny","method":"GET","normalized_path":"/` + strings.Repeat("a", suggestMaxLineBytes) + `"}`
	in := long + "\n" + `{"msg":"request_would_deny","method":"GET","normalized_path":"/info"}` // no trailing newline
	rules, stats, err := collectSuggestions(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].path != "/info" || stats.Skipped != 1 || stats.Lines != 2 {
		t.Fatalf("rules=%v stats=%+v", rules, stats)
	}
}

func TestCollectSuggestionsRuleCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < suggestMaxRules+5; i++ {
		b.WriteString(`{"msg":"request_would_deny","method":"GET","normalized_path":"/p`)
		b.WriteString(strings.Repeat("x", 1))
		b.WriteString(strings.Repeat("a", i%7))
		b.WriteString("/n")
		b.WriteString(strings.Repeat("b", i/7+1))
		b.WriteString("\"}\n")
	}
	rules, stats, err := collectSuggestions(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) > suggestMaxRules || stats.DroppedRules == 0 {
		t.Fatalf("len=%d stats=%+v", len(rules), stats)
	}
}

func TestGeneralizeSuggestPath(t *testing.T) {
	for in, want := range map[string]string{
		"/containers/json":                     "/containers/json",
		"/containers/abcdef012345/logs":        "/containers/*/logs",
		"/containers/web/json":                 "/containers/web/json",
		"/containers/ABCDEF012345/json":        "/containers/ABCDEF012345/json",
		"/containers/abcdef01234/json":         "/containers/abcdef01234/json",
		"/networks/" + strings.Repeat("a", 64): "/networks/*",
		"/images/library:tag/json":             "/images/library:tag/json",
		"/libpod/containers/abcdef012345/json": "/libpod/containers/*/json",
	} {
		got, ok := generalizeSuggestPath(in)
		if !ok || got != want {
			t.Errorf("%q = %q,%v want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "x", "/a/*", "/a/**", "/a/../b", "/a/./b", "/a b", "/a?x=1", "/a/", "/a%2fb", "/a\x00", "/[a]",
		"/0123456789ab", "/aaaaaaaaaaaa/bbbbbbbbbbbb", "/aaaaaaaaaaaa/containers", "/containers/aaaaaaaaaaaa/bbbbbbbbbbbb"} {
		if got, ok := generalizeSuggestPath(bad); ok {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

func TestSafeSuggestMethod(t *testing.T) {
	for m, want := range map[string]bool{"GET": true, "": false, "G T": false, "get1": false, strings.Repeat("A", 17): false} {
		if safeSuggestMethod(m) != want {
			t.Errorf("%q", m)
		}
	}
}

func TestPolicySuggestGoldenLoadsAsConfig(t *testing.T) {
	cfg, _, err := config.LoadWithData("testdata/suggest_access.golden.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(cfg.Rules))
	}
	if _, err := compileConfiguredRules(cfg.Rules); err != nil {
		t.Fatal(err)
	}
}

func TestPolicySuggestNeverEmitsWildcardRoot(t *testing.T) {
	in := strings.Join([]string{
		`{"msg":"request_would_deny","method":"DELETE","normalized_path":"/aaaaaaaaaaaa/bbbbbbbbbbbb","decision":"would_deny"}`,
		`{"msg":"request_would_deny","method":"GET","normalized_path":"/0123456789ab","decision":"would_deny"}`,
		`{"msg":"request_would_deny","method":"POST","normalized_path":"/aaaaaaaaaaaa/bbbbbbbbbbbb/cccccccccccc","decision":"would_deny"}`,
	}, "\n")
	rules, stats, err := collectSuggestions(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 || stats.WouldDeny != 3 || stats.Skipped != 3 {
		t.Fatalf("rules=%d wouldDeny=%d skipped=%d, want 0, 3, 3", len(rules), stats.WouldDeny, stats.Skipped)
	}
	out, err := renderSuggestions(rules, stats)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "rules: []\n") {
		t.Fatalf("output = %q, want rules: []", out)
	}
}

func TestPolicySuggestGoldenNeverHasWildcardRoot(t *testing.T) {
	golden, err := os.ReadFile("testdata/suggest_access.golden.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(golden), "\n") {
		if strings.Contains(line, "path:") && (strings.Contains(line, `path: "/*"`) || strings.Contains(line, "/*/*")) {
			t.Errorf("golden rule widens to a wildcard root: %s", line)
		}
	}
}
