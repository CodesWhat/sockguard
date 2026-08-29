package config

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/filter"
)

func TestCompatAllowDeleteWiresContainerRemoveQueryControls(t *testing.T) {
	clearCompatEnvironment(t)

	queries := []string{
		"force=1",
		"v=1",
		"link=1",
	}

	t.Run("ALLOW_DELETE preserves Tecnativa behavior", func(t *testing.T) {
		t.Setenv("ALLOW_DELETE", "1")
		cfg := Defaults()
		if !ApplyCompat(&cfg, discardLogger) {
			t.Fatal("ApplyCompat() = false, want true")
		}

		handler := compatContainerRemoveHandler(t, cfg)
		for _, query := range queries {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, "/containers/abc?"+query, nil)

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusNoContent {
				t.Errorf("DELETE query %q status = %d, want %d; body: %s", query, rec.Code, http.StatusNoContent, rec.Body.String())
			}
		}
	})

	t.Run("user-authored rule keeps native defaults", func(t *testing.T) {
		cfg := Defaults()
		cfg.Rules = []RuleConfig{
			{Match: MatchConfig{Method: http.MethodDelete, Path: "/containers/*"}, Action: "allow"},
			{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}

		handler := compatContainerRemoveHandler(t, cfg)
		for _, query := range queries {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, "/containers/abc?"+query, nil)

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("DELETE query %q status = %d, want %d; body: %s", query, rec.Code, http.StatusForbidden, rec.Body.String())
			}
		}
	})
}

func compatContainerRemoveHandler(t *testing.T, cfg Config) http.Handler {
	t.Helper()

	compiled := make([]*filter.CompiledRule, 0, len(cfg.Rules))
	for i, rule := range cfg.Rules {
		methods := strings.Split(rule.Match.Method, ",")
		for j := range methods {
			methods[j] = strings.TrimSpace(methods[j])
		}
		compiledRule, err := filter.CompileRule(filter.Rule{
			Methods: methods,
			Pattern: rule.Match.Path,
			Action:  filter.Action(rule.Action),
			Reason:  rule.Reason,
			Index:   i,
		})
		if err != nil {
			t.Fatalf("compile rule %d: %v", i+1, err)
		}
		compiled = append(compiled, compiledRule)
	}

	return filter.MiddlewareWithOptions(compiled, discardLogger, filter.Options{
		PolicyConfig: cfg.RequestBody.ToFilterOptions(),
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
}

func clearCompatEnvironment(t *testing.T) {
	t.Helper()

	type envValue struct {
		value string
		set   bool
	}
	original := make(map[string]envValue, len(compatVars))
	for _, key := range compatVars {
		value, set := os.LookupEnv(key)
		original[key] = envValue{value: value, set: set}
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
	t.Cleanup(func() {
		for key, entry := range original {
			if entry.set {
				if err := os.Setenv(key, entry.value); err != nil {
					t.Errorf("restore %s: %v", key, err)
				}
				continue
			}
			if err := os.Unsetenv(key); err != nil {
				t.Errorf("restore unset %s: %v", key, err)
			}
		}
	})
}
