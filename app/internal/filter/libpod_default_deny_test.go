package filter_test

import (
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
)

// TestDefaultConfigDeniesAllLibpodPaths is the #148 default-deny regression:
// config.Defaults() ships no allow rule for Podman's native libpod API (PR1
// adds only routing/normalization plumbing, no libpod rules or presets), so
// every representative libpod request — unversioned, Docker-style two-part
// versioned, and Podman's three-part semver versioned — must fall through to
// the default deny catch-all exactly like an unrecognized Docker path would.
func TestDefaultConfigDeniesAllLibpodPaths(t *testing.T) {
	cfg := config.Defaults()
	compiled := compileDefaultRules(t, cfg.Rules)

	tests := []struct {
		method string
		path   string
	}{
		// Unversioned.
		{"POST", "/libpod/containers/create"},
		{"POST", "/libpod/pods/create"},
		{"POST", "/libpod/containers/abc123/exec"},
		{"POST", "/libpod/exec/abc123/start"},
		{"POST", "/libpod/containers/abc123/attach"},
		{"POST", "/libpod/play/kube"},
		{"POST", "/libpod/networks/create"},
		{"POST", "/libpod/volumes/create"},
		{"POST", "/libpod/secrets/create"},
		{"GET", "/libpod/containers/json"},
		{"GET", "/libpod/images/json"},
		{"GET", "/libpod/info"},
		{"GET", "/libpod/events"},
		{"GET", "/libpod/_ping"},
		// Docker-style two-part versioned.
		{"POST", "/v1.45/libpod/containers/create"},
		{"GET", "/v1.45/libpod/containers/json"},
		// Podman's three-part semver versioned (#148: previously never
		// stripped, but denied anyway since no allow rule existed for
		// /libpod/ either way — this pins the intended behavior post-fix).
		{"POST", "/v5.0.0/libpod/containers/create"},
		{"POST", "/v4.9.3/libpod/pods/create"},
		{"GET", "/v5.0.0/libpod/containers/json"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			action, _, _ := filter.Evaluate(compiled, req)
			if action != filter.ActionDeny {
				t.Fatalf("Evaluate(%s %s) = %v, want deny", tt.method, tt.path, action)
			}
		})
	}
}

// compileDefaultRules compiles config.RuleConfig entries the same way
// internal/cmd's compileConfiguredRules does. Duplicated here (rather than
// imported) because that helper is unexported in a package this external
// test intentionally does not depend on — internal/filter must not gain a
// test-only dependency on internal/cmd.
func compileDefaultRules(t *testing.T, rules []config.RuleConfig) []*filter.CompiledRule {
	t.Helper()

	compiled := make([]*filter.CompiledRule, 0, len(rules))
	for i, rule := range rules {
		spec := filter.Rule{
			Methods: []string{rule.Match.Method},
			Pattern: rule.Match.Path,
			Action:  filter.Action(rule.Action),
			Reason:  rule.Reason,
			Index:   i,
		}
		cr, err := filter.CompileRule(spec)
		if err != nil {
			t.Fatalf("compile default rule %d (%+v): %v", i, rule, err)
		}
		compiled = append(compiled, cr)
	}
	return compiled
}
