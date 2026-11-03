package cmd

import (
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// Serial on purpose: building the chain sets a process-wide limit. Startup and
// hot reload both build through the same function, so a changed value applies
// on reload.
func TestBuildServeHandlerChainAppliesMaxBufferedBody(t *testing.T) {
	t.Cleanup(func() { filter.SetResponseBodyLimit(0) })

	build := func(value string) {
		cfg := config.Defaults()
		cfg.Upstream.Socket = shortSocketPath(t, "mbb")
		cfg.Health.Enabled = false
		cfg.Log.AccessLog = false
		cfg.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}
		cfg.Response.MaxBufferedBody = value
		rules, err := compileRuleConfigsForTest(cfg.Rules)
		if err != nil {
			t.Fatalf("compile rules: %v", err)
		}
		buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
	}

	build("")
	if got := filter.ResponseBodyLimit(); got != filter.MaxResponseBodyBytes {
		t.Fatalf("unset: limit = %d, want the 8MiB default", got)
	}
	build("64MiB")
	if got := filter.ResponseBodyLimit(); got != 64<<20 {
		t.Fatalf("64MiB: limit = %d", got)
	}
	build("16MiB")
	if got := filter.ResponseBodyLimit(); got != 16<<20 {
		t.Fatalf("reload to 16MiB: limit = %d", got)
	}
}
