package cmd

// buildServeHandler and buildServeHandlerLayers are thin convenience wrappers
// used exclusively by tests. They live here (a _test.go file) so they are
// compiled only during `go test` and never appear in production binaries.
// Production code always calls buildServeHandlerChainWithRuntime or
// buildServeHandlerLayersWithRuntime directly.

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
)

// indexAfter returns the index immediately after the first occurrence of sub
// in s, or -1 if sub is not present. Used by tests that scan Prometheus text
// output for specific metric lines.
func indexAfter(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i + len(sub)
		}
	}
	return -1
}

func buildServeHandler(t *testing.T, cfg *config.Config, logger *slog.Logger, auditLogger *logging.AuditLogger, rules []*filter.CompiledRule, deps *serveDeps) http.Handler {
	t.Helper()
	handler, teardown := buildServeHandlerWithRuntime(cfg, logger, auditLogger, rules, deps, newServeRuntime(cfg, logger, deps))
	t.Cleanup(teardown)
	return handler
}

func buildServeHandlerLayers(cfg *config.Config, logger *slog.Logger, auditLogger *logging.AuditLogger, rules []*filter.CompiledRule, deps *serveDeps, clientProfiles map[string]filter.Policy) []serveHandlerLayer {
	layers, _ := buildServeHandlerLayersWithRuntime(cfg, logger, auditLogger, rules, deps, clientProfiles, newServeRuntime(cfg, logger, deps), nil)
	return layers
}
