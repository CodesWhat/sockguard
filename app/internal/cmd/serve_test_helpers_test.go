package cmd

// buildServeHandler and buildServeHandlerLayers are thin convenience wrappers
// used exclusively by tests. They live here (a _test.go file) so they are
// compiled only during `go test` and never appear in production binaries.
// Production code always calls buildServeHandlerChainWithRuntime or
// buildServeHandlerLayersWithRuntime directly.

import (
	"log/slog"
	"net/http"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
)

func buildServeHandler(cfg *config.Config, logger *slog.Logger, auditLogger *logging.AuditLogger, rules []*filter.CompiledRule, deps *serveDeps) http.Handler {
	return buildServeHandlerWithRuntime(cfg, logger, auditLogger, rules, deps, newServeRuntime(cfg, logger, deps))
}

func buildServeHandlerLayers(cfg *config.Config, logger *slog.Logger, auditLogger *logging.AuditLogger, rules []*filter.CompiledRule, deps *serveDeps, clientProfiles map[string]filter.Policy) []serveHandlerLayer {
	layers, _ := buildServeHandlerLayersWithRuntime(cfg, logger, auditLogger, rules, deps, clientProfiles, newServeRuntime(cfg, logger, deps), nil)
	return layers
}
