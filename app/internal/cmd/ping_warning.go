package cmd

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// warnIfPingNotAllowed warns when a rule set (the default rules or a client
// profile) does not allow GET /_ping. The Docker CLI and SDKs ping before
// nearly every call: the CLI tries HEAD and falls back to GET, docker-py uses
// GET, so GET is the method that has to work and a HEAD rule is a bonus. A
// custom profile that forgets it breaks every Docker client, and the failure
// looks like an unreachable daemon rather than a policy denial. Like the replay warning, top-level rules
// are skipped when clients.default_profile makes them unreachable, and an
// empty rule set is left alone.
func warnIfPingNotAllowed(cfg *config.Config, logger *slog.Logger) {
	if cfg == nil || logger == nil {
		return
	}
	check := func(scope string, rules []config.RuleConfig) {
		if pingGetAllowed(rules) {
			return
		}
		logger.Warn("rule set does not allow GET /_ping: Docker clients ping the daemon before most calls, so clients using these rules will see the daemon as unreachable. Add allow rules for GET and HEAD /_ping",
			"scope", scope,
		)
	}
	if strings.TrimSpace(cfg.Clients.DefaultProfile) == "" {
		check("rules", cfg.Rules)
	}
	for _, profile := range cfg.Clients.Profiles {
		check("clients.profiles["+profile.Name+"].rules", profile.Rules)
	}
}

// pingGetAllowed reports whether rules allow GET /_ping. An empty rule set, or
// one that does not compile, counts as allowed so it is not reported here.
func pingGetAllowed(rules []config.RuleConfig) bool {
	if len(rules) == 0 {
		return true
	}
	compiled, err := compileConfiguredRules(rules)
	if err != nil {
		return true
	}
	return policyAllowsPath(http.MethodGet, "/_ping", compiled)
}
