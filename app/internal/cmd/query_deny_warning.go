package cmd

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// warnIfQueryDenyRules logs one warning per deny rule (top-level and per
// client profile) that carries a match.query constraint. The constraint
// compares values literally, while the daemon normalizes them (signal=kill
// and signal=9 both mean KILL, force=1 and force=yes both mean true), so a
// query deny only catches the spellings it lists. An allow rule with query is
// an allowlist and has no such gap.
func warnIfQueryDenyRules(cfg *config.Config, logger *slog.Logger) {
	if cfg == nil || logger == nil {
		return
	}
	warn := func(scope string, rules []config.RuleConfig) {
		for i, r := range rules {
			if !strings.EqualFold(strings.TrimSpace(r.Action), "deny") {
				continue
			}
			if len(r.Match.Query) > 0 {
				logger.Warn("deny rule with match.query only matches the literal spellings it lists: the daemon accepts other spellings of the same value (signal=kill, signal=9, force=1, force=yes), which would not match; express this as an allow rule with query instead",
					"rule", scope+"["+strconv.Itoa(i+1)+"]",
					"method", r.Match.Method,
					"path", r.Match.Path,
				)
			}
			if len(r.Match.Body) > 0 {
				logger.Warn("deny rule with match.body only matches the literal spellings it lists: a value the daemon would normalize, or a field the client sends in another shape, would not match; express this as an allow rule with body instead",
					"rule", scope+"["+strconv.Itoa(i+1)+"]",
					"method", r.Match.Method,
					"path", r.Match.Path,
				)
			}
		}
	}
	warn("rules", cfg.Rules)
	for _, profile := range cfg.Clients.Profiles {
		warn("clients.profiles["+profile.Name+"].rules", profile.Rules)
	}
}
