package cmd

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

//go:embed known_api_routes.json
var knownAPIRoutesJSON []byte

type knownAPIRoute struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	machine catalogRuleMachine
}

var knownRouteParameter = regexp.MustCompile(`\{[^{}]+\}`)

var loadKnownAPIRoutes = sync.OnceValues(func() ([]knownAPIRoute, error) {
	var catalog struct {
		Routes []knownAPIRoute `json:"routes"`
	}
	if err := json.Unmarshal(knownAPIRoutesJSON, &catalog); err != nil {
		return nil, err
	}
	for i := range catalog.Routes {
		route := &catalog.Routes[i]
		var expression strings.Builder
		position := 0
		for _, bounds := range knownRouteParameter.FindAllStringIndex(route.Path, -1) {
			expression.WriteString(regexp.QuoteMeta(route.Path[position:bounds[0]]))
			parameter := route.Path[bounds[0]:bounds[1]]
			if strings.Contains(parameter, ":.*") {
				expression.WriteString(`(?s:.*)`)
			} else {
				expression.WriteString(`[^/]+`)
			}
			position = bounds[1]
		}
		expression.WriteString(regexp.QuoteMeta(route.Path[position:]))
		program, err := compileReachabilityProgram(expression.String())
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", route.Path, err)
		}
		route.machine = catalogRuleMachine{program: program}
	}
	return catalog.Routes, nil
})

func ruleMatchesKnownAPIRoute(rule config.RuleConfig, routes []knownAPIRoute) bool {
	target, err := compileCatalogRuleMachine(rule.Match.Path, "allow")
	if err != nil || len(target.program.Inst) > maxCatalogReachabilityInstructions {
		return true
	}
	budget := catalogReachabilityBudget{}
	for _, route := range routes {
		if !configuredRuleMatchesMethod(rule.Match.Method, route.Method) {
			continue
		}
		_, result := catalogAllowWitness([]catalogRuleMachine{route.machine, target}, &budget)
		// Diagnostics must not label an unproved intersection as impossible.
		if result != catalogUnreachable {
			return true
		}
	}
	return false
}

func warnIfRulesMatchNoKnownRoute(cfg *config.Config, logger *slog.Logger) {
	routes, err := loadKnownAPIRoutes()
	if err != nil {
		logger.Warn("known API route diagnostics unavailable", "error", err)
		return
	}
	warn := func(prefix string, rules []config.RuleConfig) {
		for i, rule := range rules {
			if !ruleMatchesKnownAPIRoute(rule, routes) {
				logger.Warn("rule matches no known Docker or Podman API route", "rule", fmt.Sprintf("%s[%d]", prefix, i), "method", rule.Match.Method, "path", rule.Match.Path, "action", rule.Action)
			}
		}
	}
	warn("rules", cfg.Rules)
	for i, profile := range cfg.Clients.Profiles {
		warn(fmt.Sprintf("clients.profiles[%d].rules", i), profile.Rules)
	}
}
