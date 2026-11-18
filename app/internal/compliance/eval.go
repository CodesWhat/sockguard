package compliance

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// scope is one effective request-body policy.
//
// Runtime semantics relied on here: a client profile does not inherit or merge
// with the global request_body. cmd.compileClientProfiles builds each profile's
// filter.Policy from profile.RequestBody.ToFilterOptions() alone, and
// filter.compileRuntimePolicy(profile.Rules, profile.PolicyConfig) replaces both
// the global rules and the global body policy wholesale when a request resolves
// to that profile (filter.resolveActivePolicy). A profile that omits
// request_body therefore runs with zero-valued body config, not the global one.
// So the global config and every profile are each an independent scope.
//
// A profile in warn or audit rollout mode lets denied requests through
// (config.RolloutWarn / RolloutAudit), so its body gates are not enforcing.
type scope struct {
	bodyPath string
	rulePath string
	body     config.RequestBodyConfig
	rules    []config.RuleConfig
	modePath string // empty for the global scope
	enforced bool
	modeEnum string
}

func scopesOf(cfg *config.Config) []scope {
	out := make([]scope, 0, 1+len(cfg.Clients.Profiles))
	out = append(out, scope{
		bodyPath: "request_body",
		rulePath: "rules",
		body:     cfg.RequestBody,
		rules:    cfg.Rules,
		enforced: true,
	})
	for i, p := range cfg.Clients.Profiles {
		mode, ok := config.ParseRolloutMode(p.Mode)
		enum := "other"
		if ok {
			enum = mode.String()
		}
		out = append(out, scope{
			bodyPath: fmt.Sprintf("clients.profiles[%d].request_body", i),
			rulePath: fmt.Sprintf("clients.profiles[%d].rules", i),
			body:     p.RequestBody,
			rules:    p.Rules,
			modePath: fmt.Sprintf("clients.profiles[%d].mode", i),
			enforced: ok && mode == config.RolloutEnforce,
			modeEnum: enum,
		})
	}
	return out
}

func boolStr(b bool) string { return fmt.Sprintf("%t", b) }

func entries(n int) string { return fmt.Sprintf("%d entries", n) }

// check is one configuration fact a control needs. Informational checks are
// reported as evidence but never change the status.
type check struct {
	path          string // relative to the scope's request_body path
	expected      string
	informational bool
	eval          func(rb *config.RequestBodyConfig) (ok bool, observed string)
}

func boolCheck(path string, want bool, get func(*config.RequestBodyConfig) bool) check {
	return check{
		path:     path,
		expected: boolStr(want),
		eval: func(rb *config.RequestBodyConfig) (bool, string) {
			v := get(rb)
			return v == want, boolStr(v)
		},
	}
}

func emptyCheck(path string, get func(*config.RequestBodyConfig) int) check {
	return check{
		path:     path,
		expected: entries(0),
		eval: func(rb *config.RequestBodyConfig) (bool, string) {
			n := get(rb)
			return n == 0, entries(n)
		},
	}
}

func trustModeEnum(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "off", "":
		return "off"
	case "warn":
		return "warn"
	case "enforce":
		return "enforce"
	}
	return "other"
}

func trustCheck(path string, informational bool, get func(*config.RequestBodyConfig) string) check {
	return check{
		path:          path,
		expected:      "enforce",
		informational: informational,
		eval: func(rb *config.RequestBodyConfig) (bool, string) {
			m := trustModeEnum(get(rb))
			return m == "enforce", m
		},
	}
}

const blindWritesNote = "insecure_allow_body_blind_writes is true, so request bodies on body-sensitive endpoints are not inspected and this control is not enforced."

// bodyControl builds an evaluator over request_body scopes. A control is
// configured when every scope satisfies all non-informational checks,
// partial when some do, not_configured when none do.
func bodyControl(extraNotes []string, checks ...check) func(*config.Config) ControlResult {
	return func(cfg *config.Config) ControlResult {
		res := ControlResult{Evidence: []Evidence{}, Notes: append([]string{}, extraNotes...)}
		if cfg.InsecureAllowBodyBlindWrites {
			res.Status = StatusNotConfigured
			res.Evidence = append(res.Evidence, Evidence{Path: "insecure_allow_body_blind_writes", Expected: "false", Observed: "true"})
			res.Notes = append(res.Notes, blindWritesNote)
			return res
		}
		scopes := scopesOf(cfg)
		satisfied, relaxedMode := 0, false
		for _, s := range scopes {
			ok := true
			if !s.enforced {
				ok = false
				relaxedMode = true
				res.Evidence = append(res.Evidence, Evidence{Path: s.modePath, Expected: "enforce", Observed: s.modeEnum})
			}
			body := s.body
			for _, c := range checks {
				pass, observed := c.eval(&body)
				res.Evidence = append(res.Evidence, Evidence{Path: s.bodyPath + "." + c.path, Expected: c.expected, Observed: observed})
				if !c.informational && !pass {
					ok = false
				}
			}
			if ok {
				satisfied++
			}
		}
		res.Status = tally(satisfied, len(scopes))
		if res.Status == StatusPartial {
			res.Notes = append(res.Notes, fmt.Sprintf("Satisfied in %d of %d request-body scopes (global plus each client profile).", satisfied, len(scopes)))
		}
		if relaxedMode {
			res.Notes = append(res.Notes, "A client profile in warn or audit mode logs denials but lets the request through, so it does not satisfy the control.")
		}
		return res
	}
}

func tally(satisfied, total int) Status {
	switch {
	case total > 0 && satisfied == total:
		return StatusConfigured
	case satisfied > 0:
		return StatusPartial
	default:
		return StatusNotConfigured
	}
}

func alwaysOn(note string) func(*config.Config) ControlResult {
	return func(*config.Config) ControlResult {
		return ControlResult{Status: StatusAlwaysOn, Evidence: []Evidence{}, Notes: []string{note}}
	}
}

// tlsListenersControl implements 2.6. A listener is a TCP listener when it
// has no unix socket and an address (serve binds the socket when both are set).
func tlsListenersControl(cfg *config.Config) ControlResult {
	res := ControlResult{Evidence: []Evidence{}, Notes: []string{}}
	listeners := cfg.EffectiveListeners()
	legacy := len(cfg.Listeners) == 0
	tcp, withCA := 0, 0
	for i, l := range listeners {
		if l.Socket != "" || l.Address == "" {
			continue
		}
		tcp++
		path := fmt.Sprintf("listeners[%d].tls.client_ca_file", i)
		if legacy {
			path = "listen.tls.client_ca_file"
		}
		observed := "unset"
		if l.TLS.ClientCAFile != "" {
			withCA++
			observed = "set"
		}
		res.Evidence = append(res.Evidence, Evidence{Path: path, Expected: "set", Observed: observed})
	}
	if tcp == 0 {
		res.Status = StatusConfigured
		res.Notes = append(res.Notes, "no TCP listeners")
		return res
	}
	res.Status = tally(withCA, tcp)
	if res.Status == StatusPartial {
		res.Notes = append(res.Notes, fmt.Sprintf("%d of %d TCP listeners require client certificates.", withCA, tcp))
	}
	return res
}

type probe struct {
	prefix string
	paths  []string
}

var swarmProbes = []probe{
	{"/swarm/**", []string{"/swarm", "/swarm/init"}},
	{"/services/**", []string{"/services", "/services/probe"}},
	{"/nodes/**", []string{"/nodes", "/nodes/probe"}},
	{"/configs/**", []string{"/configs", "/configs/probe"}},
	{"/secrets/**", []string{"/secrets", "/secrets/probe"}},
}

// swarmControl implements 7.x: GET and POST probes on each Swarm prefix are run
// through the compiled rule matcher (filter.Evaluate, as `sockguard match`
// does) for the global ruleset and every client profile's own ruleset.
func swarmControl(cfg *config.Config) ControlResult {
	res := ControlResult{Evidence: []Evidence{}, Notes: []string{}}
	scopes := scopesOf(cfg)
	satisfied, relaxedMode := 0, false
	for _, s := range scopes {
		compiled, err := compileRules(s.rules)
		if err != nil {
			res.Evidence = append(res.Evidence, Evidence{Path: s.rulePath, Expected: "rules compile", Observed: "compile error"})
			continue
		}
		ok := true
		if !s.enforced {
			ok = false
			relaxedMode = true
			res.Evidence = append(res.Evidence, Evidence{Path: s.modePath, Expected: "enforce", Observed: s.modeEnum})
		}
		for _, p := range swarmProbes {
			total, allowed := 0, 0
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				for _, path := range p.paths {
					total++
					req := &http.Request{Method: method, URL: &url.URL{Path: path}}
					if action, _, _ := filter.Evaluate(compiled, req); action == filter.ActionAllow {
						allowed++
					}
				}
			}
			if allowed > 0 {
				ok = false
			}
			res.Evidence = append(res.Evidence, Evidence{
				Path:     s.rulePath,
				Expected: fmt.Sprintf("0 of %d GET/POST probes allowed for %s", total, p.prefix),
				Observed: fmt.Sprintf("%d of %d probes allowed", allowed, total),
			})
		}
		if ok {
			satisfied++
		}
	}
	res.Status = tally(satisfied, len(scopes))
	if res.Status == StatusPartial {
		res.Notes = append(res.Notes, fmt.Sprintf("Swarm surface denied in %d of %d rule scopes (global plus each client profile).", satisfied, len(scopes)))
	}
	if relaxedMode {
		res.Notes = append(res.Notes, "A client profile in warn or audit mode logs denials but lets the request through, so it does not satisfy the control.")
	}
	res.Notes = append(res.Notes, "Based on representative GET and POST requests against the configured rules, not an exhaustive path walk.")
	return res
}

func compileRules(rules []config.RuleConfig) ([]*filter.CompiledRule, error) {
	out := make([]*filter.CompiledRule, 0, len(rules))
	for i, r := range rules {
		var methods []string
		for _, m := range strings.Split(r.Match.Method, ",") {
			if m = strings.TrimSpace(m); m != "" {
				methods = append(methods, m)
			}
		}
		cr, err := filter.CompileRule(filter.Rule{
			Methods: methods,
			Pattern: r.Match.Path,
			Action:  filter.Action(r.Action),
			Reason:  r.Reason,
			Index:   i,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, cr)
	}
	return out, nil
}
