package cmd

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

// scpDualViewCatalogPath is the libpod image-SCP catalog template both the
// body-write and read-exfiltration catalogs carry.
const scpDualViewCatalogPath = "/libpod/images/scp/sockguard-test"

// scpDualViewAccepts runs a compiled catalog machine over a whole candidate
// string, which is what the reachability search's own walk does: every rune
// has to advance the automaton and the final state has to accept.
func scpDualViewAccepts(t *testing.T, template string, shape catalogIdentifierShape, candidate string) bool {
	t.Helper()
	machine, err := compileCatalogMachine(template, shape)
	if err != nil {
		t.Fatalf("compileCatalogMachine(%q, %d) error = %v, want nil", template, shape, err)
	}
	return catalogFuzzAccepts(machine.program, candidate)
}

// TestCatalogRoutePathIdentifierModelsTheRouteView pins the language the libpod
// image-SCP catalog entries are compiled against. Podman routes
// POST /libpod/images/scp/{name:.*} with a gorilla/mux variable that matches
// the empty string and swallows a trailing slash, so the route view of an SCP
// request is a run of clean segments that may be absent altogether or end on
// an empty segment. The action-suffix exclusions are spelled without that
// segment on purpose: .../{name}/push is the image-push route, while
// .../{name}/push/ misses it and falls through to the SCP catch-all
// (filter.isLibpodImageScpRoutePath).
func TestCatalogRoutePathIdentifierModelsTheRouteView(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		template  string
		shape     catalogIdentifierShape
		candidate string
		want      bool
	}{
		{"route view keeps a single-segment name", scpDualViewCatalogPath, catalogIdentifierRoutePath, "/libpod/images/scp/victim", true},
		{"route view keeps a slash-bearing name", scpDualViewCatalogPath, catalogIdentifierRoutePath, "/libpod/images/scp/victim/push", true},
		{"route view admits the trailing empty segment", scpDualViewCatalogPath, catalogIdentifierRoutePath, "/libpod/images/scp/victim/push/", true},
		{"route view admits the bare route", scpDualViewCatalogPath, catalogIdentifierRoutePath, "/libpod/images/scp/", true},
		{"route view refuses the prefix without its separator", scpDualViewCatalogPath, catalogIdentifierRoutePath, "/libpod/images/scp", false},
		{"route view still refuses a doubled slash", scpDualViewCatalogPath, catalogIdentifierRoutePath, "/libpod/images/scp/victim//", false},
		{"route view still refuses a dot segment", scpDualViewCatalogPath, catalogIdentifierRoutePath, "/libpod/images/scp/./push", false},
		{"decoded path shape refuses the trailing empty segment", scpDualViewCatalogPath, catalogIdentifierPath, "/libpod/images/scp/victim/", false},
		{"decoded path shape refuses the bare route", scpDualViewCatalogPath, catalogIdentifierPath, "/libpod/images/scp/", false},
		{"exclusion pins the bare action suffix", "/libpod/images/scp/sockguard-test/push", catalogIdentifierPath, "/libpod/images/scp/victim/push", true},
		{"exclusion misses the trailing empty segment", "/libpod/images/scp/sockguard-test/push", catalogIdentifierPath, "/libpod/images/scp/victim/push/", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := scpDualViewAccepts(t, test.template, test.shape, test.candidate); got != test.want {
				t.Fatalf("catalog machine for %q (shape %d) accepts %q = %t, want %t",
					test.template, test.shape, test.candidate, got, test.want)
			}
		})
	}
}

// scpDualViewCatalogRow is one of the two catalogs that carry the image-SCP
// entry. Both rows changed shape, so both are exercised: reverting either one
// to catalogIdentifierPath has to turn this test red.
type scpDualViewCatalogRow struct {
	name        string
	acknowledge func(*config.Config)
	wantRefusal string
	row         func(*testing.T) (string, string, catalogIdentifierShape, []catalogPathExclusion)
	audit       func(*config.Config, []*filter.CompiledRule) []string
}

func scpDualViewCatalogRows() []scpDualViewCatalogRow {
	return []scpDualViewCatalogRow{
		{
			name: "body-write catalog",
			// The read side is acknowledged so the refusal under test can only
			// be the blind-write one.
			acknowledge: func(cfg *config.Config) { cfg.InsecureAllowReadExfiltration = true },
			wantRefusal: "insecure_allow_body_blind_writes",
			row: func(t *testing.T) (string, string, catalogIdentifierShape, []catalogPathExclusion) {
				t.Helper()
				for _, endpoint := range bodySensitiveWriteEndpoints {
					if endpoint.path == scpDualViewCatalogPath {
						return endpoint.method, endpoint.path, endpoint.identifierShape, endpoint.exclusions
					}
				}
				t.Fatalf("%q is no longer a body-sensitive write endpoint", scpDualViewCatalogPath)
				return "", "", 0, nil
			},
			audit: func(cfg *config.Config, compiled []*filter.CompiledRule) []string {
				return allowedBodySensitiveWriteEndpoints(cfg.RequestBody, cfg.Rules, compiled)
			},
		},
		{
			name:        "read-exfiltration catalog",
			acknowledge: func(cfg *config.Config) { cfg.InsecureAllowBodyBlindWrites = true },
			wantRefusal: "insecure_allow_read_exfiltration",
			row: func(t *testing.T) (string, string, catalogIdentifierShape, []catalogPathExclusion) {
				t.Helper()
				for _, endpoint := range sensitiveExfilEndpoints {
					if endpoint.path == scpDualViewCatalogPath {
						return endpoint.method, endpoint.path, endpoint.identifierShape, endpoint.exclusions
					}
				}
				t.Fatalf("%q is no longer a read-exfiltration endpoint", scpDualViewCatalogPath)
				return "", "", 0, nil
			},
			audit: func(cfg *config.Config, compiled []*filter.CompiledRule) []string {
				return allowedSensitiveExfilEndpoints(cfg.Rules, compiled)
			},
		},
	}
}

// TestCatalogReachabilityLibpodSCPRouteView is the regression for S17b.
//
// firstAllowedCatalogPath used to search the decoded policy view only, while
// filter.Evaluate additionally evaluates Podman's gorilla/mux route view for
// POST /libpod/images/scp/... A policy allowing both a decoded path and its
// route view therefore passes both runtime views and the daemon routes the
// request to the image-SCP handler, but the validator only ever probed the
// decoded path: .../{name}/push is removed from the SCP catalog by that
// entry's own exclusions, and the bare .../scp is not in the catalog language
// at all. The verdict came back catalogUnreachable, so the audit reported
// nothing and the config loaded with no acknowledgment.
func TestCatalogReachabilityLibpodSCPRouteView(t *testing.T) {
	t.Parallel()
	shapes := []struct {
		name      string
		rules     []config.RuleConfig
		routeView string
	}{
		{
			// A trailing slash misses Podman's anchored .../push route and
			// falls through to the SCP catch-all.
			name:      "trailing slash on an action route",
			routeView: "/libpod/images/scp/foreign/push/",
			rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/foreign/push"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/foreign/push/"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
		},
		{
			// {name:.*} matches the empty string, so the bare route is an SCP
			// call with no source name rather than a non-route.
			name:      "bare route with no source name",
			routeView: "/libpod/images/scp/",
			rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
		},
	}
	for _, shape := range shapes {
		for _, catalog := range scpDualViewCatalogRows() {
			t.Run(shape.name+"/"+catalog.name, func(t *testing.T) {
				t.Parallel()
				cfg := config.Defaults()
				cfg.Rules = shape.rules
				catalog.acknowledge(&cfg)
				if err := config.ValidateStructural(&cfg); err != nil {
					t.Fatalf("ValidateStructural error = %v, want nil", err)
				}

				compiled, err := compileConfiguredRules(cfg.Rules)
				if err != nil {
					t.Fatalf("compileConfiguredRules error = %v, want nil", err)
				}
				if !policyAllowsPath(http.MethodPost, shape.routeView, compiled) {
					t.Fatalf("policyAllowsPath(POST %q) = false, want true; the premise of this regression is that both views allow", shape.routeView)
				}

				method, path, identifierShape, exclusions := catalog.row(t)
				if _, result := firstAllowedCatalogPath(method, path, identifierShape, exclusions, cfg.Rules); result == catalogUnreachable {
					t.Fatalf("firstAllowedCatalogPath(%s %q) = unreachable, but %s %q reaches the image-SCP handler",
						method, path, http.MethodPost, shape.routeView)
				}

				wantEndpoint := http.MethodPost + " " + shape.routeView
				if exposed := catalog.audit(&cfg, compiled); !slices.Contains(exposed, wantEndpoint) {
					t.Fatalf("audit = %v, want it to name %q", exposed, wantEndpoint)
				}

				if _, err := validateAndCompileRules(&cfg); err == nil {
					t.Fatalf("validateAndCompileRules error = nil, want a refusal demanding %s", catalog.wantRefusal)
				} else if !strings.Contains(err.Error(), catalog.wantRefusal) {
					t.Fatalf("validateAndCompileRules error = %v, want it to demand %s", err, catalog.wantRefusal)
				}
			})
		}
	}
}
