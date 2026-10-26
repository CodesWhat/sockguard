package cmd

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

// catalogLongPatternBound is the ceiling the long-pattern configs below are
// held to, and catalogLongPatternRaceBound is the same ceiling with race
// instrumentation in the way.
//
// A bare -race run is the wrong thing to size them against. CI runs the suite
// under `go test -race -covermode=atomic` over the whole package at once, and
// on these tight NFA loops the per-block coverage counters cost more than the
// race detector does. Only the third shape exhausts
// maxCatalogReachabilitySteps, and it measures 40ms uninstrumented, 0.48s
// under -race alone and 5.2s under CI's own flags, where a hosted runner has
// come in another 1.8-2.6x slower again. That leaves it around 4x inside the
// race bound on the runners this has actually been measured on. The other two
// shapes never reach the step budget and sit at 10ms and 10ms uninstrumented,
// 40ms and 50ms under -race, 50ms and 1.35s under CI's flags.
//
// Sizing maxCatalogReachabilitySteps against the uninstrumented number instead
// is what put this test at 63-92s on CI against the 60s bound, so a change
// that raises the step budget has to be re-measured under CI's flags and not
// under a plain `go test -race`.
const (
	catalogLongPatternBound     = 2 * time.Second
	catalogLongPatternRaceBound = 60 * time.Second
)

func catalogLongPatternDeadline() time.Duration {
	if raceBuild {
		return catalogLongPatternRaceBound
	}
	return catalogLongPatternBound
}

// catalogBoundEndpointShape reads a catalog row out of the production table so
// these tests probe the shape the validator really compiles rather than a
// hand-copied guess that a table edit would silently invalidate.
func catalogBoundEndpointShape(t *testing.T, path string) catalogIdentifierShape {
	t.Helper()
	for _, endpoint := range bodySensitiveWriteEndpoints {
		if endpoint.path == path {
			return endpoint.identifierShape
		}
	}
	t.Fatalf("%q is no longer a body-sensitive write endpoint", path)
	return 0
}

// TestValidateAndCompileRulesBoundsLongPatterns pins that an unbounded rule
// pattern cannot turn one validation into seconds of CPU. Rule patterns are
// user input and /admin/validate repeats the whole walk per request, so the
// cost of a long pattern is an amplification, not just a slow startup.
func TestValidateAndCompileRulesBoundsLongPatterns(t *testing.T) {
	if testing.Short() {
		t.Skip("asserts wall-clock time; -short skips it so a loaded runner cannot make it flaky")
	}
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
	}{
		{
			// The size the roadmap item names. It is past
			// maxCatalogReachabilityInstructions on its own, so every catalog
			// row gives up before walking anything and reports conservatively.
			name:    "4KB identifier as a literal pattern",
			pattern: "/libpod/manifests/" + strings.Repeat("a", 4096),
		},
		{
			// Small enough to compile inside the instruction budget, so this
			// one really does run the product search over a 1KB literal.
			name:    "1KB identifier as a literal pattern",
			pattern: "/libpod/manifests/" + strings.Repeat("a", 1024),
		},
		{
			// The expensive shape: hundreds of "*" segments keep hundreds of
			// instructions live at once, so every transition costs as much as
			// the whole program. This is what maxCatalogReachabilitySteps is
			// for.
			name:    "glob-dense long pattern",
			pattern: "/**/" + strings.Repeat("*a", 600),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			cfg.Rules = []config.RuleConfig{
				{Match: config.MatchConfig{Method: "*", Path: test.pattern}, Action: "allow"},
			}

			start := time.Now()
			_, err := validateAndCompileRules(&cfg)
			elapsed := time.Since(start)

			if deadline := catalogLongPatternDeadline(); elapsed > deadline {
				t.Fatalf("validateAndCompileRules() took %s for a %d-byte pattern, want under %s",
					elapsed, len(test.pattern), deadline)
			}
			// Bounding the search must not have bought speed by dropping the
			// audit: an unproved allow rule still has to be reported so the
			// acknowledgment is demanded.
			if err == nil {
				t.Fatal("validateAndCompileRules() error = nil, want the sensitive endpoints reported for an unacknowledged config")
			}
		})
	}
}

// TestFirstAllowedCatalogPathProvesLongLiteralExactly pins that the bound did
// not come out of the search's precision. A 1KB literal pattern is inside the
// instruction budget, so the exact route it allows still has to come back as a
// witness rather than as the conservative catalog spelling.
func TestFirstAllowedCatalogPathProvesLongLiteralExactly(t *testing.T) {
	t.Parallel()

	identifier := strings.Repeat("a", 1024)
	rules := []config.RuleConfig{{
		Match:  config.MatchConfig{Method: http.MethodPost, Path: "/libpod/manifests/" + identifier},
		Action: "allow",
	}}

	witness, result := firstAllowedCatalogPath(http.MethodPost, "/libpod/manifests/sockguard-test", catalogIdentifierPath, nil, rules)
	if result != catalogReachable {
		t.Fatalf("firstAllowedCatalogPath() result = %v, want reachable for a literal pattern inside the catalog language", result)
	}
	if want := "/libpod/manifests/" + identifier; witness != want {
		t.Fatalf("firstAllowedCatalogPath() witness has length %d, want the exact %d-byte route the rule allows", len(witness), len(want))
	}
}

// TestFirstAllowedCatalogPathStepBudgetFailsClosed pins the direction
// maxCatalogReachabilitySteps gives up in. A pattern dense enough to exhaust it
// has to come back indeterminate, which allowedCatalogPaths reports under the
// catalog spelling; coming back unreachable would let the allow rule through
// with no acknowledgment demanded.
func TestFirstAllowedCatalogPathStepBudgetFailsClosed(t *testing.T) {
	t.Parallel()

	const catalogPath = "/containers/sockguard-test/exec"
	shape := catalogBoundEndpointShape(t, catalogPath)
	rules := []config.RuleConfig{{
		Match:  config.MatchConfig{Method: "*", Path: "/containers/" + strings.Repeat("*a", 300)},
		Action: "allow",
	}}

	_, result := firstAllowedCatalogPath(http.MethodPost, catalogPath, shape, nil, rules)
	if result != catalogReachabilityIndeterminate {
		t.Fatalf("firstAllowedCatalogPath() result = %v, want indeterminate after step-budget exhaustion; if maxCatalogReachabilitySteps was raised, this pattern no longer reaches it", result)
	}

	compiled, err := compileConfiguredRules(rules)
	if err != nil {
		t.Fatalf("compileConfiguredRules() error = %v, want nil", err)
	}
	exposed := allowedCatalogPaths(http.MethodPost, catalogPath, shape, nil, rules, compiled)
	if len(exposed) != 1 || exposed[0] != catalogPath {
		t.Fatalf("allowedCatalogPaths() = %v, want the catalog spelling as the conservative fallback", exposed)
	}
}

// catalogHeaviestPresetSteps is what the heaviest shipped policy spends on its
// single most expensive catalog row, and the ceiling across configs/,
// examples/compose/ and the rest of this suite. Measured by instrumenting
// catalogReachabilityBudget and walking every shipped config through
// validateAndCompileRules; configs/drydock-with-selfupdate.yaml sets it, with
// the rest of the drydock family next at 50,203.
const catalogHeaviestPresetSteps = 56537

// TestCatalogReachabilityStepBudgetKeepsMeasuredHeadroom pins the window
// maxCatalogReachabilitySteps has to sit in, which nothing else checks from
// both sides. Set it too low and a shipped policy stops being provable:
// TestPresetConfigsPassBuildChain catches that, but only once the budget is
// already under what a preset spends, so the floor here is the slack that
// keeps an ordinary policy from landing against the cap the first time a rule
// is added to it. Set it too high and the search's worst case outruns
// catalogLongPatternRaceBound, because a glob-dense pattern spends the budget
// in full on every catalog row and the wall clock is linear in it. At 148x,
// the long-pattern test above measured 63-92s on CI against its own 60s
// deadline, which is the regression this ceiling exists to stop coming back.
func TestCatalogReachabilityStepBudgetKeepsMeasuredHeadroom(t *testing.T) {
	t.Parallel()

	const (
		minHeadroom = 10
		maxHeadroom = 32
	)
	headroom := float64(maxCatalogReachabilitySteps) / float64(catalogHeaviestPresetSteps)
	if headroom < minHeadroom {
		t.Fatalf("maxCatalogReachabilitySteps = %d, only %.1fx the %d steps the heaviest shipped policy spends, want at least %dx",
			maxCatalogReachabilitySteps, headroom, catalogHeaviestPresetSteps, minHeadroom)
	}
	if headroom > maxHeadroom {
		t.Fatalf("maxCatalogReachabilitySteps = %d, %.1fx the %d steps the heaviest shipped policy spends, want at most %dx so the long-pattern test keeps its margin under CI's -race -covermode=atomic run",
			maxCatalogReachabilitySteps, headroom, catalogHeaviestPresetSteps, maxHeadroom)
	}
}
