package cmd

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// catalogLongPatternRules is the shape PERF-24 is about: one long identifier
// reused verbatim as a literal rule pattern. The rule is inside the catalog
// language for POST /libpod/manifests/sockguard-test, so proving it reachable
// means walking the whole identifier.
func catalogLongPatternRules(identifierLen int) []config.RuleConfig {
	return []config.RuleConfig{{
		Match: config.MatchConfig{
			Method: http.MethodPost,
			Path:   "/libpod/manifests/" + strings.Repeat("a", identifierLen),
		},
		Action: "allow",
	}}
}

func BenchmarkFirstAllowedCatalogPathLongPattern(b *testing.B) {
	for _, size := range []int{64, 256, 1024} {
		b.Run(fmt.Sprintf("identifier=%dB", size), func(b *testing.B) {
			rules := catalogLongPatternRules(size)
			b.ReportAllocs()
			for b.Loop() {
				_, result := firstAllowedCatalogPath(http.MethodPost, "/libpod/manifests/sockguard-test", catalogIdentifierPath, nil, rules)
				if result == catalogUnreachable {
					b.Fatalf("firstAllowedCatalogPath() = unreachable, want the long literal proved or given up on")
				}
			}
		})
	}
}

func BenchmarkValidateAndCompileRulesLongPattern(b *testing.B) {
	for _, size := range []int{64, 256, 1024} {
		b.Run(fmt.Sprintf("identifier=%dB", size), func(b *testing.B) {
			rules := catalogLongPatternRules(size)
			b.ReportAllocs()
			for b.Loop() {
				cfg := config.Defaults()
				cfg.Rules = rules
				_, _ = validateAndCompileRules(&cfg)
			}
		})
	}
}
