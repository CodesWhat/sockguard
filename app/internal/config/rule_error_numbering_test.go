package config

import (
	"strings"
	"testing"
)

// TestValidateRulesNumbersRulesFromOne pins the rule numbering in the two
// authoring errors that report it through a helper. Rules are one-indexed in
// every message an operator sees, because the YAML list they are reading is
// one-indexed. The first rule in the list is the one that proves it: an
// off-by-one there reports "rule 0", which points at nothing.
func TestValidateRulesNumbersRulesFromOne(t *testing.T) {
	tests := []struct {
		name  string
		rules []RuleConfig
		want  string
	}{
		{
			name: "rootless pattern in the first rule",
			rules: []RuleConfig{
				{Match: MatchConfig{Method: "GET", Path: "containers/json"}, Action: "allow"},
			},
			want: `rule 1: match.path "containers/json" must start with '/'`,
		},
		{
			name: "version prefix in the first rule",
			rules: []RuleConfig{
				{Match: MatchConfig{Method: "GET", Path: "/v1.45/containers/json"}, Action: "allow"},
			},
			want: `rule 1: match.path "/v1.45/containers/json" begins with an API version prefix`,
		},
		{
			name: "rootless pattern in the second rule",
			rules: []RuleConfig{
				{Match: MatchConfig{Method: "GET", Path: "/containers/json"}, Action: "allow"},
				{Match: MatchConfig{Method: "GET", Path: "images/json"}, Action: "allow"},
			},
			want: `rule 2: match.path "images/json" must start with '/'`,
		},
		{
			name: "version prefix in the second rule",
			rules: []RuleConfig{
				{Match: MatchConfig{Method: "GET", Path: "/containers/json"}, Action: "allow"},
				{Match: MatchConfig{Method: "GET", Path: "/v1.45/images/json"}, Action: "allow"},
			},
			want: `rule 2: match.path "/v1.45/images/json" begins with an API version prefix`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateRules(&Config{Rules: tt.rules})
			joined := strings.Join(errs, "\n")
			if !strings.Contains(joined, tt.want) {
				t.Fatalf("validateRules() errors did not contain %q:\n%s", tt.want, joined)
			}
		})
	}
}
