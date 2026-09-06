package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// Seven mutants in this package stay alive on purpose, all verified by
// hand-applying the mutation and re-running it:
//
//   - verify.go writeVerifyText, `len(check.Name) > width`: `>=` updates the
//     running maximum on a tie, which stores the same width. The `<`
//     direction is a real change and the test below kills it.
//   - version.go shortCommit, `len(c) > n`: at len(c) == n, c[:n] is c.
//   - match.go, `matchedRuleIndex < len(cfg.Rules)`: Evaluate never returns an
//     index equal to the rule count, so `<=` decides the same way.
//   - serve.go effectiveUpstreamRequestTimeout, `d <= 0`: `< 0` returns d for
//     d == 0, and d is 0, which is what the guard returns anyway.
//   - serve.go startWatchdog and startReadiness, `interval <= 0`: health's own
//     StartWatchdog returns immediately on a non-positive interval, so `< 0`
//     only changes which no-op cancel func comes back.
//   - rule_reachability.go firstAllowedCatalogPath, the `+1` in
//     make([]catalogRuleMachine, 0, len(catalogMachines)+i+1): the catalog is
//     always in that slice and i is non-negative, so `-1` stays non-negative
//     and only changes a capacity hint.

// TestCountVerifyFailuresCountsOnlyFailures pins what the exit-code count is
// counting. countVerifyFailures feeds the process exit status, so counting the
// wrong status, or counting in the wrong direction, turns a clean verify into
// a non-zero exit or the reverse.
func TestCountVerifyFailuresCountsOnlyFailures(t *testing.T) {
	tests := []struct {
		name   string
		checks []verifyCheck
		want   int
	}{
		{name: "no checks", checks: nil, want: 0},
		{
			name:   "all ok",
			checks: []verifyCheck{{Status: verifyStatusOK}, {Status: verifyStatusOK}},
			want:   0,
		},
		{
			name:   "skips do not count",
			checks: []verifyCheck{{Status: verifyStatusSkip}, {Status: verifyStatusSkip}},
			want:   0,
		},
		{
			name:   "one failure among passes",
			checks: []verifyCheck{{Status: verifyStatusOK}, {Status: verifyStatusFail}, {Status: verifyStatusSkip}},
			want:   1,
		},
		{
			name:   "every check failed",
			checks: []verifyCheck{{Status: verifyStatusFail}, {Status: verifyStatusFail}, {Status: verifyStatusFail}},
			want:   3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := countVerifyFailures(tt.checks); got != tt.want {
				t.Fatalf("countVerifyFailures(%v) = %d, want %d", tt.checks, got, tt.want)
			}
		})
	}
}

// TestWriteVerifyTextPadsNamesToTheWidestName pins the column alignment of the
// text report. The width is measured over every check name before anything is
// styled, so a short name is padded out to the longest one and the detail
// column lines up.
func TestWriteVerifyTextPadsNamesToTheWidestName(t *testing.T) {
	var out bytes.Buffer
	writeVerifyText(&out, verifyReport{
		Config:  "/etc/sockguard/config.yaml",
		Version: "dev",
		Status:  verifyStatusOK,
		Checks: []verifyCheck{
			{Name: "tls", Status: verifyStatusOK, Detail: "short name"},
			{Name: "upstream-socket", Status: verifyStatusOK, Detail: "widest name"},
		},
	})

	got := out.String()
	if !strings.Contains(got, "tls              short name") {
		t.Fatalf("writeVerifyText did not pad the short name to the widest name's width:\n%s", got)
	}
	if !strings.Contains(got, "upstream-socket  widest name") {
		t.Fatalf("writeVerifyText did not write the widest name unpadded:\n%s", got)
	}
}
