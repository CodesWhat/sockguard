package filter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMutationRefusalIsHardOnlyWithAnEnforceRule pins which mutation refusals
// warn and audit rollout may pass through. The body is one the engine refuses
// as ambiguous; with an enforce rule on the surface forwarding it would skip
// the rewrite, without one there is nothing to skip.
func TestMutationRefusalIsHardOnlyWithAnEnforceRule(t *testing.T) {
	body := "{\"Image\":\"alpine\",\"Labels\":{\"İstanbul\":\"1\"}}"
	tests := []struct {
		mode     string
		wantHard bool
	}{
		{"enforce", true},
		{"warn", false},
		{"audit", false},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			policy := newContainerCreateMutationPolicy(newMutationEngine(MutationOptions{Rules: []MutationRuleOptions{{
				ID:           "label",
				Mode:         tt.mode,
				Surfaces:     []string{mutationSurfaceContainerCreate},
				InjectLabels: &InjectLabelsMutationOptions{Labels: map[string]string{"com.example.team": "platform"}},
			}}}))
			req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(body))
			_, err := policy.inspect(testLogger(), req, "/containers/create")
			rejection, ok := requestRejectionFromError(err)
			if !ok || rejection.reasonCode != reasonCodeRequestBodyAmbiguous {
				t.Fatalf("inspect() error = %v, want a %s rejection", err, reasonCodeRequestBodyAmbiguous)
			}
			if rejection.hard != tt.wantHard {
				t.Errorf("rejection.hard = %v, want %v", rejection.hard, tt.wantHard)
			}
		})
	}
}

func TestAsHardRequestRejectionLeavesOtherErrorsAlone(t *testing.T) {
	plain := io.ErrUnexpectedEOF
	if got := asHardRequestRejection(plain); got != plain {
		t.Errorf("asHardRequestRejection(%v) = %v, want the same error", plain, got)
	}
}

func TestDenyNamedVolumeDriverOptionsReason(t *testing.T) {
	tests := []struct {
		name    string
		options []string
		allowed []string
		denied  bool
	}{
		{"no options", nil, nil, false},
		{"unrelated option", []string{"ro"}, nil, false},
		{"bind outside the list", []string{"volume-opt=type=none", "volume-opt=o=bind", "volume-opt=device=/etc"}, []string{"/srv"}, true},
		{"bind inside the list", []string{"volume-opt=type=none", "volume-opt=o=bind", "volume-opt=device=/srv/a"}, []string{"/srv"}, false},
		{"option Podman cannot split is left to it", []string{"volume-opt=device"}, nil, false},
		{"prefix without a separator counts", []string{"volume-optx=type=none", "volume-optx=o=bind", "volume-optx=device=/etc"}, nil, true},
		{"non-host option", []string{"volume-opt=size=64m"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := denyNamedVolumeDriverOptionsReason(tt.options, tt.allowed)
			if (got != "") != tt.denied {
				t.Errorf("denyNamedVolumeDriverOptionsReason(%q) = %q, denied want %v", tt.options, got, tt.denied)
			}
		})
	}
}
