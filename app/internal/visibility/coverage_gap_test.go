package visibility

// coverage_gap_test.go covers the uncovered branch in resourceVisible:
// the error return path (deps.inspectResource returns a non-nil error).
//
// go test -coverprofile shows resourceVisible at 66.7% because the
// "err != nil → return false, err" branch on line 650 is never exercised
// by existing tests — they inject either (labels, true, nil) or (nil, false, nil).

import (
	"context"
	"errors"
	"testing"

	"github.com/codeswhat/sockguard/internal/dockerresource"
)

// TestResourceVisibleInspectError verifies that when deps.inspectResource
// returns a non-nil error, resourceVisible propagates it to the caller rather
// than silently treating the resource as visible or invisible.
func TestResourceVisibleInspectError(t *testing.T) {
	inspectErr := errors.New("upstream dial error")

	deps := visibilityDeps{
		inspectResource: func(_ context.Context, _ dockerresource.Kind, _ string) (map[string]string, bool, error) {
			return nil, false, inspectErr
		},
	}
	selectors := []compiledSelector{{key: "com.sockguard.visible", value: "true", hasValue: true}}

	visible, err := resourceVisible(context.Background(), deps, dockerresource.KindNetwork, "net-1", selectors)
	if err == nil {
		t.Fatal("expected error from resourceVisible when inspectResource fails, got nil")
	}
	if !errors.Is(err, inspectErr) {
		t.Fatalf("errors.Is(err, inspectErr) = false; err = %v", err)
	}
	if visible {
		t.Fatal("visible = true, want false when inspectResource returns an error")
	}
}

// TestResourceVisibleInspectErrorForMultipleKinds exercises the error path for
// several resource kinds that reach resourceVisible via requestVisibleWithPolicy
// (network, volume, service, secret, config, node, swarm).
func TestResourceVisibleInspectErrorForMultipleKinds(t *testing.T) {
	inspectErr := errors.New("transient error")

	deps := visibilityDeps{
		inspectResource: func(_ context.Context, _ dockerresource.Kind, _ string) (map[string]string, bool, error) {
			return nil, false, inspectErr
		},
	}
	selectors := []compiledSelector{{key: "env", hasValue: false}}

	cases := []struct {
		kind       dockerresource.Kind
		identifier string
	}{
		{dockerresource.KindVolume, "vol-1"},
		{dockerresource.KindService, "svc-1"},
		{dockerresource.KindSecret, "sec-1"},
		{dockerresource.KindConfig, "cfg-1"},
		{dockerresource.KindNode, "node-1"},
		{dockerresource.KindSwarm, ""},
	}

	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			visible, err := resourceVisible(context.Background(), deps, tc.kind, tc.identifier, selectors)
			if err == nil {
				t.Fatalf("kind=%s: expected error, got nil", tc.kind)
			}
			if !errors.Is(err, inspectErr) {
				t.Fatalf("kind=%s: errors.Is(err, inspectErr) = false; err = %v", tc.kind, err)
			}
			if visible {
				t.Fatalf("kind=%s: visible = true, want false on error", tc.kind)
			}
		})
	}
}
