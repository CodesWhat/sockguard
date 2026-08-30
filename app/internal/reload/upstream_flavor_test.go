package reload

import (
	"slices"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// TestUpstreamFlavorIsImmutable pins both halves of the immutability
// contract, because they are separate hand-maintained lists and either one
// alone is a silent no-op: ImmutableFields is what the operator-facing
// message enumerates, ImmutableDiff is what actually rejects the reload.
// Listing the field without diffing it would report "restart required" for a
// field nothing compares, and diffing it without listing it would reject a
// reload the documentation calls mutable.
func TestUpstreamFlavorIsImmutable(t *testing.T) {
	t.Parallel()
	if !slices.Contains(ImmutableFields, "upstream.flavor") {
		t.Fatal("ImmutableFields does not contain upstream.flavor")
	}

	oldCfg := config.Defaults()
	newCfg := config.Defaults()
	newCfg.Upstream.Flavor = "podman"

	changed := ImmutableDiff(&oldCfg, &newCfg)
	if !slices.Contains(changed, "upstream.flavor") {
		t.Fatalf("ImmutableDiff(auto -> podman) = %v, want it to report upstream.flavor", changed)
	}

	same := config.Defaults()
	if changed := ImmutableDiff(&oldCfg, &same); slices.Contains(changed, "upstream.flavor") {
		t.Fatalf("ImmutableDiff(no change) = %v, want upstream.flavor absent", changed)
	}
}
