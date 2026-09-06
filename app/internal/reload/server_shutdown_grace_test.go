package reload

import (
	"slices"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// TestServerIsImmutable pins both halves of the immutability contract for
// server.shutdown_grace, mirroring TestUpstreamFlavorIsImmutable: the
// process reads it once at startup into a deps seam consulted only at
// shutdown, so a reload can never make a changed value take effect, and a
// reload that changes it must be rejected rather than silently ignored.
func TestServerIsImmutable(t *testing.T) {
	t.Parallel()
	if !slices.Contains(ImmutableFields, "server") {
		t.Fatal("ImmutableFields does not contain server")
	}

	oldCfg := config.Defaults()
	newCfg := config.Defaults()
	newCfg.Server.ShutdownGrace = "1s"

	changed := ImmutableDiff(&oldCfg, &newCfg)
	if !slices.Contains(changed, "server") {
		t.Fatalf("ImmutableDiff(30s -> 1s) = %v, want it to report server", changed)
	}

	same := config.Defaults()
	if changed := ImmutableDiff(&oldCfg, &same); slices.Contains(changed, "server") {
		t.Fatalf("ImmutableDiff(no change) = %v, want server absent", changed)
	}
}
