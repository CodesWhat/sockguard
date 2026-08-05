package reload

import (
	"slices"
	"testing"
)

func TestMutationsRemainHotReloadMutable(t *testing.T) {
	if slices.Contains(ImmutableFields, "mutations") {
		t.Fatal("ImmutableFields contains mutations; admission mutations must remain hot-reload mutable")
	}
	for _, field := range ImmutableFields {
		if field == "mutations" || len(field) > len("mutations.") && field[:len("mutations.")] == "mutations." {
			t.Fatalf("ImmutableFields contains mutation subtree %q; admission mutations must remain hot-reload mutable", field)
		}
	}
}
