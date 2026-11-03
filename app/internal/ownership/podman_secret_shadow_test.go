package ownership

import (
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

func TestRefuseShadowableSecretName(t *testing.T) {
	tests := []struct {
		name       string
		flavor     upstreamflavor.Flavor
		identifier string
		refused    bool
	}{
		{"short hex on Podman", upstreamflavor.Podman, "b0b0", true},
		{"24 hex on Podman", upstreamflavor.Podman, strings.Repeat("a", 24), true},
		{"full-length ID on Podman", upstreamflavor.Podman, strings.Repeat("a", 25), false},
		{"name with a non-hex letter", upstreamflavor.Podman, "b0b0z", false},
		{"uppercase hex is only a name", upstreamflavor.Podman, "CAFE", false},
		{"short hex on Docker", upstreamflavor.Docker, "b0b0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := refuseShadowableSecretName(tt.identifier, Options{UpstreamFlavor: tt.flavor})
			if (got != "") != tt.refused {
				t.Errorf("refuseShadowableSecretName(%q) = %q, refused want %v", tt.identifier, got, tt.refused)
			}
		})
	}
}
