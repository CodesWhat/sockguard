package reload

import (
	"slices"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

func TestUpstreamResponseHeaderTimeoutIsImmutable(t *testing.T) {
	t.Parallel()
	if !slices.Contains(ImmutableFields, "upstream.response_header_timeout") {
		t.Fatal("ImmutableFields does not contain upstream.response_header_timeout")
	}
	oldCfg := config.Defaults()
	newCfg := config.Defaults()
	newCfg.Upstream.ResponseHeaderTimeout = "off"
	if changed := ImmutableDiff(&oldCfg, &newCfg); !slices.Contains(changed, "upstream.response_header_timeout") {
		t.Fatalf("ImmutableDiff = %v, want upstream.response_header_timeout", changed)
	}
	same := config.Defaults()
	if changed := ImmutableDiff(&oldCfg, &same); slices.Contains(changed, "upstream.response_header_timeout") {
		t.Fatalf("ImmutableDiff(no change) = %v", changed)
	}
}
