package cmd

import (
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

func TestClientVisibilityProfilesCarryVisibleNetworks(t *testing.T) {
	profiles := clientVisibilityProfiles([]config.ClientProfileConfig{{
		Name:     "traefik",
		Response: config.ClientProfileResponseConfig{VisibleNetworks: []string{"proxy"}},
	}})
	got := profiles["traefik"].Networks
	if len(got) != 1 || got[0] != "proxy" {
		t.Fatalf("profile Networks = %#v, want [proxy]", got)
	}
}
