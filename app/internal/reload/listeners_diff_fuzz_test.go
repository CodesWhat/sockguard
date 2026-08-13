package reload

import (
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

func FuzzImmutableListenerDiff(f *testing.F) {
	for _, seed := range []struct {
		mutation uint8
		value    string
	}{
		{0, "ops"},
		{1, "reorder"},
		{2, "/run/new.sock"},
		{3, "127.0.0.1:9999"},
		{4, "0660"},
		{5, "new.crt"},
		{6, "new.key"},
		{7, "new-ca.crt"},
		{8, "renamed"},
		{9, "added"},
	} {
		f.Add(seed.mutation, seed.value)
	}

	f.Fuzz(func(t *testing.T, mutation uint8, value string) {
		if len(value) > 1024 {
			t.Skip()
		}
		base := reloadListenerConfig()
		candidate := cloneReloadListeners(base)
		mutableOnly := false
		switch mutation % 10 {
		case 0:
			candidate.Listeners[0].AllowedProfiles = []string{value}
			mutableOnly = true
		case 1:
			candidate.Listeners[0], candidate.Listeners[1] = candidate.Listeners[1], candidate.Listeners[0]
			mutableOnly = true
		case 2:
			candidate.Listeners[0].Socket = value
		case 3:
			candidate.Listeners[1].Address = value
		case 4:
			candidate.Listeners[0].SocketMode = value
		case 5:
			candidate.Listeners[1].TLS.CertFile = value
		case 6:
			candidate.Listeners[1].TLS.KeyFile = value
		case 7:
			candidate.Listeners[1].TLS.ClientCAFile = value
		case 8:
			candidate.Listeners[0].Name = value
		case 9:
			candidate.Listeners = append(candidate.Listeners, config.ListenerConfig{Name: value})
		}

		diff := ImmutableDiff(&base, &candidate)
		if mutableOnly && len(diff) != 0 {
			t.Fatalf("allowlist/reorder-only mutation rejected: %v", diff)
		}
		if !mutableOnly && value != unchangedValueForMutation(mutation%10, base) && len(diff) == 0 {
			t.Fatalf("immutable mutation %d value %q was accepted", mutation%10, value)
		}
		for _, path := range diff {
			if !strings.HasPrefix(path, "listeners.") && !strings.HasPrefix(path, "listeners:") {
				t.Fatalf("listener diff path %q is not listener-qualified", path)
			}
		}
	})
}

func unchangedValueForMutation(mutation uint8, cfg config.Config) string {
	switch mutation {
	case 2:
		return cfg.Listeners[0].Socket
	case 3:
		return cfg.Listeners[1].Address
	case 4:
		return cfg.Listeners[0].SocketMode
	case 5:
		return cfg.Listeners[1].TLS.CertFile
	case 6:
		return cfg.Listeners[1].TLS.KeyFile
	case 7:
		return cfg.Listeners[1].TLS.ClientCAFile
	case 8:
		return cfg.Listeners[0].Name
	default:
		return ""
	}
}
