package filter

import (
	"testing"
)

func TestLibpodContainerNamedVolumeDriverBindBoundary(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		allowed []string
		want    string
	}{
		{name: "host source refused", want: `libpod container create denied: bind mount source "/private" is not allowlisted`},
		{name: "host source granted", allowed: []string{"/private"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedBindMounts: tt.allowed})
			body := []byte(`{"image":"alpine:3","systemd":"false","volumes":[{"Name":"data","Dest":"/data","Options":["volume-opt=type=none","volume-opt=o=bind","volume-opt=device=/private"]}]}`)
			if got := inspectLibpod(t, policy, body); got != tt.want {
				t.Fatalf("reason=%q, want %q", got, tt.want)
			}
		})
	}
}
