package config

import (
	"reflect"
	"testing"
)

func FuzzEffectiveListenerValidation(f *testing.F) {
	seeds := []struct {
		name, socket, address, allowed string
		tlsMask                        uint8
		explicit                       bool
	}{
		{"ci", "/run/ci.sock", "", "ci", 0, true},
		{"ops", "", "127.0.0.1:2375", "*", 0, true},
		{"admin", "/run/admin.sock", "", "*", 0, true},
		{"bad name", "/run/bad.sock", "", "ci", 0, true},
		{"ci", "/run/ci.sock", "127.0.0.1:2375", "ci", 0, true},
		{"ci", "", "127.0.0.1:2376", "ci", 1, true},
		{"ci", "", "[0:0:0:0:0:0:0:1]:2375", "ci", 0, true},
		{"default", "", "127.0.0.1:2375", "*", 0, false},
		{"default", "/run/default.sock", "", "*", 0, false},
	}
	for _, seed := range seeds {
		f.Add(seed.name, seed.socket, seed.address, seed.allowed, seed.tlsMask, seed.explicit)
	}

	f.Fuzz(func(t *testing.T, name, socket, address, allowed string, tlsMask uint8, explicit bool) {
		if len(name)+len(socket)+len(address)+len(allowed) > 4096 {
			t.Skip()
		}
		cfg := Defaults()
		cfg.Clients.Profiles = []ClientProfileConfig{{Name: "ci"}, {Name: "ops"}}
		listen := ListenConfig{Socket: socket, Address: address, SocketMode: HardenedListenSocketMode}
		if tlsMask&1 != 0 {
			listen.TLS.CertFile = "cert"
		}
		if tlsMask&2 != 0 {
			listen.TLS.KeyFile = "key"
		}
		if tlsMask&4 != 0 {
			listen.TLS.ClientCAFile = "ca"
		}
		if explicit {
			cfg.Listeners = []ListenerConfig{{Name: name, ListenConfig: listen, AllowedProfiles: []string{allowed}}}
		} else {
			cfg.Listen = listen
		}

		first := validateListeners(&cfg, validateFull)
		second := validateListeners(&cfg, validateFull)
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("validation is nondeterministic: first=%v second=%v", first, second)
		}

		effective := cfg.EffectiveListeners()
		if explicit {
			if len(effective) != 1 || effective[0].Name != name {
				t.Fatalf("EffectiveListeners(explicit) = %#v", effective)
			}
			if len(first) == 0 {
				entry := effective[0]
				if !ValidListenerName(entry.Name) || entry.Name == AdminListenerName {
					t.Fatalf("accepted unsafe listener name %q", entry.Name)
				}
				if (entry.Socket == "") == (entry.Address == "") {
					t.Fatalf("accepted entry without exactly one endpoint: %#v", entry)
				}
				if len(entry.AllowedProfiles) == 0 {
					t.Fatalf("accepted empty allowed_profiles: %#v", entry)
				}
			}
			if socket == "" && address != "" {
				normalized := normalizeTCPBindTarget(address)
				if normalized != address {
					duplicate := cfg
					duplicate.Listeners = append([]ListenerConfig(nil), cfg.Listeners...)
					duplicate.Listeners = append(duplicate.Listeners, ListenerConfig{
						Name:            "normalized-duplicate",
						ListenConfig:    ListenConfig{Address: normalized, SocketMode: HardenedListenSocketMode},
						AllowedProfiles: []string{WildcardProfile},
					})
					if errs := validateExplicitListenersBindUniqueness(&duplicate); len(errs) == 0 {
						t.Fatalf("normalized duplicate addresses accepted: %q and %q", address, normalized)
					}
				}
			}
			return
		}
		if len(effective) != 1 || effective[0].Name != DefaultListenerName || !effective[0].Wildcard() {
			t.Fatalf("EffectiveListeners(legacy) = %#v", effective)
		}
	})
}
