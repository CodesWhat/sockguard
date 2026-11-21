package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func bp(v bool) *bool { return &v }

func TestProfileResponseRedactionDecode(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want *bool
	}{
		{"true", "redact_container_env: true", bp(true)},
		{"false", "redact_container_env: false", bp(false)},
		{"unset", "visible_networks: [proxy]", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cfg.yaml")
			doc := "clients:\n  profiles:\n    - name: p\n      response:\n        " + tt.yaml + "\n"
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			got := cfg.Clients.Profiles[0].Response.RedactContainerEnv
			if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
				t.Fatalf("RedactContainerEnv = %v, want %v", got, tt.want)
			}
			keys, err := UnknownKeys(path)
			if err != nil || len(keys) != 0 {
				t.Fatalf("UnknownKeys = %v, %v; want none", keys, err)
			}
		})
	}
}

func TestApplyRedaction(t *testing.T) {
	allOn := RedactionSettings{true, true, true, true, true}
	allOff := RedactionSettings{}
	fields := []struct {
		name string
		set  func(*ClientProfileResponseConfig, *bool)
		get  func(RedactionSettings) bool
	}{
		{"container_env", func(p *ClientProfileResponseConfig, v *bool) { p.RedactContainerEnv = v }, func(s RedactionSettings) bool { return s.ContainerEnv }},
		{"mount_paths", func(p *ClientProfileResponseConfig, v *bool) { p.RedactMountPaths = v }, func(s RedactionSettings) bool { return s.MountPaths }},
		{"network_topology", func(p *ClientProfileResponseConfig, v *bool) { p.RedactNetworkTopology = v }, func(s RedactionSettings) bool { return s.NetworkTopology }},
		{"sensitive_data", func(p *ClientProfileResponseConfig, v *bool) { p.RedactSensitiveData = v }, func(s RedactionSettings) bool { return s.SensitiveData }},
		{"host_topology", func(p *ClientProfileResponseConfig, v *bool) { p.RedactHostTopology = v }, func(s RedactionSettings) bool { return s.HostTopology }},
	}
	for _, f := range fields {
		for _, base := range []RedactionSettings{allOn, allOff} {
			for _, override := range []*bool{nil, bp(true), bp(false)} {
				var p ClientProfileResponseConfig
				f.set(&p, override)
				got := p.ApplyRedaction(base)
				want := base
				if override != nil {
					// Only the named field may change; compare against a copy
					// where just that field is set.
					want = applyOne(base, f.name, *override)
				}
				if got != want {
					t.Errorf("%s base=%+v override=%v: got %+v, want %+v", f.name, base, override, got, want)
				}
				wantField := f.get(base)
				if override != nil {
					wantField = *override
				}
				if f.get(got) != wantField {
					t.Errorf("%s base=%v override=%v: field = %v, want %v", f.name, f.get(base), override, f.get(got), wantField)
				}
			}
		}
	}
}

func applyOne(s RedactionSettings, name string, v bool) RedactionSettings {
	switch name {
	case "container_env":
		s.ContainerEnv = v
	case "mount_paths":
		s.MountPaths = v
	case "network_topology":
		s.NetworkTopology = v
	case "sensitive_data":
		s.SensitiveData = v
	case "host_topology":
		s.HostTopology = v
	}
	return s
}

func TestRedactionSettingsKeys(t *testing.T) {
	root := RedactionSettings{ContainerEnv: true, MountPaths: true, SensitiveData: true}
	if got, want := root.EnabledKeys(), []string{"redact_container_env", "redact_mount_paths", "redact_sensitive_data"}; !reflect.DeepEqual(got, want) {
		t.Errorf("EnabledKeys = %v, want %v", got, want)
	}
	eff := RedactionSettings{ContainerEnv: true, HostTopology: true}
	if got, want := eff.DisabledRelativeTo(root), []string{"redact_mount_paths", "redact_sensitive_data"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DisabledRelativeTo = %v, want %v", got, want)
	}
	if got := root.DisabledRelativeTo(root); got != nil {
		t.Errorf("DisabledRelativeTo(self) = %v, want nil", got)
	}
}
