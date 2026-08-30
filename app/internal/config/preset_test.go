package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPresetConfigsValidate(t *testing.T) {
	presetsDir := filepath.Join("..", "..", "configs")

	entries, err := os.ReadDir(presetsDir)
	if err != nil {
		t.Fatalf("failed to read presets directory %s: %v", presetsDir, err)
	}

	var yamlFiles []string
	for _, e := range entries {
		if !e.IsDir() && (filepath.Ext(e.Name()) == ".yaml" || filepath.Ext(e.Name()) == ".yml") {
			yamlFiles = append(yamlFiles, e.Name())
		}
	}

	if len(yamlFiles) == 0 {
		t.Fatal("no preset YAML configs found — expected at least one")
	}

	for _, name := range yamlFiles {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(presetsDir, name)

			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load(%s) error: %v", name, err)
			}

			if err := Validate(cfg); err != nil {
				t.Fatalf("Validate(%s) error: %v", name, err)
			}

			if len(cfg.Rules) == 0 {
				t.Errorf("%s: expected at least one configured rule, got 0", name)
			}
		})
	}
}

func TestDiscoveryPresetUsesDedicatedSocket(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "discovery.yaml"))
	if err != nil {
		t.Fatalf("Load(discovery.yaml) error: %v", err)
	}

	if len(cfg.Listeners) != 1 {
		t.Fatalf("listeners = %d, want one dedicated discovery listener", len(cfg.Listeners))
	}
	listener := cfg.Listeners[0]
	if listener.Name != "discovery" {
		t.Fatalf("listeners[0].name = %q, want discovery", listener.Name)
	}
	if listener.Socket != "/var/run/sockguard-discovery.sock" {
		t.Fatalf("listeners[0].socket = %q, want dedicated discovery socket", listener.Socket)
	}
	if listener.SocketMode != "0600" {
		t.Fatalf("listeners[0].socket_mode = %q, want owner-only mode", listener.SocketMode)
	}
	if listener.Address != "" {
		t.Fatalf("listeners[0].address = %q, want no TCP discovery listener", listener.Address)
	}
	if len(listener.AllowedProfiles) != 1 || listener.AllowedProfiles[0] != "discovery" {
		t.Fatalf("listeners[0].allowed_profiles = %v, want [discovery]", listener.AllowedProfiles)
	}
}
