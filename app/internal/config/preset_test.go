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
