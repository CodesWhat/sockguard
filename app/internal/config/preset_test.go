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

			compiled, err := ValidateAndCompile(cfg)
			if err != nil {
				t.Fatalf("ValidateAndCompile(%s) error: %v", name, err)
			}

			if len(compiled) == 0 {
				t.Errorf("%s: expected at least one compiled rule, got 0", name)
			}

			if len(compiled) != len(cfg.Rules) {
				t.Errorf("%s: compiled %d rules, but config has %d", name, len(compiled), len(cfg.Rules))
			}
		})
	}
}
