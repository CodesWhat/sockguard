package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/boundedio"
)

func TestLoadRejectsOversizedConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.Truncate(MaxConfigFileBytes + 1); err != nil {
		f.Close()
		t.Fatalf("Truncate: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := Load(path); !errors.Is(err, boundedio.ErrTooLarge) {
		t.Fatalf("Load oversized config error = %v, want ErrTooLarge", err)
	}
}
