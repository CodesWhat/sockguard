package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

func validateLogOutput(output string) error {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return fmt.Errorf("invalid log output (must be stderr, stdout, or a local file path)")
	}

	switch trimmed {
	case "stderr", "stdout":
		return nil
	default:
		cleaned := filepath.Clean(trimmed)
		if !filepath.IsLocal(cleaned) {
			return fmt.Errorf("invalid log output %q (must be stderr, stdout, or a local file path)", output)
		}
		return nil
	}
}
