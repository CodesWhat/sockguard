package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// New creates a structured logger with the given level and format.
// Output may be "stderr", "stdout", or a file path.
func New(level, format, output string) (*slog.Logger, io.Closer, error) {
	writer, closer, err := outputWriter(output)
	if err != nil {
		return nil, nil, err
	}

	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: parseLevel(level),
	}

	switch format {
	case "text":
		handler = slog.NewTextHandler(writer, opts)
	default:
		handler = slog.NewJSONHandler(writer, opts)
	}

	return slog.New(handler), closer, nil
}

// ValidateOutput checks whether the configured log output target is supported.
// Allowed values are stderr, stdout, or a local file path.
func ValidateOutput(output string) error {
	_, err := normalizeOutput(output)
	return err
}

func outputWriter(output string) (io.Writer, io.Closer, error) {
	normalized, err := normalizeOutput(output)
	if err != nil {
		return nil, nil, err
	}

	switch normalized {
	case "stderr":
		return os.Stderr, nil, nil
	case "stdout":
		return os.Stdout, nil, nil
	default:
		f, err := os.OpenFile(normalized, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, nil, fmt.Errorf("open log output %q: %w", normalized, err)
		}
		return f, f, nil
	}
}

func normalizeOutput(output string) (string, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return "", fmt.Errorf("invalid log output (must be stderr, stdout, or a local file path)")
	}

	switch trimmed {
	case "stderr", "stdout":
		return trimmed, nil
	default:
		cleaned := filepath.Clean(trimmed)
		if !filepath.IsLocal(cleaned) {
			return "", fmt.Errorf("invalid log output %q (must be stderr, stdout, or a local file path)", output)
		}
		return cleaned, nil
	}
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
