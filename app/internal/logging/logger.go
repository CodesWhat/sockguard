package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
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

func outputWriter(output string) (io.Writer, io.Closer, error) {
	switch strings.TrimSpace(output) {
	case "", "stderr":
		return os.Stderr, nil, nil
	case "stdout":
		return os.Stdout, nil, nil
	default:
		f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("open log output %q: %w", output, err)
		}
		return f, f, nil
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
