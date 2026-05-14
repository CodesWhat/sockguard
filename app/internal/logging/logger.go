package logging

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// logBufferSize is the size of the bufio.Writer used when logging to a file.
// stderr and stdout are left unbuffered so dev/debug output appears immediately.
const logBufferSize = 4096

// logFlushInterval bounds the worst-case delay between a log record being
// written and reaching disk on a low-throughput host. Busy hosts flush
// implicitly when the 4 KiB buffer fills; the periodic flush is the safety
// net for hosts where records trickle in.
const logFlushInterval = time.Second

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
		// 0o600: audit logs routinely carry client IPs, user agents,
		// request paths with query strings, and the specific deny
		// reason a policy emitted. Locking them down to owner-only
		// read/write matches how the Chainguard base image runs as
		// a single identity and keeps log-scrape sidecars from
		// grabbing request metadata they weren't granted access to.
		f, err := os.OpenFile(normalized, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("open log output %q: %w", normalized, err)
		}
		w := newBufferedFileWriter(f, logBufferSize, logFlushInterval)
		return w, w, nil
	}
}

// bufferedFileWriter wraps a *bufio.Writer over an *os.File with a periodic
// flush goroutine so log records do not sit in the in-memory buffer
// indefinitely on low-throughput hosts. The mutex serializes Write and the
// periodic flush, since bufio.Writer is not concurrency-safe.
type bufferedFileWriter struct {
	mu   sync.Mutex
	buf  *bufio.Writer
	file *os.File
	stop chan struct{}
	done chan struct{}
}

func newBufferedFileWriter(f *os.File, size int, flushInterval time.Duration) *bufferedFileWriter {
	w := &bufferedFileWriter{
		buf:  bufio.NewWriterSize(f, size),
		file: f,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	go w.flushLoop(flushInterval)
	return w
}

func (w *bufferedFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *bufferedFileWriter) flushLoop(interval time.Duration) {
	defer close(w.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.mu.Lock()
			_ = w.buf.Flush()
			w.mu.Unlock()
		case <-w.stop:
			return
		}
	}
}

func (w *bufferedFileWriter) Close() error {
	close(w.stop)
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	flushErr := w.buf.Flush()
	closeErr := w.file.Close()
	if flushErr != nil {
		return flushErr
	}
	return closeErr
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
