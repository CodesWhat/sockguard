package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// logBufferSize is the flush threshold of the buffer used when logging to a file.
// stderr and stdout are left unbuffered so dev/debug output appears immediately.
// 64 KiB keeps busy hosts from flushing (and holding the writer mutex) every
// dozen access-log lines; logFlushInterval still bounds record staleness.
const logBufferSize = 64 * 1024

// logFlushInterval bounds the worst-case delay between a log record being
// written and reaching disk on a low-throughput host. Busy hosts flush
// implicitly when the buffer fills; the periodic flush is the safety
// net for hosts where records trickle in.
const logFlushInterval = time.Second

// SafeString escapes record-delimiting characters before untrusted text reaches
// a logging API. Both slog handlers already quote these values, but doing this at
// the trust boundary also protects custom handlers and makes the invariant
// explicit to static analysis.
func SafeString(value string) string {
	value = strings.ReplaceAll(value, "\r", `\r`)
	return strings.ReplaceAll(value, "\n", `\n`)
}

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
		f, err := os.OpenFile(normalized, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- arbitrary local output paths are an explicit configuration feature and normalizeOutput rejects unsafe values.
		if err != nil {
			return nil, nil, fmt.Errorf("open log output %q: %w", normalized, err)
		}
		w := newBufferedFileWriter(f, logBufferSize, logFlushInterval)
		return w, w, nil
	}
}

// maxPendingBytes bounds the bytes a file sink holds while the file refuses
// writes (disk full, I/O error). Past this, new records are refused and
// counted instead of growing memory without limit.
const maxPendingBytes = 4 * 1024 * 1024

// sinkDiagnosticInterval spaces the stderr diagnostics a failing file sink
// emits, so a dead disk produces one line a minute rather than one per record.
const sinkDiagnosticInterval = time.Minute

// bufferedFileWriter buffers log records in memory and flushes them to a file
// when the buffer reaches flushSize and on a periodic tick, so records do not
// sit in memory indefinitely on low-throughput hosts.
//
// Unlike a bufio.Writer, a failed write is not sticky. The unwritten suffix
// stays in the pending buffer and the next flush retries it, so bytes are
// neither lost nor duplicated once storage recovers. The buffer is bounded by
// maxPending; a record that would not fit is refused whole (never split) and
// counted.
type bufferedFileWriter struct {
	mu          sync.Mutex
	out         io.WriteCloser
	pending     []byte
	flushSize   int
	maxPending  int
	droppedRecs uint64
	droppedByte uint64
	failing     bool

	diagInterval time.Duration
	diagNow      func() time.Time
	diagOut      io.Writer
	lastDiag     time.Time
	diagSent     bool

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

func newBufferedFileWriter(f *os.File, size int, flushInterval time.Duration) *bufferedFileWriter {
	return newBufferedWriter(f, size, maxPendingBytes, flushInterval)
}

func newBufferedWriter(out io.WriteCloser, flushSize, maxPending int, flushInterval time.Duration) *bufferedFileWriter {
	w := &bufferedFileWriter{
		out:          out,
		flushSize:    flushSize,
		maxPending:   maxPending,
		diagInterval: sinkDiagnosticInterval,
		diagNow:      time.Now,
		diagOut:      os.Stderr,
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
	go w.flushLoop(flushInterval)
	return w
}

// Write queues p. It is all-or-nothing: either the whole record is buffered
// (nil error, even when the file is currently failing, because it will be
// retried) or the buffer is full and the record is refused with an error and
// counted as dropped.
func (w *bufferedFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending)+len(p) > w.maxPending {
		// Try to make room first; the file may have recovered.
		_ = w.flushLocked()
	}
	if len(w.pending)+len(p) > w.maxPending {
		w.droppedRecs++
		w.droppedByte += uint64(len(p))
		w.diagnoseLocked(fmt.Errorf("pending buffer full (%d bytes), dropping records", len(w.pending)))
		return 0, fmt.Errorf("log sink buffer full: dropped %d bytes", len(p))
	}
	w.pending = append(w.pending, p...)
	if len(w.pending) >= w.flushSize {
		_ = w.flushLocked()
	}
	return len(p), nil
}

// flushLocked writes pending to the file, removing whatever was written
// (including a partial prefix) and keeping the rest for the next attempt.
func (w *bufferedFileWriter) flushLocked() error {
	for len(w.pending) > 0 {
		n, err := w.out.Write(w.pending)
		if n > 0 {
			w.pending = w.pending[:copy(w.pending, w.pending[n:])]
		}
		if err == nil && n == 0 {
			err = io.ErrShortWrite
		}
		if err != nil {
			w.failing = true
			w.diagnoseLocked(err)
			return err
		}
	}
	if w.failing {
		w.failing = false
		w.lastDiag = time.Time{}
		w.emitLocked("log sink recovered")
	}
	return nil
}

// diagnoseLocked emits a rate-limited stderr line about a sink failure. It
// writes to stderr directly, independent of the logger being served, because
// that logger is the thing that is failing.
func (w *bufferedFileWriter) diagnoseLocked(err error) {
	now := w.diagNow()
	if w.diagSent && now.Sub(w.lastDiag) < w.diagInterval {
		return
	}
	w.lastDiag = now
	w.diagSent = true
	w.emitLocked(fmt.Sprintf("log sink write failed: %v (pending_bytes=%d dropped_records=%d dropped_bytes=%d)",
		err, len(w.pending), w.droppedRecs, w.droppedByte))
}

func (w *bufferedFileWriter) emitLocked(msg string) {
	if w.diagOut != nil {
		_, _ = fmt.Fprintf(w.diagOut, "sockguard: %s\n", msg)
	}
}

func (w *bufferedFileWriter) flushLoop(interval time.Duration) {
	defer close(w.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.mu.Lock()
			_ = w.flushLocked()
			w.mu.Unlock()
		case <-w.stop:
			return
		}
	}
}

func (w *bufferedFileWriter) Close() error {
	w.stopOnce.Do(func() { close(w.stop) })
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	flushErr := w.flushLocked()
	closeErr := w.out.Close()
	if flushErr != nil {
		if len(w.pending) > 0 {
			flushErr = fmt.Errorf("%w (%d unflushed bytes lost)", flushErr, len(w.pending))
		}
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
