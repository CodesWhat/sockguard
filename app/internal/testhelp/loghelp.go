// Package testhelp provides shared test utilities for the sockguard internal packages.
package testhelp

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// LogRecord is a single captured slog record from a CollectingHandler.
type LogRecord struct {
	Message string
	Level   slog.Level
	Attrs   map[string]any
}

// CollectingHandler is an slog.Handler that captures structured records into memory
// so tests can assert on message, level, and attribute values without parsing text output.
type CollectingHandler struct {
	mu        sync.Mutex
	records   []LogRecord
	condReady bool
	cond      *sync.Cond
}

func (h *CollectingHandler) condInit() {
	if !h.condReady {
		h.cond = sync.NewCond(&h.mu)
		h.condReady = true
	}
}

// Enabled always returns true so all levels are captured.
func (h *CollectingHandler) Enabled(context.Context, slog.Level) bool { return true }

// Handle captures the record's message, level, and top-level attributes.
func (h *CollectingHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := make(map[string]any, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})

	h.mu.Lock()
	h.records = append(h.records, LogRecord{Message: r.Message, Level: r.Level, Attrs: attrs})
	h.condInit()
	h.cond.Broadcast()
	h.mu.Unlock()
	return nil
}

// WithAttrs returns the same handler (attributes pre-attached to the logger are
// not needed for the assertion patterns used in these tests).
func (h *CollectingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

// WithGroup returns the same handler.
func (h *CollectingHandler) WithGroup(string) slog.Handler { return h }

// Records returns a snapshot of all captured records.
func (h *CollectingHandler) Records() []LogRecord {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make([]LogRecord, len(h.records))
	copy(out, h.records)
	return out
}

// FindMessage returns all captured records whose Message field equals msg.
func (h *CollectingHandler) FindMessage(msg string) []LogRecord {
	var out []LogRecord
	for _, r := range h.Records() {
		if r.Message == msg {
			out = append(out, r)
		}
	}
	return out
}

// HasMessage reports whether any captured record has Message == msg.
func (h *CollectingHandler) HasMessage(msg string) bool {
	return len(h.FindMessage(msg)) > 0
}

// WaitForMessage blocks until a record with Message == msg arrives or the
// deadline elapses. Returns true if the message was seen. Eliminates the
// sleep-poll-sleep pattern in tests that wait for asynchronous log output.
func (h *CollectingHandler) WaitForMessage(msg string, timeout time.Duration) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.condInit()

	for _, r := range h.records {
		if r.Message == msg {
			return true
		}
	}

	deadline := time.Now().Add(timeout)
	// A goroutine timer broadcasts the cond when the deadline fires so the
	// waiter wakes up even if no further records arrive. The timer is
	// stopped on return so we don't leak it on the success path.
	timer := time.AfterFunc(timeout, func() {
		h.mu.Lock()
		h.cond.Broadcast()
		h.mu.Unlock()
	})
	defer timer.Stop()

	for {
		h.cond.Wait()
		for _, r := range h.records {
			if r.Message == msg {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// Logger returns a new *slog.Logger backed by this handler.
func (h *CollectingHandler) Logger() *slog.Logger {
	return slog.New(h)
}

// teeHandler is an slog.Handler that dispatches each record to two handlers.
// It is intentionally unexported; callers obtain it via NewTeeLogger.
type teeHandler struct {
	a, b slog.Handler
}

func (h *teeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.a.Enabled(ctx, level) || h.b.Enabled(ctx, level)
}

func (h *teeHandler) Handle(ctx context.Context, r slog.Record) error {
	_ = h.a.Handle(ctx, r.Clone())
	_ = h.b.Handle(ctx, r.Clone())
	return nil
}

func (h *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &teeHandler{a: h.a.WithAttrs(attrs), b: h.b.WithAttrs(attrs)}
}

func (h *teeHandler) WithGroup(name string) slog.Handler {
	return &teeHandler{a: h.a.WithGroup(name), b: h.b.WithGroup(name)}
}

// NewTeeLogger returns an *slog.Logger that writes to both primary (e.g. a
// slog.NewJSONHandler) and a CollectingHandler so tests can use both approaches.
func NewTeeLogger(primary slog.Handler, collector *CollectingHandler) *slog.Logger {
	return slog.New(&teeHandler{a: primary, b: collector})
}
