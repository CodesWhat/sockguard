package logging

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// zeroWriter accepts nothing and reports no error, the shape io.Writer forbids
// but a broken sink can still produce.
type zeroWriter struct {
	mu     sync.Mutex
	calls  int
	accept bool
	data   bytes.Buffer
}

func (z *zeroWriter) Write(p []byte) (int, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.calls++
	if !z.accept {
		return 0, nil
	}
	return z.data.Write(p)
}

func (z *zeroWriter) Close() error { return nil }

func (z *zeroWriter) String() string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.data.String()
}

// TestBufferedWriterZeroByteWriteIsAShortWrite pins that a sink returning
// (0, nil) is treated as a failed write rather than looping forever or
// discarding the record: the flush reports io.ErrShortWrite, keeps the bytes
// pending, emits the diagnostic, and delivers them once the sink accepts.
func TestBufferedWriterZeroByteWriteIsAShortWrite(t *testing.T) {
	z := &zeroWriter{}
	w := newBufferedWriter(z, 1<<20, 1<<20, time.Hour)
	diag := &bytes.Buffer{}
	w.diagOut = diag
	defer w.Close()

	if _, err := w.Write([]byte("record\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	w.mu.Lock()
	err := w.flushLocked()
	pending := string(w.pending)
	w.mu.Unlock()
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("flush err = %v, want io.ErrShortWrite", err)
	}
	if pending != "record\n" {
		t.Fatalf("pending = %q, want the record kept for retry", pending)
	}
	if !strings.Contains(diag.String(), "log sink write failed") {
		t.Fatalf("diagnostic = %q, want a write failure line", diag.String())
	}

	z.mu.Lock()
	z.accept = true
	z.mu.Unlock()
	w.mu.Lock()
	err = w.flushLocked()
	w.mu.Unlock()
	if err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}
	if got := z.String(); got != "record\n" {
		t.Fatalf("sink = %q, want the record exactly once", got)
	}
	if !strings.Contains(diag.String(), "log sink recovered") {
		t.Fatalf("diagnostic = %q, want a recovery line", diag.String())
	}
}

// TestBufferedWriterFlushLoopDeliversOnTick pins the periodic flush: a record
// buffered below the size threshold reaches the sink on the next tick without
// a Write or Close forcing it.
func TestBufferedWriterFlushLoopDeliversOnTick(t *testing.T) {
	z := &zeroWriter{accept: true}
	w := newBufferedWriter(z, 1<<20, 1<<20, 5*time.Millisecond)
	w.diagOut = &bytes.Buffer{}
	defer w.Close()

	if _, err := w.Write([]byte("tick\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for z.String() != "tick\n" {
		if time.Now().After(deadline) {
			t.Fatalf("sink = %q after 5s, want the record flushed by the ticker", z.String())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAuditLoggerCountersOnNilLogger(t *testing.T) {
	var l *AuditLogger
	if got := l.LostEvents(); got != 0 {
		t.Fatalf("nil LostEvents() = %d, want 0", got)
	}
	if got := l.DroppedEvents(); got != 0 {
		t.Fatalf("nil DroppedEvents() = %d, want 0", got)
	}
}
