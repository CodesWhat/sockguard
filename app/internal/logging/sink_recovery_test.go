package logging

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// flakyFile is an io.WriteCloser whose writes fail or truncate on demand.
type flakyFile struct {
	mu       sync.Mutex
	data     bytes.Buffer
	failErr  error // when non-nil, Write returns (0, failErr)
	partial  int   // when > 0, the next Write accepts only this many bytes then fails
	closeErr error
	closed   bool
}

func (f *flakyFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failErr != nil {
		return 0, f.failErr
	}
	if f.partial > 0 {
		n := min(f.partial, len(p))
		f.partial = 0
		f.data.Write(p[:n])
		return n, errors.New("injected partial write")
	}
	return f.data.Write(p)
}

func (f *flakyFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return f.closeErr
}

func (f *flakyFile) set(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func (f *flakyFile) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data.String()
}

func newTestSink(f *flakyFile, flushSize, maxPending int) (*bufferedFileWriter, *bytes.Buffer) {
	w := newBufferedWriter(f, flushSize, maxPending, time.Hour)
	diag := &bytes.Buffer{}
	w.diagOut = diag
	return w, diag
}

func TestBufferedWriterRecoversAfterTransientError(t *testing.T) {
	f := &flakyFile{}
	w, diag := newTestSink(f, 1, 1<<20)
	defer w.Close()

	f.set(func() { f.failErr = errors.New("ENOSPC") })
	if _, err := w.Write([]byte("one\n")); err != nil {
		t.Fatalf("Write during outage returned %v, want buffered nil", err)
	}
	if _, err := w.Write([]byte("two\n")); err != nil {
		t.Fatalf("Write during outage returned %v, want buffered nil", err)
	}
	if f.String() != "" {
		t.Fatalf("file has %q during outage", f.String())
	}

	f.set(func() { f.failErr = nil })
	if _, err := w.Write([]byte("three\n")); err != nil {
		t.Fatalf("Write after recovery: %v", err)
	}
	if got := f.String(); got != "one\ntwo\nthree\n" {
		t.Fatalf("file = %q, want all records once, in order", got)
	}
	if !strings.Contains(diag.String(), "write failed") || !strings.Contains(diag.String(), "ENOSPC") {
		t.Fatalf("diagnostic missing failure: %q", diag.String())
	}
	if !strings.Contains(diag.String(), "recovered") {
		t.Fatalf("diagnostic missing recovery: %q", diag.String())
	}
}

func TestBufferedWriterPartialWriteNotDuplicated(t *testing.T) {
	f := &flakyFile{}
	w, _ := newTestSink(f, 1, 1<<20)
	defer w.Close()

	f.set(func() { f.partial = 3 })
	if _, err := w.Write([]byte("abcdef\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := f.String(); got != "abc" {
		t.Fatalf("after partial write file = %q, want %q", got, "abc")
	}
	// Next write (and flush) retries only the unwritten suffix.
	if _, err := w.Write([]byte("ghi\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := f.String(); got != "abcdef\nghi\n" {
		t.Fatalf("file = %q, want %q (suffix retried without duplication)", got, "abcdef\nghi\n")
	}
}

func TestBufferedWriterPeriodicFlushRetries(t *testing.T) {
	f := &flakyFile{}
	w, _ := newTestSink(f, 1<<20, 1<<20)
	defer w.Close()

	f.set(func() { f.failErr = errors.New("EIO") })
	_, _ = w.Write([]byte("kept\n"))
	w.mu.Lock()
	_ = w.flushLocked()
	w.mu.Unlock()
	f.set(func() { f.failErr = nil })
	w.mu.Lock()
	err := w.flushLocked()
	w.mu.Unlock()
	if err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}
	if got := f.String(); got != "kept\n" {
		t.Fatalf("file = %q, want %q", got, "kept\n")
	}
}

func TestBufferedWriterOverflowRefusesWholeRecords(t *testing.T) {
	f := &flakyFile{failErr: errors.New("ENOSPC")}
	w, diag := newTestSink(f, 1, 10)
	defer w.Close()

	if _, err := w.Write([]byte("12345\n")); err != nil {
		t.Fatalf("first record: %v", err)
	}
	// 6 + 6 > 10 and the file still fails: refused whole and counted.
	w.diagNow = func() time.Time { return time.Now().Add(time.Hour) } // past the diagnostic rate limit
	if n, err := w.Write([]byte("67890\n")); err == nil || n != 0 {
		t.Fatalf("overflow Write = (%d, %v), want (0, error)", n, err)
	}
	w.mu.Lock()
	recs, bytesDropped, pending := w.droppedRecs, w.droppedByte, len(w.pending)
	w.mu.Unlock()
	if recs != 1 || bytesDropped != 6 || pending != 6 {
		t.Fatalf("dropped=%d/%d pending=%d, want 1/6/6", recs, bytesDropped, pending)
	}
	if !strings.Contains(diag.String(), "write failed") {
		t.Fatalf("diagnostic = %q, want a sink failure line", diag.String())
	}

	// Recovery: the retained record lands intact, later records are accepted.
	f.set(func() { f.failErr = nil })
	if _, err := w.Write([]byte("after\n")); err != nil {
		t.Fatalf("Write after recovery: %v", err)
	}
	if got := f.String(); got != "12345\nafter\n" {
		t.Fatalf("file = %q, want %q", got, "12345\nafter\n")
	}
}

func TestBufferedWriterDiagnosticIsRateLimited(t *testing.T) {
	f := &flakyFile{failErr: errors.New("EIO")}
	w, diag := newTestSink(f, 1, 1<<20)
	defer w.Close()
	now := time.Unix(1000, 0)
	w.diagNow = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		_, _ = w.Write([]byte("x\n"))
	}
	if got := strings.Count(diag.String(), "write failed"); got != 1 {
		t.Fatalf("diagnostics within interval = %d, want 1", got)
	}
	now = now.Add(2 * time.Minute)
	_, _ = w.Write([]byte("x\n"))
	if got := strings.Count(diag.String(), "write failed"); got != 2 {
		t.Fatalf("diagnostics after interval = %d, want 2", got)
	}
}

func TestBufferedWriterCloseReportsFlushFailure(t *testing.T) {
	f := &flakyFile{failErr: errors.New("EIO")}
	w, _ := newTestSink(f, 1<<20, 1<<20)
	_, _ = w.Write([]byte("lost\n"))
	err := w.Close()
	if err == nil || !strings.Contains(err.Error(), "EIO") || !strings.Contains(err.Error(), "5 unflushed bytes") {
		t.Fatalf("Close error = %v, want EIO with unflushed byte count", err)
	}
	if !f.closed {
		t.Fatal("file not closed after failed flush")
	}
}

func TestAuditLoggerSurvivesTransientSinkError(t *testing.T) {
	f := &flakyFile{}
	w, _ := newTestSink(f, 1, 1<<20)
	defer w.Close()
	logger := NewAuditLogger(w)

	f.set(func() { f.failErr = errors.New("ENOSPC") })
	logger.log(auditEvent{EventType: "during_outage"})
	f.set(func() { f.failErr = nil })
	logger.log(auditEvent{EventType: "after_recovery"})
	_ = logger.Close()

	if err := w.Close(); err != nil {
		t.Fatalf("sink Close: %v", err)
	}
	got := f.String()
	if !strings.Contains(got, "during_outage") || !strings.Contains(got, "after_recovery") {
		t.Fatalf("file = %q, want both records persisted after recovery", got)
	}
	if lost := logger.LostEvents(); lost != 0 {
		t.Fatalf("LostEvents = %d, want 0 (buffered and retried)", lost)
	}
}

// failingWriter always errors, standing in for a sink with no retry buffer.
type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }

func TestAuditLoggerCountsLostEventsAndKeepsWriting(t *testing.T) {
	logger := NewAuditLogger(failingWriter{err: errors.New("disk gone")})
	logger.log(auditEvent{EventType: "a"})
	logger.log(auditEvent{EventType: "b"})
	_ = logger.Close()
	if got := logger.LostEvents(); got != 2 {
		t.Fatalf("LostEvents = %d, want 2", got)
	}
}

func TestAuditLoggerCountsOverflowLoss(t *testing.T) {
	f := &flakyFile{failErr: errors.New("ENOSPC")}
	w, _ := newTestSink(f, 1, 1) // nothing fits
	defer w.Close()
	logger := NewAuditLogger(w)
	logger.log(auditEvent{EventType: "x"})
	_ = logger.Close()
	if got := logger.LostEvents(); got != 1 {
		t.Fatalf("LostEvents = %d, want 1", got)
	}
}

func TestAuditLoggerCountsShortWriteAsLost(t *testing.T) {
	logger := NewAuditLogger(shortWriter{})
	logger.log(auditEvent{EventType: "x"})
	_ = logger.Close()
	if got := logger.LostEvents(); got != 1 {
		t.Fatalf("LostEvents = %d, want 1", got)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
