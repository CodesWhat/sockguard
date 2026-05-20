package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOutputWriterStdStreams(t *testing.T) {
	stderrWriter, stderrCloser, err := outputWriter("stderr")
	if err != nil {
		t.Fatalf("outputWriter(stderr) error = %v", err)
	}
	if stderrWriter != os.Stderr {
		t.Fatal("expected stderr writer to be os.Stderr")
	}
	if stderrCloser != nil {
		t.Fatal("expected nil closer for stderr output")
	}

	stdoutWriter, stdoutCloser, err := outputWriter(" stdout ")
	if err != nil {
		t.Fatalf("outputWriter(stdout) error = %v", err)
	}
	if stdoutWriter != os.Stdout {
		t.Fatal("expected stdout writer to be os.Stdout")
	}
	if stdoutCloser != nil {
		t.Fatal("expected nil closer for stdout output")
	}
}

func TestNewFileOutput(t *testing.T) {
	tmpDir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd(): %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir(%q): %v", tmpDir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	logPath := filepath.Join("logs", "..", "sockguard.log")
	logFile := filepath.Join(tmpDir, "sockguard.log")

	logger, closer, err := New("info", "text", logPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if closer == nil {
		t.Fatal("expected non-nil closer for file output")
	}

	logger.Info("test-log-entry", "k", "v")

	if err := closer.Close(); err != nil {
		t.Fatalf("close log output: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", logFile, err)
	}
	output := string(data)
	if !strings.Contains(output, "test-log-entry") {
		t.Fatalf("expected log output to contain entry, got %q", output)
	}

	info, err := os.Stat(logFile)
	if err != nil {
		t.Fatalf("Stat(%q): %v", logFile, err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("log file mode = %04o, want 0600", got)
	}
}

func TestNewInvalidOutputPath(t *testing.T) {
	tmpDir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd(): %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir(%q): %v", tmpDir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	logPath := filepath.Join("missing", "sockguard.log")
	_, closer, err := New("info", "json", logPath)
	if err == nil {
		if closer != nil {
			_ = closer.Close()
		}
		t.Fatal("expected New() to fail for invalid output path")
	}
}

func TestNewTextFormatAndParseLevels(t *testing.T) {
	logger, closer, err := New("warn", "text", "stderr")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if closer != nil {
		t.Fatalf("closer = %v, want nil for stderr", closer)
	}

	_ = logger

	if parseLevel("debug") != -4 {
		t.Fatalf("parseLevel(debug) = %v, want %v", parseLevel("debug"), -4)
	}
	if parseLevel("warn") != 4 {
		t.Fatalf("parseLevel(warn) = %v, want %v", parseLevel("warn"), 4)
	}
	if parseLevel("error") != 8 {
		t.Fatalf("parseLevel(error) = %v, want %v", parseLevel("error"), 8)
	}
	if parseLevel("info") != 0 {
		t.Fatalf("parseLevel(info) = %v, want %v", parseLevel("info"), 0)
	}
}

func TestValidateOutput(t *testing.T) {
	if err := ValidateOutput("stdout"); err != nil {
		t.Fatalf("ValidateOutput(stdout) error = %v", err)
	}
	if err := ValidateOutput("../sockguard.log"); err == nil {
		t.Fatal("expected ValidateOutput to reject non-local path")
	}
}

func TestNewJSONFormat(t *testing.T) {
	logger, closer, err := New("info", "json", "stdout")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if logger == nil {
		t.Fatal("logger = nil")
	}
	if closer != nil {
		t.Fatalf("closer = %v, want nil for stdout", closer)
	}
}

// TestBufferedFileWriterFlushOnClose pins the contract that Close() drains
// the in-memory buffer to disk before returning. The 1 s periodic flush ticker
// is irrelevant here: we explicitly want to assert that even records the
// ticker never had a chance to flush (because Close runs first) end up on disk.
//
// Write a tight burst of records larger than the 4 KiB bufio buffer in one go
// so most of the burst stays buffered, then Close immediately and assert the
// resulting file holds every record.
func TestBufferedFileWriterFlushOnClose(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "burst.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}

	// Hour-long flush interval so the periodic flush definitely does not fire
	// before Close. Anything Close drains has to come from the explicit final
	// Flush in Close itself.
	w := newBufferedFileWriter(f, logBufferSize, time.Hour)

	// 100 records × 64 bytes = 6400 bytes, well above the 4 KiB buffer.
	const records = 100
	for i := 0; i < records; i++ {
		line := bytes.Repeat([]byte{'a' + byte(i%26)}, 63)
		line = append(line, '\n')
		if _, err := w.Write(line); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := bytes.Count(data, []byte("\n"))
	if lines != records {
		t.Fatalf("persisted %d lines, want %d (buffer was not drained on Close)", lines, records)
	}
}

// TestBufferedFileWriterDoubleCloseSafe pins the idempotent-Close contract:
// the second Close must not panic on a re-closed stop channel. Pre-v1.0 the
// stop channel was unprotected and a defer'd Close paired with an explicit
// Close at shutdown would crash the process during teardown.
func TestBufferedFileWriterDoubleCloseSafe(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "double-close.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	w := newBufferedFileWriter(f, logBufferSize, time.Hour)

	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second Close used to panic via close(w.stop) on an already-closed chan.
	// File.Close on the underlying handle returns os.ErrClosed; the stopOnce
	// guard means we should reach that point rather than crashing earlier.
	if err := w.Close(); err == nil {
		t.Fatal("expected error from second Close on already-closed file, got nil")
	}
}

func TestOutputWriterRejectsNonLocalPaths(t *testing.T) {
	tests := []string{
		"",
		"../sockguard.log",
		"/tmp/sockguard.log",
	}

	for _, output := range tests {
		t.Run(output, func(t *testing.T) {
			_, closer, err := outputWriter(output)
			if closer != nil {
				_ = closer.Close()
			}
			if err == nil {
				t.Fatalf("expected outputWriter(%q) to fail", output)
			}
			if !strings.Contains(err.Error(), "local file path") {
				t.Fatalf("expected local path validation error, got %v", err)
			}
		})
	}
}
