package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	logPath := filepath.Join(t.TempDir(), "sockguard.log")

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

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", logPath, err)
	}
	output := string(data)
	if !strings.Contains(output, "test-log-entry") {
		t.Fatalf("expected log output to contain entry, got %q", output)
	}
}

func TestNewInvalidOutputPath(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "missing", "sockguard.log")
	_, closer, err := New("info", "json", logPath)
	if err == nil {
		if closer != nil {
			_ = closer.Close()
		}
		t.Fatal("expected New() to fail for invalid output path")
	}
}
