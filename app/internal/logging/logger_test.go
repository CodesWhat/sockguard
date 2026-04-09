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
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("log file mode = %04o, want 0640", got)
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
