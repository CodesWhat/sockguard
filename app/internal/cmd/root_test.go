package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestExecuteVersionCommand(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"sockguard", "version"}
	t.Cleanup(func() {
		os.Args = oldArgs
		rootCmd.SetArgs(nil)
	})

	output := captureStdout(t, func() {
		if err := Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})

	if !strings.Contains(output, "sockguard ") {
		t.Fatalf("expected version output, got %q", output)
	}
}

func TestExecuteInvokesServeCommandByDefault(t *testing.T) {
	originalRunE := serveCmd.RunE
	serveCmd.RunE = func(cmd *cobra.Command, args []string) error {
		return nil
	}
	t.Cleanup(func() {
		serveCmd.RunE = originalRunE
		rootCmd.SetArgs(nil)
	})

	rootCmd.SetArgs([]string{})
	if err := Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe(): %v", err)
	}

	os.Stdout = writer
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, reader)
		done <- buf.String()
	}()

	fn()

	_ = writer.Close()
	os.Stdout = originalStdout
	output := <-done
	_ = reader.Close()

	return output
}
