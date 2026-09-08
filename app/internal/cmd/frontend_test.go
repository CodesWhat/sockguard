package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestFrontendCommandRequiresPinnedImageAndRuntime(t *testing.T) {
	for _, args := range [][]string{{}, {"frontend:latest"}, {"--runtime-context", "local", "frontend:latest"}} {
		command := newFrontendCommand()
		command.SetArgs(args)
		command.SetOut(&bytes.Buffer{})
		command.SetErr(&bytes.Buffer{})
		if err := command.Execute(); err == nil {
			t.Fatalf("invalid command reached execution: %v", args)
		}
	}
	command := newFrontendCommand()
	command.SetArgs([]string{"--help"})
	var out bytes.Buffer
	command.SetOut(&out)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--host", "--runtime-context", "--operations-file", "--opt", "--tls-cert"} {
		if !strings.Contains(out.String(), flag) {
			t.Fatalf("missing frontend flag: %s", flag)
		}
	}
}
