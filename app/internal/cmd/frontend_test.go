package cmd

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

func TestFrontendCommandOperationsFile(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"stdout", "new report", "existing report"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusForbidden)
			}))
			t.Cleanup(server.Close)
			args := []string{"--runtime-context", "local", "--host", server.URL}
			var report string
			if name != "stdout" {
				report = filepath.Join(t.TempDir(), "operations.jsonl")
				args = append(args, "--operations-file", report)
			}
			if name == "existing report" {
				if err := os.WriteFile(report, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			args = append(args, "example.invalid/frontend@sha256:"+strings.Repeat("a", 64))
			command := newFrontendCommand()
			command.SetContext(t.Context())
			command.SetArgs(args)
			command.SetOut(&bytes.Buffer{})
			command.SetErr(&bytes.Buffer{})
			err := command.Execute()
			if name == "existing report" {
				if !errors.Is(err, os.ErrExist) || calls.Load() != 0 {
					t.Fatalf("existing report: error=%v, proxy calls=%d; want file-exists refusal before dialing", err, calls.Load())
				}
			} else if err == nil || !strings.Contains(err.Error(), "proxy refused /grpc upgrade") || calls.Load() != 1 {
				t.Fatalf("proxy refusal: error=%v, calls=%d; want one attempted upgrade", err, calls.Load())
			}
			if report != "" {
				content, err := os.ReadFile(report)
				if err != nil {
					t.Fatal(err)
				}
				want := ""
				if name == "existing report" {
					want = "keep"
				}
				if string(content) != want {
					t.Fatalf("report = %q, want %q", content, want)
				}
				info, err := os.Stat(report)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0o600 {
					t.Fatalf("report mode = %o, want 600", info.Mode().Perm())
				}
			}
		})
	}
}
