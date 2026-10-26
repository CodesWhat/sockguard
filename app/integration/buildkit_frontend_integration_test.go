//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/pb"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproxy"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitrunner"
	"google.golang.org/protobuf/proto"
)

const frontendPinnedRef = "docker/dockerfile@sha256:fe40cf4e92cd0c467be2cfc30657a680ae2398318afd50b0c80585784c604f28"

func TestExternalFrontendExecApprovalsRealDaemon(t *testing.T) {
	runtimeContext := os.Getenv("SOCKGUARD_FRONTEND_RUNTIME_CONTEXT")
	if runtimeContext == "" {
		t.Skip("set SOCKGUARD_FRONTEND_RUNTIME_CONTEXT to a Docker runtime containing the pinned frontend")
	}
	socket := dockerSocketForIntegration(t)
	imageName := fmt.Sprintf("sockguard-frontend-check:%d", time.Now().UnixNano())
	checkName := fmt.Sprintf("sockguard-output-check-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", "--context", runtimeContext, "rm", "-f", checkName).Run()
		_ = exec.CommandContext(ctx, "docker", "--context", runtimeContext, "image", "rm", "-f", imageName).Run()
	})
	buildStamp := fmt.Sprint(time.Now().UnixNano())
	var changed atomic.Bool
	dockerfile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		command := "sleep 11; echo approved > /approved; echo " + buildStamp + " > /build-id"
		if changed.Load() {
			command = "echo changed > /approved"
		}
		_, _ = fmt.Fprintf(w, "FROM %s\nRUN %s\n", busyboxPinnedRef, command)
	}))
	defer dockerfile.Close()
	contextURL := dockerfile.URL + "/Dockerfile"
	if host := os.Getenv("SOCKGUARD_FRONTEND_CONTEXT_HOST"); host != "" {
		contextURL = strings.Replace(contextURL, "127.0.0.1", host, 1)
	}
	approved := map[string]struct{}{}
	for _, step := range []string{"unapproved", "approved", "changed", "canceled"} {
		t.Run(step, func(t *testing.T) {
			changed.Store(step == "changed")
			policy := buildkitproxy.Policy{
				Control: buildkitproxy.ControlPolicy{Solve: buildkitproxy.SolvePolicy{Allow: true, AllowFrontendGateway: true, AllowRemoteContext: true, AllowedExecDigests: maps.Clone(approved), AllowedExporters: []string{"moby"}}},
				Session: buildkitproxy.SessionPolicy{Health: true, Auth: buildkitproxy.AuthPolicy{Allow: true, AllowedRegistries: []string{"docker.io"}}},
			}
			mediator := buildkitproxy.NewMediator(llbDaemonDialer{socket}, newIntegrationLogger())
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				key := buildkitproxy.SessionKey{ClientIdentity: "frontend-integration", Profile: "builder"}
				if r.URL.Path == "/session" {
					mediator.ServeSession(w, r, policy, key)
				} else {
					mediator.ServeGRPC(w, r, policy, key)
				}
			}))
			defer server.Close()
			var operations, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			var report io.Writer = &operations
			var cancellation *cancelOperationWriter
			var realDocker, nameFile string
			if step == "canceled" {
				cancellation = &cancelOperationWriter{Writer: &operations, cancel: cancel}
				report = cancellation
				realDocker, nameFile = captureFrontendName(t)
			}
			err := buildkitrunner.Run(ctx, buildkitrunner.Options{Host: server.URL, ExportName: imageName, Image: frontendPinnedRef, RuntimeContext: runtimeContext, FrontendOptions: []string{"context=" + contextURL, "image-resolve-mode=local", "force-network-mode=none"}, Operations: report, Stderr: &stderr})
			returnedAt := time.Now()
			if (err == nil) != (step == "approved") {
				t.Fatalf("step=%s err=%v frontend=%s operations=%s", step, err, stderr.String(), operations.String())
			}
			count, records := 0, 0
			decoder := json.NewDecoder(&operations)
			for decoder.More() {
				var record struct {
					Digest  string `json:"digest"`
					Encoded []byte `json:"encoded"`
				}
				if err := decoder.Decode(&record); err != nil {
					t.Fatal(err)
				}
				records++
				var op pb.Op
				if err := proto.Unmarshal(record.Encoded, &op); err != nil {
					t.Fatal(err)
				}
				if op.GetExec() != nil {
					count++
					if step == "unapproved" {
						approved[record.Digest] = struct{}{}
					}
					if step == "changed" {
						if _, ok := approved[record.Digest]; ok {
							t.Fatal("changed execution retained approval")
						}
					}
				}
			}
			if step == "canceled" {
				canceledAt := cancellation.cancellationTime()
				if validationErr := validateFrontendCancellation(ctx.Err(), err, canceledAt, returnedAt, records); validationErr != nil {
					t.Errorf("%v; frontend=%s", validationErr, stderr.String())
				}
				name, readErr := os.ReadFile(nameFile)
				if readErr != nil || !strings.HasPrefix(string(name), "sockguard-frontend-") || strings.ContainsAny(string(name), "\r\n") {
					t.Fatalf("frontend name was not captured: %q, %v", name, readErr)
				}
				cleanupCtx, stopCleanup := context.WithTimeout(context.Background(), 20*time.Second)
				defer stopCleanup()
				output, queryErr := exec.CommandContext(cleanupCtx, realDocker, "--context", runtimeContext, "container", "ls", "--all", "--filter", "name=^/"+string(name)+"$", "--format", "{{.ID}}").Output()
				if cleanupErr := validateFrontendAbsence(output, queryErr); cleanupErr != nil {
					t.Fatalf("frontend %s: %v", name, cleanupErr)
				}
				t.Logf("canceled after %d complete operation records; returned in %s; frontend %s is absent", records, returnedAt.Sub(canceledAt), name)
			}
			if step == "approved" || step == "changed" {
				output, err := exec.CommandContext(ctx, "docker", "--context", runtimeContext, "run", "--rm", "--name", checkName, "--network", "none", "--read-only", imageName, "cat", "/approved").CombinedOutput()
				if err != nil || string(output) != "approved\n" {
					t.Fatalf("approved image output=%q error=%v", output, err)
				}
			}
			if count == 0 && step != "canceled" {
				t.Fatalf("frontend did not submit an ExecOp: err=%v stderr=%s", err, stderr.String())
			}
		})
	}
}

// Cancellation occurs only after a live frontend submits its first operation.
type cancelOperationWriter struct {
	io.Writer
	cancel     context.CancelFunc
	mu         sync.Mutex
	canceledAt time.Time
}

func (w *cancelOperationWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.Writer.Write(p)
	if err == nil && n == len(p) && json.Valid(p) && bytes.HasSuffix(p, []byte("\n")) && w.canceledAt.IsZero() {
		w.canceledAt = time.Now()
		w.cancel()
	}
	return n, err
}

func TestCancelOperationWriterRequiresSuccessfulRecord(t *testing.T) {
	for _, tc := range []struct {
		name       string
		data       string
		writer     io.Writer
		wantCancel bool
	}{
		{"complete", "{\"digest\":\"sha256:abc\"}\n", io.Discard, true},
		{"partial", "{\"digest\":", io.Discard, false},
		{"failed", "{\"digest\":\"sha256:abc\"}\n", failedOperationWriter{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			w := &cancelOperationWriter{Writer: tc.writer, cancel: cancel}
			_, _ = w.Write([]byte(tc.data))
			if got := ctx.Err() != nil; got != tc.wantCancel {
				t.Fatalf("canceled = %v, want %v", got, tc.wantCancel)
			}
		})
	}
}

type failedOperationWriter struct{}

func (failedOperationWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func (w *cancelOperationWriter) cancellationTime() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.canceledAt
}

func validateFrontendCancellation(ctxErr, runErr error, canceledAt, returnedAt time.Time, records int) error {
	if canceledAt.IsZero() || records == 0 {
		return errors.New("cancellation callback did not deliver an operation record")
	}
	if !errors.Is(ctxErr, context.Canceled) {
		return fmt.Errorf("frontend context was not explicitly canceled: %w", ctxErr)
	}
	if !onlyCancellation(runErr) {
		return fmt.Errorf("frontend returned an unrelated or cleanup error: %w", runErr)
	}
	if elapsed := returnedAt.Sub(canceledAt); elapsed < 0 || elapsed > 20*time.Second {
		return fmt.Errorf("frontend cancellation took %s, limit 20s", elapsed)
	}
	return nil
}

func onlyCancellation(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyCancellation(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyCancellation(wrapped.Unwrap())
	}
	return errors.Is(err, context.Canceled)
}

func validateFrontendAbsence(output []byte, queryErr error) error {
	if queryErr != nil {
		return fmt.Errorf("independent cleanup query failed: %w", queryErr)
	}
	if strings.TrimSpace(string(output)) != "" {
		return fmt.Errorf("container survived cleanup: %s", output)
	}
	return nil
}

func captureFrontendName(t *testing.T) (string, string) {
	t.Helper()
	realDocker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	realDocker, err = filepath.Abs(realDocker)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	nameFile := filepath.Join(dir, "frontend-name")
	script := `#!/bin/sh
if [ "$3" = run ]; then
  previous=
  for argument in "$@"; do
    if [ "$previous" = --name ]; then printf '%s' "$argument" > "$FRONTEND_NAME_FILE"; fi
    previous="$argument"
  done
fi
exec "$FRONTEND_REAL_DOCKER" "$@"
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FRONTEND_REAL_DOCKER", realDocker)
	t.Setenv("FRONTEND_NAME_FILE", nameFile)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return realDocker, nameFile
}

func TestFrontendCancellationEvidence(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name           string
		ctxErr, runErr error
		canceledAt     time.Time
		records        int
		elapsed        time.Duration
		wantValid      bool
	}{
		{"complete", context.Canceled, errors.Join(context.Canceled), now, 1, time.Second, true},
		{"early startup", nil, errors.New("dial failed"), time.Time{}, 0, 0, false},
		{"deadline", context.DeadlineExceeded, context.DeadlineExceeded, now, 1, time.Second, false},
		{"cleanup failure", context.Canceled, errors.Join(context.Canceled, errors.New("cleanup failed")), now, 1, time.Second, false},
		{"nested cleanup failure", context.Canceled, fmt.Errorf("run: %w", errors.Join(context.Canceled, errors.New("cleanup failed"))), now, 1, time.Second, false},
		{"missing records", context.Canceled, context.Canceled, now, 0, time.Second, false},
		{"too slow", context.Canceled, context.Canceled, now, 1, 21 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFrontendCancellation(tc.ctxErr, tc.runErr, tc.canceledAt, now.Add(tc.elapsed), tc.records)
			if (err == nil) != tc.wantValid {
				t.Fatalf("validation error = %v, want valid %v", err, tc.wantValid)
			}
		})
	}
	for _, tc := range []struct {
		name, output string
		queryErr     error
		wantValid    bool
	}{
		{"absent", "", nil, true},
		{"query failed", "", errors.New("daemon unavailable"), false},
		{"survived", "abc123\n", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateFrontendAbsence([]byte(tc.output), tc.queryErr); (err == nil) != tc.wantValid {
				t.Fatalf("validation error = %v, want valid %v", err, tc.wantValid)
			}
		})
	}
}
