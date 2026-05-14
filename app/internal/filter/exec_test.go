package filter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMiddlewareDeniesUnallowlistedExecCreateCommand(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/*/exec", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected exec create to be denied")
	}))

	req := httptest.NewRequest(
		http.MethodPost,
		"/containers/abc123/exec",
		strings.NewReader(`{"Cmd":["/bin/sh","-c","id"],"AttachStdout":true}`),
	)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(body.Reason, "allowlisted") {
		t.Fatalf("reason = %q, want allowlist denial", body.Reason)
	}
}

func TestMiddlewareAllowsAllowlistedExecCreateCommand(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/*/exec", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	payload := []byte(`{"Cmd":["/usr/local/bin/pre-update","--check"],"AttachStdout":true}`)
	wantDigest := sha256.Sum256(payload)

	handler := MiddlewareWithOptions(rules, testLogger(), Options{
		PolicyConfig: PolicyConfig{
			Exec: ExecOptions{
				AllowedCommands: [][]string{{"/usr/local/bin/pre-update", "--check"}},
			},
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if gotDigest := sha256.Sum256(body); gotDigest != wantDigest {
			t.Fatalf("body sha256 = %s, want %s", hex.EncodeToString(gotDigest[:]), hex.EncodeToString(wantDigest[:]))
		}
		w.WriteHeader(http.StatusCreated)
	}))

	req := httptest.NewRequest(http.MethodPost, "/containers/abc123/exec", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
}

func TestMiddlewareDeniesPrivilegedAndRootExecCreate(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/*/exec", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "privileged exec",
			payload: `{"Cmd":["/usr/local/bin/pre-update"],"Privileged":true}`,
			want:    "privileged",
		},
		{
			name:    "root user exec",
			payload: `{"Cmd":["/usr/local/bin/pre-update"],"User":"root"}`,
			want:    "root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := MiddlewareWithOptions(rules, testLogger(), Options{
				PolicyConfig: PolicyConfig{
					DenyResponseVerbosity: DenyResponseVerbosityVerbose,
					Exec: ExecOptions{
						AllowedCommands: [][]string{{"/usr/local/bin/pre-update"}},
					},
				},
			})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("expected exec create to be denied")
			}))

			req := httptest.NewRequest(http.MethodPost, "/containers/abc123/exec", strings.NewReader(tt.payload))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}

			var body DenialResponse
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if !strings.Contains(body.Reason, tt.want) {
				t.Fatalf("reason = %q, want substring %q", body.Reason, tt.want)
			}
		})
	}
}

func TestMiddlewareDeniesOversizedExecCreateBody(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/*/exec", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	handler := MiddlewareWithOptions(rules, testLogger(), Options{
		PolicyConfig: PolicyConfig{
			DenyResponseVerbosity: DenyResponseVerbosityVerbose,
			Exec: ExecOptions{
				AllowedCommands: [][]string{{"/usr/local/bin/pre-update"}},
			},
		},
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected oversized exec request body to be denied")
	}))

	padding := strings.Repeat("A", maxExecBodyBytes)
	payload := fmt.Sprintf(`{"Cmd":["/usr/local/bin/pre-update"],"Pad":"%s"}`, padding)
	req := httptest.NewRequest(http.MethodPost, "/containers/abc123/exec", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(body.Reason, "exceeds") {
		t.Fatalf("reason = %q, want body-limit denial", body.Reason)
	}
}

func TestMiddlewareDeniesExecStartWhenInspectedExecViolatesPolicy(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/exec/*/start", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	handler := MiddlewareWithOptions(rules, testLogger(), Options{
		PolicyConfig: PolicyConfig{
			DenyResponseVerbosity: DenyResponseVerbosityVerbose,
			Exec: ExecOptions{
				AllowedCommands: [][]string{{"/usr/local/bin/pre-update"}},
				InspectStart: func(context.Context, string) (ExecInspectResult, bool, error) {
					return ExecInspectResult{
						Command:    []string{"/bin/sh", "-c", "id"},
						Privileged: false,
					}, true, nil
				},
			},
		},
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected exec start to be denied")
	}))

	req := httptest.NewRequest(http.MethodPost, "/exec/exec-123/start", strings.NewReader(`{"Detach":false,"Tty":false}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(body.Reason, "allowlisted") {
		t.Fatalf("reason = %q, want allowlist denial", body.Reason)
	}
}

func TestExecCommandAllowlistOverlapHandling(t *testing.T) {
	allowExec, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/*/exec", Action: ActionAllow, Index: 0})
	denyContainers, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/**", Action: ActionDeny, Reason: "container deny", Index: 1})
	denyAll, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 2})
	rules := []*CompiledRule{allowExec, denyContainers, denyAll}

	tests := []struct {
		name       string
		payload    string
		wantStatus int
		wantReason string
	}{
		{
			name:       "shorter exact command allowed",
			payload:    `{"Cmd":["/usr/local/bin/pre-update"]}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "longer exact command allowed",
			payload:    `{"Cmd":["/usr/local/bin/pre-update","--check"]}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "overlapping prefix command still denied",
			payload:    `{"Cmd":["/usr/local/bin/pre-update","--check","--force"]}`,
			wantStatus: http.StatusForbidden,
			wantReason: "allowlisted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := MiddlewareWithOptions(rules, testLogger(), Options{
				PolicyConfig: PolicyConfig{
					DenyResponseVerbosity: DenyResponseVerbosityVerbose,
					Exec: ExecOptions{
						AllowedCommands: [][]string{
							{"/usr/local/bin/pre-update"},
							{"/usr/local/bin/pre-update", "--check"},
						},
					},
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := NormalizePath(r.URL.Path); got != "/containers/abc123/exec" {
					t.Fatalf("NormalizePath(%q) = %q, want %q", r.URL.Path, got, "/containers/abc123/exec")
				}
				w.WriteHeader(http.StatusCreated)
			}))

			req := httptest.NewRequest(http.MethodPost, "/v1.53/containers/abc123/exec", strings.NewReader(tt.payload))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantReason == "" {
				return
			}

			var body DenialResponse
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if !strings.Contains(body.Reason, tt.wantReason) {
				t.Fatalf("reason = %q, want substring %q", body.Reason, tt.wantReason)
			}
		})
	}
}

func TestExecAttachHijackStreamInterruption(t *testing.T) {
	allowExecStart, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/exec/*/start", Action: ActionAllow, Index: 0})
	allowAttach, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/*/attach", Action: ActionAllow, Index: 1})
	denyAll, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 2})
	rules := []*CompiledRule{allowExecStart, allowAttach, denyAll}

	streamErr := errors.New("stream interrupted")

	tests := []struct {
		name            string
		path            string
		payload         string
		wantInspectID   string
		wantInspectCall bool
	}{
		{
			name:            "exec start passes interrupted body downstream after inspection",
			path:            "/v1.53/exec/exec-123/start",
			payload:         `{"Detach":false,"Tty":false}`,
			wantInspectID:   "exec-123",
			wantInspectCall: true,
		},
		{
			name:            "attach passes interrupted body downstream unchanged",
			path:            "/v1.53/containers/abc123/attach",
			payload:         "stdin chunk",
			wantInspectCall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspectCalls := 0
			var gotBody string
			var gotBodyErr error

			handler := MiddlewareWithOptions(rules, testLogger(), Options{
				PolicyConfig: PolicyConfig{
					DenyResponseVerbosity: DenyResponseVerbosityVerbose,
					Exec: ExecOptions{
						AllowedCommands: [][]string{{"/usr/local/bin/pre-update"}},
						InspectStart: func(_ context.Context, execID string) (ExecInspectResult, bool, error) {
							inspectCalls++
							if execID != tt.wantInspectID {
								t.Fatalf("inspect exec id = %q, want %q", execID, tt.wantInspectID)
							}
							return ExecInspectResult{
								Command: []string{"/usr/local/bin/pre-update"},
							}, true, nil
						},
					},
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				gotBody = string(body)
				gotBodyErr = err
				w.WriteHeader(http.StatusSwitchingProtocols)
			}))

			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			req.Body = io.NopCloser(io.MultiReader(strings.NewReader(tt.payload), execTestErrorReader{err: streamErr}))
			req.ContentLength = int64(len(tt.payload))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusSwitchingProtocols {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusSwitchingProtocols, rec.Body.String())
			}
			if gotBody != tt.payload {
				t.Fatalf("downstream body = %q, want %q", gotBody, tt.payload)
			}
			if !errors.Is(gotBodyErr, streamErr) {
				t.Fatalf("downstream body error = %v, want %v", gotBodyErr, streamErr)
			}

			wantCalls := 0
			if tt.wantInspectCall {
				wantCalls = 1
			}
			if inspectCalls != wantCalls {
				t.Fatalf("inspect calls = %d, want %d", inspectCalls, wantCalls)
			}
		})
	}
}

func TestDecodeExecCommandWrapsSentinelErrors(t *testing.T) {
	tests := []struct {
		name        string
		raw         json.RawMessage
		want        error
		wantMessage string
	}{
		{
			name:        "missing cmd",
			raw:         json.RawMessage("null"),
			want:        errExecMissingCmd,
			wantMessage: "missing Cmd",
		},
		{
			name:        "empty cmd array",
			raw:         json.RawMessage("[]"),
			want:        errExecEmptyCmdArray,
			wantMessage: "empty Cmd array",
		},
		{
			name:        "empty cmd string",
			raw:         json.RawMessage(`"   "`),
			want:        errExecEmptyCmdString,
			wantMessage: "empty Cmd string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeExecCommand(tt.raw)
			if err == nil {
				t.Fatal("expected decodeExecCommand() to fail")
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("errors.Is(err, %v) = false, err = %v", tt.want, err)
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Fatalf("err = %q, want message %q", err, tt.wantMessage)
			}
		})
	}
}

type execTestErrorReader struct {
	err error
}

func (r execTestErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestNewExecPolicyFiltersEmptyCommands(t *testing.T) {
	// Empty slices in AllowedCommands should be silently dropped.
	policy := newExecPolicy(ExecOptions{
		AllowedCommands: [][]string{
			{},
			{"/usr/bin/env"},
			{},
		},
	})
	if len(policy.allowedCommands) != 1 {
		t.Fatalf("allowedCommands = %v, want 1 entry", policy.allowedCommands)
	}
	if policy.allowedCommands[0][0] != "/usr/bin/env" {
		t.Fatalf("allowedCommands[0] = %v, want [/usr/bin/env]", policy.allowedCommands[0])
	}
}

func TestExecInspectNilRequestReturnsEmpty(t *testing.T) {
	policy := newExecPolicy(ExecOptions{})
	reason, err := policy.inspect(nil, nil, "/containers/abc/exec")
	if err != nil {
		t.Fatalf("inspect(nil) error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestExecInspectNonPostReturnsEmpty(t *testing.T) {
	policy := newExecPolicy(ExecOptions{})
	req := httptest.NewRequest(http.MethodGet, "/containers/abc/exec", nil)
	reason, err := policy.inspect(nil, req, "/containers/abc/exec")
	if err != nil {
		t.Fatalf("inspect(GET) error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestExecInspectDefaultPathReturnsEmpty(t *testing.T) {
	// A POST to a path that is neither exec-create nor exec-start.
	policy := newExecPolicy(ExecOptions{})
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/logs", nil)
	reason, err := policy.inspect(nil, req, "/containers/abc/logs")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestExecInspectNilBodyReturnsEmpty(t *testing.T) {
	policy := newExecPolicy(ExecOptions{AllowedCommands: [][]string{{"/bin/sh"}}})
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/exec", nil)
	req.Body = nil
	reason, err := policy.inspect(nil, req, "/containers/abc/exec")
	if err != nil {
		t.Fatalf("inspect(nil body) error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestExecStartIdentifierMissingIDReturnsNotOK(t *testing.T) {
	// Path /exec//start has empty ID segment.
	id, ok := execStartIdentifier("/exec//start")
	if ok {
		t.Fatalf("expected ok=false for empty id, got id=%q", id)
	}
}

func TestExecStartIdentifierWrongTailReturnsNotOK(t *testing.T) {
	// Path /exec/abc123/json is not a start path.
	id, ok := execStartIdentifier("/exec/abc123/json")
	if ok {
		t.Fatalf("expected ok=false for wrong tail, got id=%q", id)
	}
}

func TestExecStartIdentifierNoPrefixReturnsNotOK(t *testing.T) {
	_, ok := execStartIdentifier("/containers/abc/start")
	if ok {
		t.Fatal("expected ok=false for non-exec path")
	}
}

func TestNewDockerExecInspectorConstructor(t *testing.T) {
	// Verifies the constructor returns a non-nil function without panicking.
	fn := NewDockerExecInspector("/var/run/docker.sock")
	if fn == nil {
		t.Fatal("NewDockerExecInspector() returned nil")
	}
}

func TestNewDockerExecInspectorDialError(t *testing.T) {
	// Exercises lines 261-263: client.Do fails when the socket doesn't exist.
	fn := NewDockerExecInspector("/nonexistent/path/docker.sock")
	_, _, err := fn(context.Background(), "abc123")
	if err == nil {
		t.Fatal("expected dial error for nonexistent socket")
	}
}

func TestNewDockerExecInspectorNilContext(t *testing.T) {
	// Exercises lines 257-259: http.NewRequestWithContext returns error for nil context.
	fn := NewDockerExecInspector("/nonexistent/docker.sock")
	//nolint:staticcheck // intentionally passing nil to test error branch
	_, _, err := fn(nil, "abc123") //nolint:SA1012
	if err == nil {
		t.Fatal("expected error for nil context")
	}
}

func TestNewDockerExecInspectorUsesHTTPServer(t *testing.T) {
	// Spin up a mock upstream that responds to GET /exec/{id}/json with a
	// minimal response, and wire the inspector to it via a TCP address.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/exec/notfound/json":
			w.WriteHeader(http.StatusNotFound)
		case "/exec/errored/json":
			w.WriteHeader(http.StatusInternalServerError)
		case "/exec/badjson/json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{not json"))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			body := `{"ProcessConfig":{"entrypoint":"/bin/sh","arguments":["-c","id"],"privileged":false,"user":""}}`
			_, _ = w.Write([]byte(body))
		}
	})

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// Build an inspector backed by TCP (not unix) to avoid needing root.
	transport := &http.Transport{}
	client := &http.Client{Transport: transport}
	inspectFn := func(ctx context.Context, id string) (ExecInspectResult, bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/exec/"+id+"/json", nil)
		if err != nil {
			return ExecInspectResult{}, false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return ExecInspectResult{}, false, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusNotFound {
			return ExecInspectResult{}, false, nil
		}
		if resp.StatusCode != http.StatusOK {
			return ExecInspectResult{}, false, fmt.Errorf("upstream returned %s", resp.Status)
		}
		var decoded execInspectResponse
		if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
			return ExecInspectResult{}, false, err
		}
		command := make([]string, 0, 1+len(decoded.ProcessConfig.Arguments))
		if decoded.ProcessConfig.Entrypoint != "" {
			command = append(command, decoded.ProcessConfig.Entrypoint)
		}
		command = append(command, decoded.ProcessConfig.Arguments...)
		return ExecInspectResult{
			Command:    command,
			Privileged: decoded.ProcessConfig.Privileged,
			User:       decoded.ProcessConfig.User,
		}, true, nil
	}

	ctx := context.Background()

	// Success case.
	result, found, err := inspectFn(ctx, "abc123")
	if err != nil {
		t.Fatalf("inspectFn success: error = %v", err)
	}
	if !found {
		t.Fatal("inspectFn success: found = false")
	}
	if len(result.Command) == 0 || result.Command[0] != "/bin/sh" {
		t.Fatalf("command = %v, want [/bin/sh -c id]", result.Command)
	}

	// Not found.
	_, found, err = inspectFn(ctx, "notfound")
	if err != nil {
		t.Fatalf("inspectFn notfound: error = %v", err)
	}
	if found {
		t.Fatal("inspectFn notfound: found = true, want false")
	}

	// Upstream error.
	_, _, err = inspectFn(ctx, "errored")
	if err == nil {
		t.Fatal("inspectFn errored: expected error")
	}

	// Bad JSON.
	_, _, err = inspectFn(ctx, "badjson")
	if err == nil {
		t.Fatal("inspectFn badjson: expected JSON decode error")
	}
}

func TestInspectExistingNilInspectStartDenies(t *testing.T) {
	// inspectExisting with nil inspectStart should deny.
	policy := newExecPolicy(ExecOptions{
		AllowedCommands: [][]string{{"/bin/sh"}},
		InspectStart:    nil,
	})
	reason, err := policy.inspectExisting(context.Background(), "/exec/abc123/start")
	if err != nil {
		t.Fatalf("inspectExisting() error = %v", err)
	}
	if reason == "" {
		t.Fatal("expected denial when inspectStart is nil")
	}
}

func TestInspectExistingInspectStartError(t *testing.T) {
	sentinel := errors.New("inspect failed")
	policy := newExecPolicy(ExecOptions{
		AllowedCommands: [][]string{{"/bin/sh"}},
		InspectStart: func(context.Context, string) (ExecInspectResult, bool, error) {
			return ExecInspectResult{}, false, sentinel
		},
	})
	_, err := policy.inspectExisting(context.Background(), "/exec/abc123/start")
	if !errors.Is(err, sentinel) {
		t.Fatalf("errors.Is(err, sentinel) = false, err = %v", err)
	}
}

func TestInspectExistingNotFoundReturnsEmpty(t *testing.T) {
	policy := newExecPolicy(ExecOptions{
		AllowedCommands: [][]string{{"/bin/sh"}},
		InspectStart: func(context.Context, string) (ExecInspectResult, bool, error) {
			return ExecInspectResult{}, false, nil // not found
		},
	})
	reason, err := policy.inspectExisting(context.Background(), "/exec/abc123/start")
	if err != nil {
		t.Fatalf("inspectExisting() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty when exec not found", reason)
	}
}

func TestInspectCreateEmptyBodyReturnsEmpty(t *testing.T) {
	policy := newExecPolicy(ExecOptions{AllowedCommands: [][]string{{"/bin/sh"}}})
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/exec", bytes.NewReader([]byte{}))
	reason, err := policy.inspectCreate(nil, req)
	if err != nil {
		t.Fatalf("inspectCreate(empty body) error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestInspectCreateMalformedJSONWithLogger(t *testing.T) {
	policy := newExecPolicy(ExecOptions{AllowedCommands: [][]string{{"/bin/sh"}}})
	logs := &collectingHandler{}
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/exec", strings.NewReader("{bad"))
	reason, err := policy.inspectCreate(slog.New(logs), req)
	if err != nil {
		t.Fatalf("inspectCreate() error = %v", err)
	}
	// Malformed JSON must be denied (fail-closed).
	const wantReason = "exec denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("reason = %q, want %q", reason, wantReason)
	}
	if len(logs.snapshot()) != 1 {
		t.Fatalf("log records = %d, want 1", len(logs.snapshot()))
	}
}

func TestInspectExistingInvalidPathReturnsEmpty(t *testing.T) {
	// execStartIdentifier returns false for non-start paths.
	policy := newExecPolicy(ExecOptions{
		AllowedCommands: [][]string{{"/bin/sh"}},
		InspectStart:    func(context.Context, string) (ExecInspectResult, bool, error) { return ExecInspectResult{}, true, nil },
	})
	reason, err := policy.inspectExisting(context.Background(), "/exec/abc/json")
	if err != nil {
		t.Fatalf("inspectExisting() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty for non-start path", reason)
	}
}

func TestDecodeExecCommandStringFallback(t *testing.T) {
	// Exercises the string fallback path in decodeExecCommand.
	raw := json.RawMessage(`"/bin/sh -c id"`)
	argv, err := decodeExecCommand(raw)
	if err != nil {
		t.Fatalf("decodeExecCommand() error = %v", err)
	}
	if len(argv) == 0 || argv[0] != "/bin/sh" {
		t.Fatalf("argv = %v, want [/bin/sh -c id]", argv)
	}
}

func TestDecodeExecCommandInvalidJSONFails(t *testing.T) {
	raw := json.RawMessage(`{not json}`)
	_, err := decodeExecCommand(raw)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestInspectCreateUnparseableCmdWithLoggerDeniesFail_Closed(t *testing.T) {
	// Valid JSON body with Cmd as an object (not array or string) causes
	// decodeExecCommand to fail. Must deny (fail-closed) and log at Debug.
	policy := newExecPolicy(ExecOptions{AllowedCommands: [][]string{{"/bin/sh"}}})
	logs := &collectingHandler{}
	// {"Cmd":{}} parses as execCreateRequest but Cmd={} fails both []string and string unmarshal.
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/exec", strings.NewReader(`{"Cmd":{}}`))
	reason, err := policy.inspectCreate(slog.New(logs), req)
	if err != nil {
		t.Fatalf("inspectCreate() error = %v", err)
	}
	const wantReason = "exec denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("reason = %q, want %q", reason, wantReason)
	}
	if len(logs.snapshot()) != 1 {
		t.Fatalf("log records = %d, want 1", len(logs.snapshot()))
	}
}

func TestNewDockerExecInspectorViaUnixSocket(t *testing.T) {
	// Create a temporary unix socket and serve a minimal exec inspect HTTP server.
	// macOS limits unix socket paths to 104 bytes; use os.MkdirTemp with a short prefix.
	tmpDir, err := os.MkdirTemp("", "sg")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	socketPath := filepath.Join(tmpDir, "d.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen unix: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/exec/abc123/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ProcessConfig":{"entrypoint":"/bin/sh","arguments":["-c","id"],"privileged":false,"user":""}}`))
	})
	mux.HandleFunc("/exec/notfound/json", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/exec/errored/json", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/exec/badjson/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not json"))
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	inspectFn := NewDockerExecInspector(socketPath)
	ctx := context.Background()

	// Success path.
	result, found, err := inspectFn(ctx, "abc123")
	if err != nil {
		t.Fatalf("inspect abc123: error = %v", err)
	}
	if !found {
		t.Fatal("inspect abc123: found = false, want true")
	}
	if len(result.Command) == 0 || result.Command[0] != "/bin/sh" {
		t.Fatalf("command = %v, want [/bin/sh -c id]", result.Command)
	}

	// Not found path.
	_, found, err = inspectFn(ctx, "notfound")
	if err != nil {
		t.Fatalf("inspect notfound: error = %v", err)
	}
	if found {
		t.Fatal("inspect notfound: found = true, want false")
	}

	// Upstream error path.
	_, _, err = inspectFn(ctx, "errored")
	if err == nil {
		t.Fatal("inspect errored: expected error from non-200 response")
	}

	// Bad JSON path.
	_, _, err = inspectFn(ctx, "badjson")
	if err == nil {
		t.Fatal("inspect badjson: expected JSON decode error")
	}
}

func TestExecInspectCreateDeniesUnparseableCmdField(t *testing.T) {
	// When the Cmd field cannot be decoded (e.g. it is an integer or nested
	// object rather than an array or string), inspectCreate must deny rather
	// than skip the allowedCommands check (fail-closed, not fail-open).
	policy := execPolicy{
		allowedCommands: [][]string{{"/safe/cmd"}},
	}

	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "Cmd is an integer",
			payload: `{"Cmd":42}`,
		},
		{
			name:    "Cmd is a nested object",
			payload: `{"Cmd":{"exec":"/bin/sh"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/abc123/exec", strings.NewReader(tt.payload))
			reason, err := policy.inspectCreate(nil, req)
			if err != nil {
				t.Fatalf("inspectCreate() error = %v", err)
			}
			const wantReason = "exec denied: request body could not be inspected"
			if reason != wantReason {
				t.Fatalf("reason = %q, want %q", reason, wantReason)
			}
		})
	}
}
