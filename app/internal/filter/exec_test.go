package filter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
		Exec: ExecOptions{
			AllowedCommands: [][]string{{"/usr/local/bin/pre-update", "--check"}},
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
				DenyResponseVerbosity: DenyResponseVerbosityVerbose,
				Exec: ExecOptions{
					AllowedCommands: [][]string{{"/usr/local/bin/pre-update"}},
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

func TestMiddlewareDeniesExecStartWhenInspectedExecViolatesPolicy(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/exec/*/start", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	handler := MiddlewareWithOptions(rules, testLogger(), Options{
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
