package filter

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNodeInspectDeniesRoleChangesByDefault(t *testing.T) {
	policy := newNodePolicy(NodeOptions{})
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-1/update?version=42", strings.NewReader(`{"Role":"manager"}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "node update denied: role changes are not allowed" {
		t.Fatalf("denyReason = %q, want role denial", denyReason)
	}
}

func TestNodeInspectDeniesAvailabilityChangesByDefault(t *testing.T) {
	policy := newNodePolicy(NodeOptions{})
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-1/update?version=42", strings.NewReader(`{"Availability":"drain"}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "node update denied: availability changes are not allowed" {
		t.Fatalf("denyReason = %q, want availability denial", denyReason)
	}
}

func TestNodeInspectDeniesNameChangesByDefault(t *testing.T) {
	policy := newNodePolicy(NodeOptions{})
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-1/update?version=42", strings.NewReader(`{"Name":"node-renamed"}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "node update denied: name changes are not allowed" {
		t.Fatalf("denyReason = %q, want name denial", denyReason)
	}
}

func TestNodeInspectDeniesArbitraryLabelMutationByDefault(t *testing.T) {
	policy := newNodePolicy(NodeOptions{})
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-1/update?version=42", strings.NewReader(`{"Labels":{"env":"prod"}}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "node update denied: label mutation is not allowed" {
		t.Fatalf("denyReason = %q, want label mutation denial", denyReason)
	}
}

func TestNodeInspectAllowsSpecFieldChangesWhenConfigured(t *testing.T) {
	tests := []struct {
		name string
		opts NodeOptions
		body string
	}{
		{
			name: "role",
			opts: NodeOptions{AllowRoleChange: true},
			body: `{"Role":"manager"}`,
		},
		{
			name: "availability",
			opts: NodeOptions{AllowAvailabilityChange: true},
			body: `{"Availability":"drain"}`,
		},
		{
			name: "name",
			opts: NodeOptions{AllowNameChange: true},
			body: `{"Name":"node-renamed"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newNodePolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPost, "/nodes/node-1/update?version=42", strings.NewReader(tt.body))

			denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if denyReason != "" {
				t.Fatalf("denyReason = %q, want allow", denyReason)
			}
		})
	}
}

func TestNodeInspectAllowsConfiguredLabelKeyAndPreservesBody(t *testing.T) {
	policy := newNodePolicy(NodeOptions{
		AllowedLabelKeys: []string{"com.example.safe"},
	})
	payload := []byte(`{"Labels":{"com.example.safe":"value"}}`)
	req := httptest.NewRequest(http.MethodPost, "/v1.54/nodes/node-1/update?version=42", bytes.NewReader(payload))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "" {
		t.Fatalf("denyReason = %q, want allow", denyReason)
	}

	body, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		t.Fatalf("ReadAll() error = %v", readErr)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("body = %q, want %q", string(body), string(payload))
	}
}

func TestNodeInspectAllowsDefaultOwnerLabelPattern(t *testing.T) {
	policy := newNodePolicy(NodeOptions{})
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-1/update?version=42", strings.NewReader(`{"Labels":{"com.sockguard.owner":"job-123"}}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "" {
		t.Fatalf("denyReason = %q, want allow", denyReason)
	}
}

func TestNodeInspectDeniesExtraLabelsWithConfiguredLabelKey(t *testing.T) {
	policy := newNodePolicy(NodeOptions{
		AllowedLabelKeys: []string{"com.sockguard.owner"},
	})
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-1/update?version=42", strings.NewReader(`{
		"Labels": {
			"com.sockguard.owner": "job-123",
			"env": "prod"
		}
	}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "node update denied: label mutation is not allowed" {
		t.Fatalf("denyReason = %q, want label mutation denial", denyReason)
	}
}

func TestNodeInspectAllowsArbitraryLabelsWhenConfigured(t *testing.T) {
	policy := newNodePolicy(NodeOptions{AllowLabelMutation: true})
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-1/update?version=42", strings.NewReader(`{"Labels":{"env":"prod"}}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "" {
		t.Fatalf("denyReason = %q, want allow", denyReason)
	}
}

func TestNodeInspectMalformedJSONWithLogger(t *testing.T) {
	logs := &collectingHandler{}
	logger := slog.New(logs)
	policy := newNodePolicy(NodeOptions{})

	req := httptest.NewRequest(http.MethodPost, "/nodes/node-1/update?version=42", strings.NewReader("{bad json"))
	reason, err := policy.inspect(logger, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty (deferred to Docker)", reason)
	}
	if len(logs.snapshot()) != 1 {
		t.Fatalf("log records = %d, want 1", len(logs.snapshot()))
	}
}

func TestNodeInspectNilAndNonPostRequestsReturnEmpty(t *testing.T) {
	policy := newNodePolicy(NodeOptions{})

	tests := []struct {
		name           string
		req            *http.Request
		normalizedPath string
	}{
		{name: "nil request", req: nil, normalizedPath: "/nodes/node-1/update"},
		{name: "non-post", req: httptest.NewRequest(http.MethodGet, "/nodes/node-1/update", strings.NewReader(`{"Name":"node-1"}`)), normalizedPath: "/nodes/node-1/update"},
		{name: "non-node-update", req: httptest.NewRequest(http.MethodPost, "/nodes/node-1", strings.NewReader(`{"Name":"node-1"}`)), normalizedPath: "/nodes/node-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, err := policy.inspect(nil, tt.req, tt.normalizedPath)
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "" {
				t.Fatalf("reason = %q, want empty", reason)
			}
		})
	}
}

func TestNodeInspectReadBodyError(t *testing.T) {
	policy := newNodePolicy(NodeOptions{})
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-1/update", nil)
	req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}

	reason, err := policy.inspect(nil, req, "/nodes/node-1/update")
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("inspect() error = %v, want wrapped unexpected EOF", err)
	}
}

func TestNodeInspectOversizedBody(t *testing.T) {
	policy := newNodePolicy(NodeOptions{})
	payload := strings.Repeat("x", maxNodeBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-1/update", strings.NewReader(payload))

	reason, err := policy.inspect(nil, req, "/nodes/node-1/update")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason == "" || !strings.HasPrefix(reason, "node update denied: request body exceeds") {
		t.Fatalf("reason = %q, want oversized body denial", reason)
	}
}

func TestMiddlewareDeniesNodeUpdateNameChangeWhenRuleAllows(t *testing.T) {
	rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/nodes/*/update", Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	handler := verboseMiddleware([]*CompiledRule{rule}, testLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected node update to be denied before reaching inner handler")
	}))

	req := httptest.NewRequest(http.MethodPost, "/nodes/node-1/update?version=42", strings.NewReader(`{"Name":"node-renamed"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Reason != "node update denied: name changes are not allowed" {
		t.Fatalf("reason = %q, want name denial", body.Reason)
	}
}
