package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSwarmInspectDeniesForceNewCluster(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})

	req := httptest.NewRequest(http.MethodPost, "/swarm/init", strings.NewReader(`{
		"ListenAddr": "0.0.0.0:2377",
		"ForceNewCluster": true
	}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "swarm init denied: force-new-cluster is not allowed" {
		t.Fatalf("denyReason = %q, want force-new-cluster denial", denyReason)
	}
}

func TestSwarmInspectDeniesExternalCA(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})

	req := httptest.NewRequest(http.MethodPost, "/swarm/init", strings.NewReader(`{
		"Spec": {
			"CAConfig": {
				"ExternalCAs": [
					{"Protocol": "cfssl", "URL": "https://ca.example.com"}
				]
			}
		}
	}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "swarm init denied: external CAs are not allowed" {
		t.Fatalf("denyReason = %q, want external CA denial", denyReason)
	}
}

func TestSwarmInspectAllowsDefaultInit(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})

	req := httptest.NewRequest(http.MethodPost, "/v1.53/swarm/init", strings.NewReader(`{
		"ListenAddr": "0.0.0.0:2377",
		"AdvertiseAddr": "10.0.0.10:2377"
	}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "" {
		t.Fatalf("denyReason = %q, want allow", denyReason)
	}
}

func TestSwarmInspectJoinAllowsAndPreservesBody(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{
		AllowedJoinRemoteAddrs: []string{"10.0.0.11:2377"},
	})

	payload := []byte(`{
		"ListenAddr": "0.0.0.0:2377",
		"AdvertiseAddr": "10.0.0.10:2377",
		"DataPathAddr": "10.0.0.10",
		"RemoteAddrs": ["10.0.0.11:2377"],
		"JoinToken": "SWMTKN-1-join"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/swarm/join", bytes.NewReader(payload))

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
	if string(body) != string(payload) {
		t.Fatalf("body = %q, want %q", string(body), string(payload))
	}
}

func TestSwarmInspectJoinDeniesUnallowlistedRemoteAddr(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{
		AllowedJoinRemoteAddrs: []string{"manager.internal:2377"},
	})

	req := httptest.NewRequest(http.MethodPost, "/swarm/join", strings.NewReader(`{
		"RemoteAddrs": ["10.0.0.11:2377"],
		"JoinToken": "SWMTKN-1-join"
	}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != `swarm join denied: remote address "10.0.0.11:2377" is not allowlisted` {
		t.Fatalf("denyReason = %q", denyReason)
	}
}

func TestSwarmInspectUpdateDeniesExternalCA(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})

	req := httptest.NewRequest(http.MethodPost, "/swarm/update?version=42&rotateWorkerToken=true", strings.NewReader(`{
		"CAConfig": {
			"ExternalCAs": [
				{"Protocol": "cfssl", "URL": "https://ca.example.com"}
			]
		}
	}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "swarm update denied: external CAs are not allowed" {
		t.Fatalf("denyReason = %q, want external CA denial", denyReason)
	}
}

func TestSwarmInspectUpdateAllowsAndPreservesBody(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})

	payload := []byte(`{
		"CAConfig": {
			"NodeCertExpiry": 7776000000000000
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/v1.54/swarm/update?version=42", bytes.NewReader(payload))

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
	if !json.Valid(body) {
		t.Fatalf("restored body is not valid JSON: %q", string(body))
	}
}

func TestSwarmInspectUpdateDeniesTokenRotation(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})

	req := httptest.NewRequest(http.MethodPost, "/swarm/update?version=42&rotateWorkerToken=true", strings.NewReader(`{}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "swarm update denied: worker token rotation is not allowed" {
		t.Fatalf("denyReason = %q", denyReason)
	}
}

func TestSwarmInspectUpdateDeniesManagerUnlockKeyRotation(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})

	req := httptest.NewRequest(http.MethodPost, "/swarm/update?version=42&rotateManagerUnlockKey=1", strings.NewReader(`{}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "swarm update denied: manager unlock key rotation is not allowed" {
		t.Fatalf("denyReason = %q", denyReason)
	}
}

func TestSwarmInspectUpdateDeniesAutoLockManagers(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})

	req := httptest.NewRequest(http.MethodPost, "/swarm/update?version=42", strings.NewReader(`{
		"EncryptionConfig": {
			"AutoLockManagers": true
		}
	}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "swarm update denied: manager autolock is not allowed" {
		t.Fatalf("denyReason = %q", denyReason)
	}
}

func TestSwarmInspectUpdateDeniesSigningCAUpdate(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})

	req := httptest.NewRequest(http.MethodPost, "/swarm/update?version=42", strings.NewReader(`{
		"CAConfig": {
			"SigningCACert": "-----BEGIN CERTIFICATE-----"
		}
	}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "swarm update denied: signing CA updates are not allowed" {
		t.Fatalf("denyReason = %q", denyReason)
	}
}

func TestSwarmInspectUnlockDeniedByDefaultAndPreservesBody(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})
	const unlockKey = "SWMKEY-1-secret"
	payload := []byte(`{"UnlockKey":"` + unlockKey + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/swarm/unlock", bytes.NewReader(payload))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "swarm unlock denied: swarm unlock is not allowed" {
		t.Fatalf("denyReason = %q, want unlock denial", denyReason)
	}
	if strings.Contains(denyReason, unlockKey) {
		t.Fatalf("denyReason leaks unlock key: %q", denyReason)
	}

	body, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		t.Fatalf("ReadAll() error = %v", readErr)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("body = %q, want %q", string(body), string(payload))
	}
}

func TestSwarmInspectUnlockAllowsWhenConfigured(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{AllowUnlock: true})
	payload := []byte(`{"UnlockKey":"SWMKEY-1-secret"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1.54/swarm/unlock", bytes.NewReader(payload))

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

func TestSwarmInspectUnlockMalformedJSONDefersWithoutLoggingKey(t *testing.T) {
	logs := &collectingHandler{}
	logger := slog.New(logs)
	policy := newSwarmPolicy(SwarmOptions{})
	const unlockKey = "SWMKEY-1-secret"

	req := httptest.NewRequest(http.MethodPost, "/swarm/unlock", strings.NewReader(`{"UnlockKey":"`+unlockKey+`",`))
	reason, err := policy.inspect(logger, req, "/swarm/unlock")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty (deferred to Docker)", reason)
	}

	records := logs.snapshot()
	if len(records) != 1 {
		t.Fatalf("log records = %d, want 1", len(records))
	}
	recordText := records[0].message
	for key, value := range records[0].attrs {
		recordText += " " + key + "=" + fmt.Sprint(value)
	}
	if strings.Contains(recordText, unlockKey) {
		t.Fatalf("debug log leaks unlock key: %q", recordText)
	}
}

func TestMiddlewareDeniesSwarmUnlockByDefaultWhenRuleAllows(t *testing.T) {
	rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/swarm/unlock", Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	handler := verboseMiddleware([]*CompiledRule{rule}, testLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected swarm unlock to be denied before reaching inner handler")
	}))

	req := httptest.NewRequest(http.MethodPost, "/swarm/unlock", strings.NewReader(`{"UnlockKey":"SWMKEY-1-secret"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Reason != "swarm unlock denied: swarm unlock is not allowed" {
		t.Fatalf("reason = %q, want unlock denial", body.Reason)
	}
	if strings.Contains(rec.Body.String(), "SWMKEY-1-secret") {
		t.Fatalf("response leaks unlock key: %q", rec.Body.String())
	}
}

func TestMiddlewareAllowsSwarmUnlockWhenConfigured(t *testing.T) {
	rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/swarm/unlock", Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	reached := false
	handler := MiddlewareWithOptions([]*CompiledRule{rule}, testLogger(), Options{
		PolicyConfig: PolicyConfig{
			Swarm: SwarmOptions{AllowUnlock: true},
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/swarm/unlock", strings.NewReader(`{"UnlockKey":"SWMKEY-1-secret"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if !reached {
		t.Fatal("inner handler was not reached")
	}
}

func TestSwarmInspectNilRequestReturnsEmpty(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})
	reason, err := policy.inspect(nil, nil, "/swarm/init")
	if err != nil {
		t.Fatalf("inspect(nil) error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestSwarmInspectNonPostReturnsEmpty(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})
	req := httptest.NewRequest(http.MethodGet, "/swarm/init", strings.NewReader(`{}`))
	reason, err := policy.inspect(nil, req, "/swarm/init")
	if err != nil {
		t.Fatalf("inspect(GET) error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestSwarmInspectNilBodyReturnsEmpty(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})
	req := httptest.NewRequest(http.MethodPost, "/swarm/init", nil)
	req.Body = nil
	reason, err := policy.inspect(nil, req, "/swarm/init")
	if err != nil {
		t.Fatalf("inspect(nil body) error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestSwarmInspectDefaultPathReturnsEmpty(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})
	req := httptest.NewRequest(http.MethodPost, "/swarm/leave", strings.NewReader(`{}`))
	reason, err := policy.inspect(nil, req, "/swarm/leave")
	if err != nil {
		t.Fatalf("inspect(/swarm/leave) error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestSwarmInspectInitDeniesSigningCAUpdate(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})

	req := httptest.NewRequest(http.MethodPost, "/swarm/init", strings.NewReader(`{
		"Spec": {
			"CAConfig": {
				"ForceRotate": 1
			}
		}
	}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "swarm init denied: signing CA updates are not allowed" {
		t.Fatalf("denyReason = %q, want signing CA denial", denyReason)
	}
}

func TestSwarmInspectInitEmptyBodyReturnsEmpty(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})
	req := httptest.NewRequest(http.MethodPost, "/swarm/init", strings.NewReader(""))
	reason, err := policy.inspect(nil, req, "/swarm/init")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestSwarmInspectJoinEmptyBodyReturnsEmpty(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})
	req := httptest.NewRequest(http.MethodPost, "/swarm/join", strings.NewReader(""))
	reason, err := policy.inspect(nil, req, "/swarm/join")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestSwarmInspectUpdateEmptyBodyReturnsEmpty(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{AllowTokenRotation: true})
	req := httptest.NewRequest(http.MethodPost, "/swarm/update", strings.NewReader(""))
	reason, err := policy.inspect(nil, req, "/swarm/update")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestSwarmInspectUpdateDeniesManagerTokenRotation(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})
	req := httptest.NewRequest(http.MethodPost, "/swarm/update?version=42&rotateManagerToken=true", strings.NewReader(`{}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "swarm update denied: manager token rotation is not allowed" {
		t.Fatalf("denyReason = %q, want manager token rotation denial", denyReason)
	}
}

func TestNormalizeSwarmRemoteAddrsDeduplicates(t *testing.T) {
	input := []string{"10.0.0.1:2377", "  10.0.0.1:2377  ", "10.0.0.2:2377"}
	got := normalizeSwarmRemoteAddrs(input)
	if len(got) != 2 {
		t.Fatalf("normalizeSwarmRemoteAddrs() = %v, want 2 unique entries", got)
	}
}

func TestNormalizeSwarmRemoteAddrsSkipsEmpty(t *testing.T) {
	input := []string{"  ", "", "10.0.0.1:2377"}
	got := normalizeSwarmRemoteAddrs(input)
	if len(got) != 1 || got[0] != "10.0.0.1:2377" {
		t.Fatalf("normalizeSwarmRemoteAddrs() = %v, want [10.0.0.1:2377]", got)
	}
}

func TestSwarmInspectInitMalformedJSONWithLogger(t *testing.T) {
	// Exercises the logger != nil branch in inspectInit decode error path.
	policy := newSwarmPolicy(SwarmOptions{})
	logs := &collectingHandler{}
	logger := slog.New(logs)

	req := httptest.NewRequest(http.MethodPost, "/swarm/init", strings.NewReader("{bad json"))
	reason, err := policy.inspect(logger, req, "/swarm/init")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty (deferred to Docker)", reason)
	}

	records := logs.snapshot()
	if len(records) != 1 {
		t.Fatalf("log records = %d, want 1", len(records))
	}
	if records[0].level != slog.LevelDebug {
		t.Fatalf("level = %v, want Debug", records[0].level)
	}
}

func TestSwarmInspectJoinMalformedJSONWithLogger(t *testing.T) {
	logs := &collectingHandler{}
	logger := slog.New(logs)
	policy := newSwarmPolicy(SwarmOptions{})

	req := httptest.NewRequest(http.MethodPost, "/swarm/join", strings.NewReader("{bad json"))
	reason, err := policy.inspect(logger, req, "/swarm/join")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	records := logs.snapshot()
	if len(records) != 1 {
		t.Fatalf("log records = %d, want 1", len(records))
	}
}

func TestSwarmInspectUpdateMalformedJSONWithLogger(t *testing.T) {
	logs := &collectingHandler{}
	logger := slog.New(logs)
	policy := newSwarmPolicy(SwarmOptions{})

	req := httptest.NewRequest(http.MethodPost, "/swarm/update", strings.NewReader("{bad json"))
	reason, err := policy.inspect(logger, req, "/swarm/update")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	records := logs.snapshot()
	if len(records) != 1 {
		t.Fatalf("log records = %d, want 1", len(records))
	}
}

func TestSwarmInspectUpdateAllowsManagerTokenRotation(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{AllowTokenRotation: true})
	req := httptest.NewRequest(http.MethodPost, "/swarm/update?version=42&rotateManagerToken=true", strings.NewReader(`{}`))
	reason, err := policy.inspect(nil, req, "/swarm/update")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow", reason)
	}
}

func TestSwarmInspectUpdateAllowsManagerUnlockKeyRotation(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{AllowManagerUnlockKeyRotation: true})
	req := httptest.NewRequest(http.MethodPost, "/swarm/update?version=42&rotateManagerUnlockKey=1", strings.NewReader(`{}`))
	reason, err := policy.inspect(nil, req, "/swarm/update")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow", reason)
	}
}

func TestSwarmInspectJoinAllowsEmptyRemoteAddrs(t *testing.T) {
	// Empty RemoteAddrs should pass through.
	policy := newSwarmPolicy(SwarmOptions{})
	req := httptest.NewRequest(http.MethodPost, "/swarm/join", strings.NewReader(`{
		"RemoteAddrs": [],
		"JoinToken": "SWMTKN-1-join"
	}`))
	reason, err := policy.inspect(nil, req, "/swarm/join")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestSwarmInspectInitReadBodyError(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})
	req := httptest.NewRequest(http.MethodPost, "/swarm/init", nil)
	req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}
	_, err := policy.inspectInit(nil, req)
	if err == nil {
		t.Fatal("expected error from inspectInit when bounded body read fails")
	}
}

func TestSwarmInspectJoinReadBodyError(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})
	req := httptest.NewRequest(http.MethodPost, "/swarm/join", nil)
	req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}
	_, err := policy.inspectJoin(nil, req)
	if err == nil {
		t.Fatal("expected error from inspectJoin when bounded body read fails")
	}
}

func TestSwarmInspectJoinOversizedBody(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})
	payload := strings.Repeat("x", maxSwarmBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/swarm/join", strings.NewReader(payload))
	reason, err := policy.inspectJoin(nil, req)
	if err != nil {
		t.Fatalf("inspectJoin() error = %v", err)
	}
	if reason == "" {
		t.Fatal("expected oversized body denial")
	}
}

func TestSwarmInspectUpdateReadBodyError(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})
	req := httptest.NewRequest(http.MethodPost, "/swarm/update", nil)
	req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}
	_, err := policy.inspectUpdate(nil, req)
	if err == nil {
		t.Fatal("expected error from inspectUpdate when bounded body read fails")
	}
}

func TestSwarmInspectUpdateOversizedBody(t *testing.T) {
	policy := newSwarmPolicy(SwarmOptions{})
	payload := strings.Repeat("x", maxSwarmBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/swarm/update", strings.NewReader(payload))
	reason, err := policy.inspectUpdate(nil, req)
	if err != nil {
		t.Fatalf("inspectUpdate() error = %v", err)
	}
	if reason == "" {
		t.Fatal("expected oversized body denial")
	}
}
