package filter

import (
	"bytes"
	"encoding/json"
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

func TestReadSwarmBodyTooLargeReturnsFlag(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), maxSwarmBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/swarm/join", bytes.NewReader(payload))

	body, tooLarge, err := readSwarmBody(req)
	if err != nil {
		t.Fatalf("readSwarmBody() error = %v", err)
	}
	if !tooLarge {
		t.Fatal("expected tooLarge = true")
	}
	if len(body) == 0 {
		t.Fatal("expected body to be populated even when tooLarge")
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

func TestContainsString(t *testing.T) {
	values := []string{"alpha", "beta", "gamma"}
	if !containsString(values, "beta") {
		t.Fatal("containsString() = false for present element")
	}
	if containsString(values, "delta") {
		t.Fatal("containsString() = true for absent element")
	}
	if containsString(nil, "alpha") {
		t.Fatal("containsString(nil) = true, want false")
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

func TestReadSwarmBodyReadError(t *testing.T) {
	// Exercises readSwarmBody when io.ReadAll returns an error (lines 210-215).
	sentinel := io.ErrUnexpectedEOF
	req := httptest.NewRequest(http.MethodPost, "/swarm/init", nil)
	req.Body = &readErrorReadCloser{readErr: sentinel}
	_, tooLarge, err := readSwarmBody(req)
	if err == nil {
		t.Fatal("expected read error to propagate")
	}
	if tooLarge {
		t.Fatal("tooLarge should be false on error")
	}
}

func TestReadSwarmBodyCloseError(t *testing.T) {
	// Exercises the closeErr branch in readSwarmBody (line 210-212).
	sentinel := io.ErrClosedPipe
	req := httptest.NewRequest(http.MethodPost, "/swarm/init", nil)
	req.Body = &erroringReadCloser{Reader: bytes.NewReader([]byte(`{}`)), closeErr: sentinel}
	_, _, err := readSwarmBody(req)
	if err == nil {
		t.Fatal("expected close error to propagate")
	}
}

func TestSwarmInspectInitReadBodyError(t *testing.T) {
	// Exercises lines 98-100: readSwarmBody returning an error in inspectInit.
	policy := newSwarmPolicy(SwarmOptions{})
	req := httptest.NewRequest(http.MethodPost, "/swarm/init", nil)
	req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}
	_, err := policy.inspectInit(nil, req)
	if err == nil {
		t.Fatal("expected error from inspectInit when readSwarmBody fails")
	}
}

func TestSwarmInspectJoinReadBodyError(t *testing.T) {
	// Exercises lines 133-135: readSwarmBody returning an error in inspectJoin.
	policy := newSwarmPolicy(SwarmOptions{})
	req := httptest.NewRequest(http.MethodPost, "/swarm/join", nil)
	req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}
	_, err := policy.inspectJoin(nil, req)
	if err == nil {
		t.Fatal("expected error from inspectJoin when readSwarmBody fails")
	}
}

func TestSwarmInspectJoinOversizedBody(t *testing.T) {
	// Exercises lines 136-138: tooLarge branch in inspectJoin.
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
	// Exercises lines 166-168: readSwarmBody returning an error in inspectUpdate.
	policy := newSwarmPolicy(SwarmOptions{})
	req := httptest.NewRequest(http.MethodPost, "/swarm/update", nil)
	req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}
	_, err := policy.inspectUpdate(nil, req)
	if err == nil {
		t.Fatal("expected error from inspectUpdate when readSwarmBody fails")
	}
}

func TestSwarmInspectUpdateOversizedBody(t *testing.T) {
	// Exercises lines 169-171: tooLarge branch in inspectUpdate.
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
