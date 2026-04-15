package filter

import (
	"bytes"
	"encoding/json"
	"io"
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
