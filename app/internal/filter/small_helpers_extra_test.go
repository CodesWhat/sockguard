package filter

import (
	"math"
	"net/http"
	"strings"
	"testing"
)

func TestPrivateNetworkOnly(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]bool{
		`[{"Name":"network"}]`:                         true,
		`[{"Name":"network","Host":true}]`:             false,
		`[{"Name":"network","Path":"/proc/1/ns/net"}]`: false,
		`[{"Name":"ipc"}]`:                             false,
		`[]`:                                           false,
		`not json`:                                     false,
	} {
		if got := privateNetworkOnly(raw); got != want {
			t.Fatalf("privateNetworkOnly(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestBoundedUint64AsInt64(t *testing.T) {
	t.Parallel()
	if got := boundedUint64AsInt64(42); got != 42 {
		t.Fatalf("boundedUint64AsInt64(42) = %d", got)
	}
	if got := boundedUint64AsInt64(math.MaxInt64); got != math.MaxInt64 {
		t.Fatalf("boundedUint64AsInt64(MaxInt64) = %d", got)
	}
	if got := boundedUint64AsInt64(math.MaxUint64); got != math.MaxInt64 {
		t.Fatalf("boundedUint64AsInt64(MaxUint64) = %d, want MaxInt64", got)
	}
}

func TestLibpodNetworkDisconnectBodyHandling(t *testing.T) {
	t.Parallel()
	policy := newNetworkPolicy(NetworkOptions{})
	const path = "/libpod/networks/net1/disconnect"

	// Non-matching method or path is not this inspector's request.
	req := newJSONInspectorFuzzRequest(http.MethodGet, path, "", []byte(`{}`))
	if reason, err := policy.inspectLibpodDisconnect(nil, req, path); reason != "" || err != nil {
		t.Fatalf("GET = (%q, %v), want allow", reason, err)
	}
	// Oversized body is a 413 rejection.
	req = newJSONInspectorFuzzRequest(http.MethodPost, path, "", []byte(strings.Repeat("a", maxLibpodNetworkBodyBytes+1)))
	if _, err := policy.inspectLibpodDisconnect(nil, req, path); err == nil {
		t.Fatal("oversized body must be rejected")
	}
	// Undecodable body is denied as uninspectable.
	req = newJSONInspectorFuzzRequest(http.MethodPost, path, "", []byte(`{`))
	if reason, err := policy.inspectLibpodDisconnect(nil, req, path); err != nil || !strings.Contains(reason, "could not be inspected") {
		t.Fatalf("malformed body = (%q, %v), want an uninspectable denial", reason, err)
	}
	// Force disconnect is refused unless allowed.
	req = newJSONInspectorFuzzRequest(http.MethodPost, path, "", []byte(`{"Force":true}`))
	if reason, err := policy.inspectLibpodDisconnect(nil, req, path); err != nil || reason == "" {
		t.Fatalf("force disconnect = (%q, %v), want a denial", reason, err)
	}
}
