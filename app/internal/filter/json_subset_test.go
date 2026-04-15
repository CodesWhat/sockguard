package filter

import "testing"

func TestDecodePolicySubsetJSONIgnoresUnknownFields(t *testing.T) {
	var payload struct {
		Name string `json:"Name"`
	}

	err := decodePolicySubsetJSON([]byte(`{"Name":"cache","Labels":{"env":"prod"}}`), &payload)
	if err != nil {
		t.Fatalf("decodePolicySubsetJSON() error = %v, want nil", err)
	}
	if payload.Name != "cache" {
		t.Fatalf("payload.Name = %q, want cache", payload.Name)
	}
}

func TestDecodePolicySubsetJSONRejectsMalformedJSON(t *testing.T) {
	var payload struct {
		Name string `json:"Name"`
	}

	if err := decodePolicySubsetJSON([]byte(`{`), &payload); err == nil {
		t.Fatal("decodePolicySubsetJSON() error = nil, want malformed-json error")
	}
}
