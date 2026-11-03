package ownership

import (
	"context"
	"strings"
	"testing"
)

func TestExactSecretLookupContext(t *testing.T) {
	if exactSecretLookup(context.Background()) {
		t.Error("a plain context asks for an exact lookup")
	}
	if !exactSecretLookup(withExactSecretLookup(context.Background())) {
		t.Error("withExactSecretLookup did not mark the context")
	}
}

func TestSecretLookupAmbiguousPrefix(t *testing.T) {
	if !secretLookupAmbiguousPrefix(strings.NewReader(`{"message":"more than one result secret with prefix b0: ambiguous"}`)) {
		t.Error("the ambiguous-prefix error was not recognised")
	}
	if secretLookupAmbiguousPrefix(strings.NewReader(`{"message":"database is locked"}`)) {
		t.Error("an unrelated lookup failure was read as an ambiguous prefix")
	}
}

func TestDecodeExactSecret(t *testing.T) {
	const body = `{"ID":"b0b0b0b0b0b0b0b0b0b0b0b02","Spec":{"Name":"theirs","Labels":{"com.sockguard.owner":"team-b"}}}`
	tests := []struct {
		name       string
		body       string
		identifier string
		found      bool
		wantErr    bool
	}{
		{"exact name", body, "theirs", true, false},
		{"exact ID", body, "b0b0b0b0b0b0b0b0b0b0b0b02", true, false},
		{"ID prefix only", body, "b0b0", false, false},
		{"malformed body", `{`, "theirs", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels, found, err := decodeExactSecret(strings.NewReader(tt.body), tt.identifier)
			if (err != nil) != tt.wantErr || found != tt.found {
				t.Fatalf("decodeExactSecret() = (%v, %v, %v), want found=%v err=%v", labels, found, err, tt.found, tt.wantErr)
			}
			if found && labels["com.sockguard.owner"] != "team-b" {
				t.Errorf("labels = %v, want the secret's labels", labels)
			}
		})
	}
}
