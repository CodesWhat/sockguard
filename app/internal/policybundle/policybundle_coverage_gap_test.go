package policybundle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

// TestVerify_NoVerifiersConfiguredReturnsError exercises the
// "no verifiers configured" branch in sigstoreVerifier.Verify — the case
// where Enabled=true but AllowedSigningKeys and AllowedKeyless are both
// empty. BuildConfig rejects that combo, so the only way to hit this
// branch is to construct the verifier struct directly.
func TestVerify_NoVerifiersConfiguredReturnsError(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	yaml := []byte("rules: []\n")
	entity, err := vs.Sign("ops@example.com", "https://github.com/login/oauth", yaml)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	v := &sigstoreVerifier{cfg: Config{Enabled: true}}

	_, err = v.Verify(context.Background(), yaml, entity)
	if err == nil {
		t.Fatal("Verify with empty key/keyless lists returned nil error")
	}
	if !strings.Contains(err.Error(), "no verifiers configured") {
		t.Errorf("err = %q, want \"no verifiers configured\"", err.Error())
	}
}

// TestLoadBundle_CorruptJSONReturnsError covers the "file exists but is
// not a valid sigstore bundle" path inside LoadBundle, distinct from the
// already-tested missing-path case.
func TestLoadBundle_CorruptJSONReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.json")
	if err := os.WriteFile(path, []byte("{not valid sigstore bundle"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := LoadBundle(path)
	if err == nil {
		t.Fatal("LoadBundle(corrupt) err = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "policy_bundle") {
		t.Errorf("err = %q, want a policy_bundle-prefixed error", err.Error())
	}
}
