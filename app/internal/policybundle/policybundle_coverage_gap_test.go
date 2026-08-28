package policybundle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"

	"github.com/codeswhat/sockguard/app/internal/boundedio"
)

// TestVerify_NoVerifiersConfiguredReturnsError exercises the
// "no verifiers configured" branch in sigstoreVerifier.Verify — the case
// where Enabled=true but AllowedSigningKeys and AllowedKeyless are both
// empty. BuildConfig rejects that combo, so the only way to hit this
// branch is to construct the verifier struct directly.
func TestVerify_NoVerifiersConfiguredReturnsError(t *testing.T) {
	t.Parallel()
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

// TestLoadBundleRejectsInvalidFiles covers malformed and oversized bundle
// files, distinct from the already-tested missing-path case.
func TestLoadBundleRejectsInvalidFiles(t *testing.T) {
	tests := []struct {
		name       string
		contents   []byte
		truncateTo int64
		wantErr    error
		wantText   string
	}{
		{name: "corrupt JSON", contents: []byte("{not valid sigstore bundle"), wantText: "policy_bundle"},
		{name: "oversized", truncateTo: MaxBundleFileBytes + 1, wantErr: boundedio.ErrTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "bundle.json")
			if err := os.WriteFile(path, tc.contents, 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if tc.truncateTo > 0 {
				if err := os.Truncate(path, tc.truncateTo); err != nil {
					t.Fatalf("Truncate: %v", err)
				}
			}

			_, err := LoadBundle(path)
			if err == nil {
				t.Fatal("LoadBundle error = nil, want non-nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("LoadBundle error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantText != "" && !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("LoadBundle error = %q, want text %q", err, tc.wantText)
			}
		})
	}
}
