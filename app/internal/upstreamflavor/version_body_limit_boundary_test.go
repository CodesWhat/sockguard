package upstreamflavor

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// versionBodyOfExactLength builds a valid /version JSON body, naming the
// Docker "Engine" component, padded with an ignored field so the total byte
// length is exactly want. The padding field is outside the schema classify
// reads (versionPayload only decodes Components), so it never changes the
// classification.
func versionBodyOfExactLength(t *testing.T, want int) []byte {
	t.Helper()
	const prefix = `{"Components":[{"Name":"Engine"}],"Padding":"`
	const suffix = `"}`
	padLen := want - len(prefix) - len(suffix)
	if padLen < 0 {
		t.Fatalf("versionBodyOfExactLength(%d): body scaffolding alone is %d bytes", want, len(prefix)+len(suffix))
	}
	body := prefix + strings.Repeat("a", padLen) + suffix
	if len(body) != want {
		t.Fatalf("versionBodyOfExactLength(%d) built %d bytes", want, len(body))
	}
	return []byte(body)
}

// TestDetectAtExactVersionBodyLimit pins the `len(body) > maxVersionBodyBytes`
// boundary in Detect: a /version body of exactly maxVersionBodyBytes must
// still classify successfully, and one byte more must be rejected as
// oversized. TestDetectFailsOnOversizedBody already covers well past the
// limit; this pins the exact edge the comparison operator decides.
func TestDetectAtExactVersionBodyLimit(t *testing.T) {
	t.Run("exactly at the limit succeeds", func(t *testing.T) {
		t.Parallel()
		body := versionBodyOfExactLength(t, maxVersionBodyBytes)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		got, err := Detect(t.Context(), clientFor(srv.Listener.Addr().String()))
		if err != nil {
			t.Fatalf("Detect() with an exactly-%d-byte body error = %v, want nil", maxVersionBodyBytes, err)
		}
		if got != Docker {
			t.Fatalf("Detect() = %q, want %q", got, Docker)
		}
	})

	t.Run("one byte over the limit is rejected", func(t *testing.T) {
		t.Parallel()
		body := versionBodyOfExactLength(t, maxVersionBodyBytes+1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		got, err := Detect(t.Context(), clientFor(srv.Listener.Addr().String()))
		if err == nil {
			t.Fatalf("Detect() with a %d-byte body = %q, want a size-limit error", maxVersionBodyBytes+1, got)
		}
		if !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("Detect() error = %v, want a size-limit error", err)
		}
	})
}
