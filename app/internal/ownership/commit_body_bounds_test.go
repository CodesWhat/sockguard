package ownership

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// commitBodyOfExactly builds a JSON commit config whose encoded length is
// exactly n bytes, so the at-limit and over-limit sides of the body cap can be
// told apart.
func commitBodyOfExactly(t *testing.T, n int) []byte {
	t.Helper()
	const prefix = `{"Image":"`
	const suffix = `"}`
	if n <= len(prefix)+len(suffix) {
		t.Fatalf("commitBodyOfExactly(%d): too small to encode", n)
	}
	body := make([]byte, 0, n)
	body = append(body, prefix...)
	body = append(body, bytes.Repeat([]byte("a"), n-len(prefix)-len(suffix))...)
	body = append(body, suffix...)
	if len(body) != n {
		t.Fatalf("commitBodyOfExactly(%d) produced %d bytes", n, len(body))
	}
	return body
}

// TestMutateCommitOwnershipBodyAcceptsABodyExactlyAtTheLimit covers the
// at-limit side of the commit body cap. The reader takes one byte past the cap
// precisely so a body of exactly maxOwnershipBodyBytes arrives whole and is
// accepted; reading exactly the cap instead would silently truncate it, and
// rejecting at the cap would refuse a legal request.
func TestMutateCommitOwnershipBodyAcceptsABodyExactlyAtTheLimit(t *testing.T) {
	body := commitBodyOfExactly(t, int(maxOwnershipBodyBytes))
	r := httptest.NewRequest(http.MethodPost, "/commit", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	if err := mutateCommitOwnershipBody(r, "sockguard.owner", "client-a"); err != nil {
		t.Fatalf("mutateCommitOwnershipBody with a body of exactly %d bytes: %v", maxOwnershipBodyBytes, err)
	}

	mutated, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read mutated body: %v", err)
	}
	if !bytes.Contains(mutated, []byte(`"sockguard.owner":"client-a"`)) {
		t.Fatal("mutated commit body does not carry the owner label")
	}
}

// TestMutateCommitOwnershipBodyRejectsABodyOnePastTheLimit is the other side
// of the same boundary.
func TestMutateCommitOwnershipBodyRejectsABodyOnePastTheLimit(t *testing.T) {
	body := commitBodyOfExactly(t, int(maxOwnershipBodyBytes)+1)
	r := httptest.NewRequest(http.MethodPost, "/commit", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	err := mutateCommitOwnershipBody(r, "sockguard.owner", "client-a")
	if err == nil {
		t.Fatalf("mutateCommitOwnershipBody with a body of %d bytes returned no error", len(body))
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("mutateCommitOwnershipBody error = %v, want an over-limit error", err)
	}
}

// TestMutateCommitOwnershipBodySurfacesACloseError pins that a body whose
// Close fails is reported rather than swallowed. The read succeeded, so
// nothing else in the pipeline would ever notice.
func TestMutateCommitOwnershipBodySurfacesACloseError(t *testing.T) {
	closeErr := errors.New("body close failed")
	r := httptest.NewRequest(http.MethodPost, "/commit", http.NoBody)
	r.Body = closeErrorReadCloser{Reader: strings.NewReader(`{"Image":"busybox"}`), closeErr: closeErr}

	err := mutateCommitOwnershipBody(r, "sockguard.owner", "client-a")
	if err == nil {
		t.Fatal("mutateCommitOwnershipBody swallowed the body close error")
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("mutateCommitOwnershipBody error = %v, want it to wrap %v", err, closeErr)
	}
}

// TestCommitChangeInstructionStopsAtTheFirstSeparator pins where the
// instruction token ends, including the degenerate line that starts with the
// separator itself and therefore has no token at all.
func TestCommitChangeInstructionStopsAtTheFirstSeparator(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{name: "space separated", line: "LABEL k=v", want: "LABEL"},
		{name: "equals separated", line: "LABEL=k=v", want: "LABEL"},
		{name: "lowercase is folded up", line: "label k=v", want: "LABEL"},
		{name: "leading whitespace trimmed", line: "   LABEL k=v", want: "LABEL"},
		{name: "no separator", line: "LABEL", want: "LABEL"},
		{name: "leading equals leaves no token", line: "=LABEL", want: ""},
		{name: "bare equals", line: "=", want: ""},
		{name: "empty line", line: "", want: ""},
		{name: "whitespace only", line: "   ", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := commitChangeInstruction(tt.line); got != tt.want {
				t.Fatalf("commitChangeInstruction(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// TestLibpodNeedsOwnerFilterCoversHEAD pins that HEAD gets the same owner
// filtering as GET on the libpod list routes. A HEAD that skipped the filter
// would leak the existence of another owner's resources through status codes
// and Content-Length alone.
func TestLibpodNeedsOwnerFilterCoversHEAD(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{name: "GET containers list", method: http.MethodGet, path: libpodPrefix + "containers/json", want: true},
		{name: "HEAD containers list", method: http.MethodHead, path: libpodPrefix + "containers/json", want: true},
		{name: "HEAD images list", method: http.MethodHead, path: libpodPrefix + "images/json", want: true},
		{name: "HEAD events", method: http.MethodHead, path: libpodPrefix + "events", want: true},
		{name: "HEAD unrelated path", method: http.MethodHead, path: libpodPrefix + "info", want: false},
		{name: "PUT is not a read", method: http.MethodPut, path: libpodPrefix + "containers/json", want: false},
		{name: "POST prune", method: http.MethodPost, path: libpodPrefix + "containers/prune", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := libpodNeedsOwnerFilter(tt.method, tt.path); got != tt.want {
				t.Fatalf("libpodNeedsOwnerFilter(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}
