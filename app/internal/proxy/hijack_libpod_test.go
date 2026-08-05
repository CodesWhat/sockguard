package proxy

import (
	"net/http"
	"testing"

	"github.com/codeswhat/sockguard/internal/filter"
)

// TestIsHijackEndpointLibpod covers #148's libpod/ prefix peel in
// isHijackEndpointNormalized: /libpod/containers/{id}/attach and
// /libpod/exec/{id}/start must upgrade exactly like their Docker-compat
// counterparts, including through a three-part Podman semver version prefix.
func TestIsHijackEndpointLibpod(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		// Positive cases.
		{"POST", "/libpod/containers/abc123/attach", true},
		{"POST", "/libpod/exec/abc123/start", true},
		// With a Docker-style two-part version prefix.
		{"POST", "/v1.45/libpod/containers/abc123/attach", true},
		{"POST", "/v1.45/libpod/exec/abc123/start", true},
		// With Podman's three-part semver version prefix (#148).
		{"POST", "/v5.0.0/libpod/containers/abc123/attach", true},
		{"POST", "/v4.9.3/libpod/exec/abc123/start", true},
		// Negative: wrong method.
		{"GET", "/libpod/containers/abc123/attach", false},
		{"PUT", "/libpod/exec/abc123/start", false},
		// Negative: wrong path within the libpod namespace.
		{"POST", "/libpod/containers/abc123/start", false},
		{"POST", "/libpod/exec/abc123/resize", false},
		{"POST", "/libpod/containers/attach", false},
		{"POST", "/libpod/exec/start", false},
		// Negative: not actually the libpod namespace.
		{"POST", "/libpodxyz/containers/abc123/attach", false},
		{"POST", "/LIBPOD/containers/abc123/attach", false},
		// Negative: other libpod endpoints.
		{"POST", "/libpod/containers/create", false},
		{"POST", "/libpod/pods/create", false},
		{"POST", "/libpod/play/kube", false},
		{"GET", "/libpod/info", false},
	}

	for _, tt := range tests {
		name := tt.method + " " + tt.path
		t.Run(name, func(t *testing.T) {
			got := isHijackEndpoint(tt.method, tt.path)
			if got != tt.want {
				t.Errorf("isHijackEndpoint(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestIsHijackEndpointLibpodDoesNotAllocate(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "libpod_attach", method: http.MethodPost, path: "/libpod/containers/abc123/attach"},
		{name: "libpod_versioned_exec_start", method: http.MethodPost, path: "/v5.0.0/libpod/exec/abc123/start"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !isHijackEndpoint(tt.method, tt.path) {
				t.Fatalf("isHijackEndpoint(%q, %q) = false, want true", tt.method, tt.path)
			}

			allocs := testing.AllocsPerRun(1000, func() {
				isHijackEndpoint(tt.method, tt.path)
			})

			if allocs > 0 {
				t.Fatalf("isHijackEndpoint(%q, %q) allocated %.0f times, want 0", tt.method, tt.path, allocs)
			}
		})
	}
}

// TestHijackFilterParity is the #148 design doc's parity invariant: every
// path internal/proxy's hijack layer treats as a connection-upgrade
// candidate must be one internal/filter's own routing recognizes too, and
// vice versa. A path where the two disagree is a two-parser-drift smuggling
// bug — one layer would forward traffic (or apply body inspection) the other
// layer never accounted for. filter.IsHijackCandidatePath is exported
// specifically to let this test exercise the real production matchers on
// both sides of the package split rather than a hand-duplicated copy of
// either one's logic.
func TestHijackFilterParity(t *testing.T) {
	tests := []struct {
		method string
		path   string
	}{
		// Docker-compat hijack endpoints.
		{"POST", "/containers/abc123/attach"},
		{"POST", "/exec/abc123/start"},
		{"POST", "/v1.45/containers/abc123/attach"},
		{"POST", "/v1.45/exec/abc123/start"},
		// libpod hijack endpoints (#148).
		{"POST", "/libpod/containers/abc123/attach"},
		{"POST", "/libpod/exec/abc123/start"},
		{"POST", "/v5.0.0/libpod/containers/abc123/attach"},
		{"POST", "/v5.0.0/libpod/exec/abc123/start"},
		// Paths that must NOT be hijack candidates on either side.
		{"GET", "/containers/abc123/attach"},
		{"POST", "/containers/abc123/exec"},
		{"POST", "/containers/create"},
		{"POST", "/libpod/containers/abc123/exec"},
		{"POST", "/libpod/containers/create"},
		{"POST", "/libpod/pods/create"},
		{"POST", "/libpod/play/kube"},
		{"GET", "/libpod/exec/abc123/start"},
		{"POST", "/containers/abc123/start"},
		{"POST", "/exec/abc123/resize"},
	}

	for _, tt := range tests {
		name := tt.method + " " + tt.path
		t.Run(name, func(t *testing.T) {
			normalized := filter.NormalizePath(tt.path)
			hijackWant := isHijackEndpointNormalized(tt.method, normalized)
			filterWant := filter.IsHijackCandidatePath(tt.method, normalized)
			if hijackWant != filterWant {
				t.Fatalf("parity mismatch for %s %s (normalized %q): hijack layer = %v, filter layer = %v",
					tt.method, tt.path, normalized, hijackWant, filterWant)
			}
		})
	}
}
