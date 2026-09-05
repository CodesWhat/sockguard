package apipath

import (
	"net/http"
	"testing"
)

func TestIsLibpodExecStartPathRequiresTail(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"valid", "/libpod/exec/abc/start", true},
		// Empty id is accepted, matching IsExecStartPath's existing Docker
		// behavior; see the equivalent case in
		// internal/filter's TestIsLibpodExecCreatePathRequiresTail.
		{"empty id", "/libpod/exec//start", true},
		{"wrong tail", "/libpod/exec/abc/resize", false},
		{"no tail at all", "/libpod/exec/abc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLibpodExecStartPath(tt.path); got != tt.want {
				t.Errorf("IsLibpodExecStartPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsLibpodContainerAttachPathRequiresTail(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"valid", "/libpod/containers/abc/attach", true},
		// Empty id is accepted, matching IsContainerAttachPath's existing
		// Docker behavior; see the equivalent case in
		// internal/filter's TestIsLibpodExecCreatePathRequiresTail.
		{"empty id", "/libpod/containers//attach", true},
		{"wrong tail", "/libpod/containers/abc/exec", false},
		{"no tail at all", "/libpod/containers/abc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLibpodContainerAttachPath(tt.path); got != tt.want {
				t.Errorf("IsLibpodContainerAttachPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestIsHijackCandidatePath pins the composed candidate set internal/proxy's
// hijack layer and internal/filter's routing both read: the four
// connection-upgrade endpoints, POST only.
func TestIsHijackCandidatePath(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{name: "docker attach", method: http.MethodPost, path: "/containers/abc/attach", want: true},
		{name: "docker exec start", method: http.MethodPost, path: "/exec/abc/start", want: true},
		{name: "libpod attach", method: http.MethodPost, path: "/libpod/containers/abc/attach", want: true},
		{name: "libpod exec start", method: http.MethodPost, path: "/libpod/exec/abc/start", want: true},
		{name: "get is never a candidate", method: http.MethodGet, path: "/containers/abc/attach", want: false},
		{name: "exec create is not a candidate", method: http.MethodPost, path: "/containers/abc/exec", want: false},
		{name: "container inspect", method: http.MethodPost, path: "/containers/abc/json", want: false},
		{name: "empty path", method: http.MethodPost, path: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsHijackCandidatePath(tt.method, tt.path); got != tt.want {
				t.Errorf("IsHijackCandidatePath(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

// TestHijackMatchersStayFamilyExclusive is internal/apipath's half of
// internal/filter's TestLibpodMatchersNeverMatchDockerPathsAndViceVersa: the
// libpod attach/exec-start matchers are exact-prefix-guarded, so a
// Docker-compat path must never satisfy one and vice versa.
func TestHijackMatchersStayFamilyExclusive(t *testing.T) {
	dockerPaths := []string{"/containers/abc/attach", "/exec/abc/start"}
	libpodPaths := []string{"/libpod/containers/abc/attach", "/libpod/exec/abc/start"}

	for _, p := range dockerPaths {
		if IsLibpodContainerAttachPath(p) {
			t.Errorf("IsLibpodContainerAttachPath(%q) = true, want false", p)
		}
		if IsLibpodExecStartPath(p) {
			t.Errorf("IsLibpodExecStartPath(%q) = true, want false", p)
		}
	}
	for _, p := range libpodPaths {
		if IsContainerAttachPath(p) {
			t.Errorf("IsContainerAttachPath(%q) = true, want false", p)
		}
		if IsExecStartPath(p) {
			t.Errorf("IsExecStartPath(%q) = true, want false", p)
		}
	}
}

// TestIsExecStartPathRequiresTail is IsLibpodExecStartPathRequiresTail's
// Docker-compat counterpart.
func TestIsExecStartPathRequiresTail(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "valid", path: "/exec/abc/start", want: true},
		{name: "empty id", path: "/exec//start", want: true},
		{name: "wrong tail", path: "/exec/abc/resize", want: false},
		{name: "no tail at all", path: "/exec/abc", want: false},
		{name: "collection route", path: "/exec", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsExecStartPath(tt.path); got != tt.want {
				t.Errorf("IsExecStartPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestIsContainerAttachPathRequiresTail is
// IsLibpodContainerAttachPathRequiresTail's Docker-compat counterpart.
func TestIsContainerAttachPathRequiresTail(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "valid", path: "/containers/abc/attach", want: true},
		{name: "empty id", path: "/containers//attach", want: true},
		{name: "wrong tail", path: "/containers/abc/exec", want: false},
		{name: "no tail at all", path: "/containers/abc", want: false},
		{name: "collection route", path: "/containers", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsContainerAttachPath(tt.path); got != tt.want {
				t.Errorf("IsContainerAttachPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
