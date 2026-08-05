package filter

import "testing"

func TestIsLibpodPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "libpod container create", path: "/libpod/containers/create", want: true},
		{name: "libpod pod create", path: "/libpod/pods/create", want: true},
		{name: "libpod info", path: "/libpod/info", want: true},
		{name: "bare libpod without trailing slash", path: "/libpod", want: false},
		{name: "docker containers create", path: "/containers/create", want: false},
		{name: "docker root", path: "/", want: false},
		{name: "empty", path: "", want: false},
		{name: "libpod-prefixed but different resource", path: "/libpodxyz/containers/create", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLibpodPath(tt.path); got != tt.want {
				t.Errorf("isLibpodPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestLibpodPerResourceMatchers table-tests every per-resource libpod
// predicate added for #148 against the exact path it must match and a set
// of near-miss paths (wrong resource, wrong method-shaped path, Docker
// equivalent) it must not.
func TestLibpodPerResourceMatchers(t *testing.T) {
	matchers := []struct {
		name    string
		matcher func(string) bool
	}{
		{"isLibpodContainerCreatePath", isLibpodContainerCreatePath},
		{"isLibpodPodCreatePath", isLibpodPodCreatePath},
		{"isLibpodExecCreatePath", isLibpodExecCreatePath},
		{"isLibpodExecStartPath", isLibpodExecStartPath},
		{"isLibpodContainerAttachPath", isLibpodContainerAttachPath},
		{"isLibpodPlayKubePath", isLibpodPlayKubePath},
	}

	positives := map[string]string{
		"isLibpodContainerCreatePath": "/libpod/containers/create",
		"isLibpodPodCreatePath":       "/libpod/pods/create",
		"isLibpodExecCreatePath":      "/libpod/containers/abc123/exec",
		"isLibpodExecStartPath":       "/libpod/exec/abc123/start",
		"isLibpodContainerAttachPath": "/libpod/containers/abc123/attach",
		"isLibpodPlayKubePath":        "/libpod/play/kube",
	}

	// Cross-cutting near-misses every matcher must reject.
	commonNegatives := []string{
		"",
		"/",
		"/libpod",
		"/libpod/",
		"/containers/create",
		"/containers/abc123/exec",
		"/exec/abc123/start",
		"/containers/abc123/attach",
		"/pods/create",
	}

	for _, m := range matchers {
		t.Run(m.name, func(t *testing.T) {
			positive, ok := positives[m.name]
			if !ok {
				t.Fatalf("no positive case registered for %s", m.name)
			}
			if !m.matcher(positive) {
				t.Errorf("%s(%q) = false, want true", m.name, positive)
			}

			for _, neg := range commonNegatives {
				if m.matcher(neg) {
					t.Errorf("%s(%q) = true, want false", m.name, neg)
				}
			}

			for otherName, otherPositive := range positives {
				if otherName == m.name {
					continue
				}
				if m.matcher(otherPositive) {
					t.Errorf("%s(%q) = true, want false (that path belongs to %s)", m.name, otherPositive, otherName)
				}
			}
		})
	}
}

// TestLibpodMatchersNeverMatchDockerPathsAndViceVersa is the routing-safety
// invariant from the #148 design doc ("fail-open body-shape confusion is the
// #1 risk"): a libpod matcher must never fire on a Docker-compat path, and a
// Docker matcher must never fire on the equivalent libpod path. Because every
// libpod matcher here is exact-prefix-guarded on "/libpod/", this holds by
// construction — the test exists to catch a future edit that weakens the
// guard.
func TestLibpodMatchersNeverMatchDockerPathsAndViceVersa(t *testing.T) {
	dockerPaths := []string{
		"/containers/create",
		"/containers/abc123/exec",
		"/exec/abc123/start",
		"/containers/abc123/attach",
	}
	libpodMatchers := []struct {
		name    string
		matcher func(string) bool
	}{
		{"isLibpodPath", isLibpodPath},
		{"isLibpodContainerCreatePath", isLibpodContainerCreatePath},
		{"isLibpodPodCreatePath", isLibpodPodCreatePath},
		{"isLibpodExecCreatePath", isLibpodExecCreatePath},
		{"isLibpodExecStartPath", isLibpodExecStartPath},
		{"isLibpodContainerAttachPath", isLibpodContainerAttachPath},
		{"isLibpodPlayKubePath", isLibpodPlayKubePath},
	}
	for _, dp := range dockerPaths {
		for _, m := range libpodMatchers {
			if m.matcher(dp) {
				t.Errorf("%s(%q) = true, want false (Docker-compat path must never satisfy a libpod matcher)", m.name, dp)
			}
		}
	}

	libpodPaths := []string{
		"/libpod/containers/create",
		"/libpod/containers/abc123/exec",
		"/libpod/exec/abc123/start",
		"/libpod/containers/abc123/attach",
		"/libpod/pods/create",
		"/libpod/play/kube",
	}
	dockerMatchers := []struct {
		name    string
		matcher func(string) bool
	}{
		{"isExecCreatePath", isExecCreatePath},
		{"isExecStartPath", isExecStartPath},
		{"isContainerAttachPath", isContainerAttachPath},
	}
	for _, lp := range libpodPaths {
		for _, m := range dockerMatchers {
			if m.matcher(lp) {
				t.Errorf("%s(%q) = true, want false (libpod path must never satisfy a Docker matcher)", m.name, lp)
			}
		}
	}
}

// TestLibpodPathAdversarial exercises the path-adversarial cases from the
// #148 design doc: traversal, doubled/trailing slashes, and case variance.
// Every case is routed through NormalizePath first, exactly as the real
// request pipeline does — a libpod matcher must never be called with a raw,
// uncleaned path (see isLibpodPath's doc comment).
func TestLibpodPathAdversarial(t *testing.T) {
	tests := []struct {
		name           string
		rawPath        string
		wantNormalized string
		wantLibpod     bool
	}{
		{
			name:           "traversal out of libpod collapses to the Docker path",
			rawPath:        "/libpod/../containers/create",
			wantNormalized: "/containers/create",
			wantLibpod:     false,
		},
		{
			name:           "traversal within libpod stays in namespace",
			rawPath:        "/libpod/containers/../pods/create",
			wantNormalized: "/libpod/pods/create",
			wantLibpod:     true,
		},
		{
			name:           "doubled interior slash collapses",
			rawPath:        "/libpod//containers/create",
			wantNormalized: "/libpod/containers/create",
			wantLibpod:     true,
		},
		{
			name:           "doubled leading slash collapses",
			rawPath:        "//libpod/containers/create",
			wantNormalized: "/libpod/containers/create",
			wantLibpod:     true,
		},
		{
			name:           "trailing slash is cleaned",
			rawPath:        "/libpod/containers/create/",
			wantNormalized: "/libpod/containers/create",
			wantLibpod:     true,
		},
		{
			name:           "uppercase LIBPOD segment stays unmatched",
			rawPath:        "/LIBPOD/containers/create",
			wantNormalized: "/LIBPOD/containers/create",
			wantLibpod:     false,
		},
		{
			name:           "mixed-case Libpod segment stays unmatched",
			rawPath:        "/Libpod/containers/create",
			wantNormalized: "/Libpod/containers/create",
			wantLibpod:     false,
		},
		{
			name:           "versioned prefix still resolves into libpod namespace",
			rawPath:        "/v5.0.0/libpod/containers/create",
			wantNormalized: "/libpod/containers/create",
			wantLibpod:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := NormalizePath(tt.rawPath)
			if normalized != tt.wantNormalized {
				t.Fatalf("NormalizePath(%q) = %q, want %q", tt.rawPath, normalized, tt.wantNormalized)
			}
			if got := isLibpodPath(normalized); got != tt.wantLibpod {
				t.Errorf("isLibpodPath(%q) = %v, want %v", normalized, got, tt.wantLibpod)
			}
		})
	}
}

func TestIsLibpodContainerCreatePathTrailingSegment(t *testing.T) {
	// A trailing segment past "create" must not match — mirrors Docker's
	// exact-match isContainerCreatePath-equivalent inline check.
	if isLibpodContainerCreatePath("/libpod/containers/create/extra") {
		t.Error("isLibpodContainerCreatePath with a trailing segment must be false")
	}
}

func TestIsLibpodExecCreatePathRequiresTail(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"valid", "/libpod/containers/abc/exec", true},
		// Empty id is accepted, matching isExecCreatePath's existing Docker
		// behavior — only the tail segment is checked. A raw request never
		// reaches here with this shape anyway: NormalizePath collapses the
		// doubled slash before any matcher sees the path.
		{"empty id", "/libpod/containers//exec", true},
		{"wrong tail", "/libpod/containers/abc/json", false},
		{"no tail at all", "/libpod/containers/abc", false},
		{"nested tail rejected", "/libpod/containers/abc/exec/extra", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLibpodExecCreatePath(tt.path); got != tt.want {
				t.Errorf("isLibpodExecCreatePath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsLibpodExecStartPathRequiresTail(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"valid", "/libpod/exec/abc/start", true},
		// Empty id is accepted, matching isExecStartPath's existing Docker
		// behavior; see the equivalent case in
		// TestIsLibpodExecCreatePathRequiresTail.
		{"empty id", "/libpod/exec//start", true},
		{"wrong tail", "/libpod/exec/abc/resize", false},
		{"no tail at all", "/libpod/exec/abc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLibpodExecStartPath(tt.path); got != tt.want {
				t.Errorf("isLibpodExecStartPath(%q) = %v, want %v", tt.path, got, tt.want)
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
		// Empty id is accepted, matching isContainerAttachPath's existing
		// Docker behavior; see the equivalent case in
		// TestIsLibpodExecCreatePathRequiresTail.
		{"empty id", "/libpod/containers//attach", true},
		{"wrong tail", "/libpod/containers/abc/exec", false},
		{"no tail at all", "/libpod/containers/abc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLibpodContainerAttachPath(tt.path); got != tt.want {
				t.Errorf("isLibpodContainerAttachPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
