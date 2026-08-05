package filter

import (
	"os"
	"strings"
	"testing"
)

// maxSupportedVersionTestdataPath points at the repo-root testdata file that
// pins the highest Docker Engine API version sockguard has been validated
// against. It is read by both this test and the monthly
// quality-api-version-watch.yml CI workflow, which fails loudly when the
// upstream Engine API version history moves past this pin.
const maxSupportedVersionTestdataPath = "../../testdata/docker-api/max-supported-version.txt"

// TestMaxSupportedEngineAPIVersionPin asserts the version-prefix stripping
// pipeline (NormalizePath -> stripVersionPrefix) still normalizes requests
// carrying the pinned "/v<max-supported-version>/" prefix exactly like any
// other supported version prefix. NormalizePath's stripping is
// version-number agnostic — it accepts any well-formed /vN[.N]/ prefix
// rather than hardcoding a version list — so this test's job is to catch a
// regression in that generality landing at the same time the pin is bumped,
// not to enumerate every version in between.
func TestMaxSupportedEngineAPIVersionPin(t *testing.T) {
	version := readMaxSupportedEngineAPIVersion(t)

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "pinned version prefix strips to unversioned path",
			path: "/v" + version + "/containers/json",
			want: "/containers/json",
		},
		{
			name: "pinned version prefix on buildkit session endpoint",
			path: "/v" + version + "/session",
			want: "/session",
		},
		{
			name: "pinned version prefix on buildkit grpc endpoint",
			path: "/v" + version + "/grpc",
			want: "/grpc",
		},
		{
			name: "pinned version prefix on ping",
			path: "/v" + version + "/_ping",
			want: "/_ping",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizePath(tt.path)
			if got != tt.want {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.path, got, tt.want)
			}
			if !HasVersionPrefix(tt.path) {
				t.Errorf("HasVersionPrefix(%q) = false, want true", tt.path)
			}
		})
	}
}

// readMaxSupportedEngineAPIVersion reads and validates the pinned version
// string from testdata, failing the test with a clear message if the file is
// missing or malformed rather than silently skipping coverage.
func readMaxSupportedEngineAPIVersion(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile(maxSupportedVersionTestdataPath)
	if err != nil {
		t.Fatalf("reading %s: %v", maxSupportedVersionTestdataPath, err)
	}

	version := strings.TrimSpace(string(raw))
	if version == "" {
		t.Fatalf("%s is empty, want a version like \"1.55\"", maxSupportedVersionTestdataPath)
	}
	parts := strings.Split(version, ".")
	if len(parts) != 2 {
		t.Fatalf("%s contains %q, want a major.minor version like \"1.55\"", maxSupportedVersionTestdataPath, version)
	}
	for _, part := range parts {
		if part == "" {
			t.Fatalf("%s contains %q, want a major.minor version like \"1.55\"", maxSupportedVersionTestdataPath, version)
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				t.Fatalf("%s contains %q, want a major.minor version like \"1.55\"", maxSupportedVersionTestdataPath, version)
			}
		}
	}

	return version
}
