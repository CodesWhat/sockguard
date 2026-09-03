package filter

import "testing"

func TestLookupLibpodUnscopeableReadMatchesManifestReads(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path     string
		wantStem string
	}{
		{path: "/libpod/manifests/app/exists", wantStem: "manifest_exists"},
		{path: "/libpod/manifests/registry.io/team/app/json", wantStem: "manifest_json"},
		{path: "/libpod/manifests/registry.io/team/app/json/exists", wantStem: "manifest_exists"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			read, ok := LookupLibpodUnscopeableRead(tt.path)
			if !ok {
				t.Fatalf("LookupLibpodUnscopeableRead(%q) = no match, want %q", tt.path, tt.wantStem)
			}
			if read.ReasonCodeStem != tt.wantStem {
				t.Fatalf("LookupLibpodUnscopeableRead(%q).ReasonCodeStem = %q, want %q", tt.path, read.ReasonCodeStem, tt.wantStem)
			}
		})
	}
}

func TestLookupLibpodUnscopeableReadDoesNotMatchOtherManifestPaths(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/libpod/manifests/json",
		"/libpod/manifests/app",
		"/libpod/manifests/app/push",
		"/libpod/images/app/json",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			if read, ok := LookupLibpodUnscopeableRead(path); ok {
				t.Fatalf("LookupLibpodUnscopeableRead(%q) = %#v, want no match", path, read)
			}
		})
	}
}
