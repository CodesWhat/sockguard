package buildkitproxy

import "testing"

func TestParseGRPCPath(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		wantService string
		wantMethod  string
		wantOK      bool
	}{
		{"well-formed", "/moby.buildkit.v1.Control/Solve", "moby.buildkit.v1.Control", "Solve", true},
		{"nested package name", "/moby.buildkit.v1.frontend.LLBBridge/ExecProcess", "moby.buildkit.v1.frontend.LLBBridge", "ExecProcess", true},
		{"no leading slash", "moby.buildkit.v1.Control/Solve", "", "", false},
		{"bare slash", "/", "", "", false},
		{"empty string", "", "", "", false},
		{"no method segment", "/moby.buildkit.v1.Control", "", "", false},
		{"trailing slash, empty method", "/moby.buildkit.v1.Control/", "", "", false},
		{"extra segment", "/moby.buildkit.v1.Control/Solve/extra", "", "", false},
		{"only a method, no service", "//Solve", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service, method, ok := ParseGRPCPath(tc.path)
			if ok != tc.wantOK {
				t.Fatalf("ParseGRPCPath(%q) ok = %v, want %v", tc.path, ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if service != tc.wantService || method != tc.wantMethod {
				t.Errorf("ParseGRPCPath(%q) = (%q, %q), want (%q, %q)", tc.path, service, method, tc.wantService, tc.wantMethod)
			}
		})
	}
}
