package metrics

import "testing"

// routeCategoryBenchPaths are the shapes routeLabel sees on a live proxy: a
// version-prefixed list, its unversioned equivalent, a container action, the
// two static endpoints every client polls, and a registry-namespaced image
// path (the longest real shape).
var routeCategoryBenchPaths = []struct {
	name string
	path string
}{
	{"versioned_container_list", "/v1.45/containers/json"},
	{"container_list", "/containers/json"},
	{"versioned_container_start", "/v1.45/containers/abc123def456/start"},
	{"ping", "/_ping"},
	{"events", "/events"},
	{"versioned_image_list", "/v1.45/images/json"},
	{"namespaced_image_inspect", "/v1.45/images/ghcr.io/codeswhat/sockguard:2.1.0/json"},
	{"unknown", "/v1.45/distribution/alpine/json"},
}

var routeCategorySink string

func BenchmarkRouteCategory(b *testing.B) {
	for _, p := range routeCategoryBenchPaths {
		b.Run(p.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				routeCategorySink = RouteCategory(p.path)
			}
		})
	}
}

// TestRouteCategoryDoesNotAllocate pins the reason RouteCategory splits into a
// stack array and looks its labels up in the routeFamily tables: it runs on
// every request through routeLabel, so a per-call segment slice or a
// concatenated label is per-request garbage.
func TestRouteCategoryDoesNotAllocate(t *testing.T) {
	if raceBuild {
		t.Skip("race instrumentation perturbs allocation counts")
	}
	for _, p := range routeCategoryBenchPaths {
		t.Run(p.name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(1000, func() {
				routeCategorySink = RouteCategory(p.path)
			})
			if allocs != 0 {
				t.Fatalf("RouteCategory(%q) allocations = %.0f, want 0", p.path, allocs)
			}
		})
	}
}
