package visibility

import (
	"strings"
	"testing"
)

// FuzzLibpodPathIdentifiers fuzzes the libpod path-identifier helpers in
// libpod_paths.go, mirroring the seed+property style of
// internal/filter's FuzzNormalizePath / FuzzPathMatch. Every call site
// (middleware.go's normalizedPathForRequest, feeding needsVisibilityLabelFilter
// / requestVisibleWithPolicy) passes these helpers an already
// filter.NormalizePath-normalized path, so seeds and properties are
// expressed in terms of normalized paths — version-prefix stripping itself
// is filter.NormalizePath's concern and is already fuzzed by
// internal/filter's FuzzNormalizePath.
func FuzzLibpodPathIdentifiers(f *testing.F) {
	seeds := []string{
		// Real endpoint shapes: collection routes.
		"/libpod/containers/json",
		"/libpod/images/json",
		"/libpod/pods/json",
		"/libpod/pods/stats",
		"/libpod/containers/stats",
		"/libpod/containers/showmounted",
		"/libpod/networks/json",
		"/libpod/volumes/json",
		"/libpod/secrets/json",
		"/libpod/images/search",
		"/libpod/images/export",
		// Real endpoint shapes: single-resource reads.
		"/libpod/containers/abc123/json",
		"/libpod/containers/abc123/logs",
		"/libpod/containers/abc123/stats",
		"/libpod/containers/abc123/top",
		"/libpod/containers/abc123/changes",
		"/libpod/containers/abc123/export",
		"/libpod/containers/abc123/archive",
		"/libpod/containers/abc123/exists",
		"/libpod/containers/abc123/healthcheck",
		"/libpod/images/app/json",
		"/libpod/images/app/history",
		"/libpod/images/app/get",
		"/libpod/images/app/tree",
		"/libpod/images/app/exists",
		"/libpod/images/registry.io/team/app/json",
		"/libpod/pods/pod-1/json",
		"/libpod/pods/pod-1/exists",
		"/libpod/pods/pod-1/top",
		"/libpod/networks/bridge/json",
		"/libpod/networks/bridge/exists",
		"/libpod/networks/bridge",
		"/libpod/volumes/vol-1/json",
		"/libpod/volumes/vol-1/export",
		"/libpod/secrets/sec-1/json",
		"/libpod/secrets/sec-1/exists",
		// Docker-compat shapes that must never leak into libpod matchers.
		"/containers/json",
		"/containers/abc/json",
		"/pods/abc/json",
		"/networks/bridge",
		"",
		"/",
		// Tricky cases: empty segments, doubled suffixes, trailing slashes.
		"/libpod/pods//json",
		"/libpod/pods/json/json",
		"/libpod/pods/pod-1/json/",
		"/libpod/pods/pod-1//json",
		"//libpod/pods/pod-1/json",
		"/libpod/",
		"/libpod",
		"/libpod/pods",
		"/libpod/pods/",
		"/libpod/containers/abc/def/json",
		// Case variance — libpod routes are lowercase-only; anything else
		// must not match.
		"/LIBPOD/pods/pod-1/json",
		"/libpod/Pods/pod-1/JSON",
		// Percent-encoding — NormalizePath does not decode, so these arrive
		// as literal characters; the helpers must treat them as opaque.
		"/libpod/pods/pod-1/json%2F",
		"/libpod/pods/pod-1%2Fjson",
		"/libpod/pods/%2e%2e/json",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// Collection routes: a bare word after the prefix with no "/id/suffix"
	// shape, so no single-resource identifier may ever match one. The three
	// in filter.LibpodUnscopeableReads() are here for the same reason the
	// list endpoints are — misclassifying one as a container or pod named
	// "stats" or "showmounted" is what left them unchecked before v2.1.
	collectionRoutes := map[string]bool{
		"/libpod/containers/json":        true,
		"/libpod/containers/stats":       true,
		"/libpod/containers/showmounted": true,
		"/libpod/images/json":            true,
		"/libpod/pods/json":              true,
		"/libpod/pods/stats":             true,
		"/libpod/networks/json":          true,
		"/libpod/volumes/json":           true,
		"/libpod/secrets/json":           true,
	}

	type identifierHelper struct {
		name string
		fn   func(string) (string, bool)
		// allowSlash is true for helpers built on readSubresourceIdentifier,
		// which by design preserves "/" in the identifier (see its doc
		// comment on namespaced image refs) rather than splitting on the
		// first "/" the way suffixedIdentifier does.
		allowSlash bool
	}
	helpers := []identifierHelper{
		{"libpodContainerReadIdentifier", libpodContainerReadIdentifier, true},
		{"libpodImageReadIdentifier", libpodImageReadIdentifier, true},
		{"libpodPodReadIdentifier", libpodPodReadIdentifier, false},
		{"libpodNetworkInspectIdentifier", libpodNetworkInspectIdentifier, false},
		{"libpodVolumeInspectIdentifier", libpodVolumeInspectIdentifier, false},
		{"libpodSecretInspectIdentifier", libpodSecretInspectIdentifier, false},
	}

	f.Fuzz(func(t *testing.T, normPath string) {
		underLibpod := isLibpodVisibilityPath(normPath)

		// needsLibpodVisibilityLabelFilter must never panic, and must never
		// fire for a path outside /libpod/.
		if needsLibpodVisibilityLabelFilter(normPath) && !underLibpod {
			t.Fatalf("needsLibpodVisibilityLabelFilter(%q) = true outside /libpod/", normPath)
		}

		for _, h := range helpers {
			id, ok := h.fn(normPath)
			if !ok {
				continue
			}

			// Property: any match implies the path is under /libpod/ — none
			// of these helpers should ever fire for a non-libpod path.
			if !underLibpod {
				t.Fatalf("%s(%q) matched %q outside /libpod/", h.name, normPath, id)
			}

			// Property: a matched identifier is never empty.
			if id == "" {
				t.Fatalf("%s(%q) matched an empty identifier", h.name, normPath)
			}

			// Property: suffixedIdentifier-based helpers (pod/network/
			// volume/secret) never return an identifier containing "/" —
			// strings.Cut splits on the first "/", so the leading segment
			// is slash-free by construction.
			if !h.allowSlash && strings.Contains(id, "/") {
				t.Fatalf("%s(%q) matched identifier %q containing '/'", h.name, normPath, id)
			}

			// Property: collection routes (bare .../json with no id
			// segment) must never be classified as a single-resource
			// identifier.
			if collectionRoutes[normPath] {
				t.Fatalf("%s(%q) classified collection route as identifier %q", h.name, normPath, id)
			}
		}
	})
}
