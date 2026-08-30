package upstreamflavor

import "testing"

// FuzzClassify drives arbitrary /version response bodies through the engine
// classifier.
//
// The upstream is the thing sockguard is defending against a
// misconfiguration of, so its response is not trusted input. Two invariants:
// classify never panics, and its two return values are never both meaningful
// or both empty — a caller must be able to branch on the error alone and know
// whether it holds a usable flavor. A non-empty flavor must also be one of the
// two resolved values; "auto" is a config spelling and must never come back
// from a probe.
func FuzzClassify(f *testing.F) {
	f.Add([]byte(`{"Components":[{"Name":"Podman Engine"}]}`))
	f.Add([]byte(`{"Components":[{"Name":"Engine"}]}`))
	f.Add([]byte(`{"Components":[{"Name":"Engine"},{"Name":"Podman Engine"}]}`))
	f.Add([]byte(`{"Components":[{"Name":"  podman engine  "}]}`))
	f.Add([]byte(`{"Components":[{"Name":"ENGINE"}]}`))
	f.Add([]byte(`{"Components":[]}`))
	f.Add([]byte(`{"Components":null}`))
	f.Add([]byte(`{"Components":[{"Name":null}]}`))
	f.Add([]byte(`{"Components":[{}]}`))
	f.Add([]byte(`{"Components":[{"Name":"auto"}]}`))
	f.Add([]byte(`{"Components":{"Name":"Engine"}}`)) // wrong shape for Components
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Add([]byte(`{"Components":[{"Name":"Engine"}]} trailing`))

	f.Fuzz(func(t *testing.T, body []byte) {
		flavor, err := classify(body)
		if err != nil {
			if flavor != "" {
				t.Fatalf("classify(%q) = %q with error %v, want an empty flavor alongside an error", body, flavor, err)
			}
			return
		}
		if flavor != Docker && flavor != Podman {
			t.Fatalf("classify(%q) = %q, want %q or %q", body, flavor, Docker, Podman)
		}
	})
}

// FuzzConfigured drives arbitrary configured upstream.flavor strings through
// the parser. A value it accepts must be one of the three spellings, and a
// value it rejects must come back empty — an accepted-but-unnamed flavor
// would reach the middleware as the zero value, which means Docker, and that
// is precisely the silent fail-open this field exists to prevent.
func FuzzConfigured(f *testing.F) {
	for _, seed := range []string{"auto", "docker", "podman", "", " podman ", "Podman", "AUTO", "containerd", "podman\x00", "\tdocker\n", "podmanx"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		flavor, ok := Configured(value)
		if !ok {
			if flavor != "" {
				t.Fatalf("Configured(%q) = %q with ok=false, want an empty flavor", value, flavor)
			}
			return
		}
		if flavor != Auto && flavor != Docker && flavor != Podman {
			t.Fatalf("Configured(%q) = %q with ok=true, want one of the three named values", value, flavor)
		}
	})
}
