package filter_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

// presetsAllowedToAdmitUnscopeableLibpodReads is the complete set of shipped
// presets whose rules may reach an endpoint in
// filter.LibpodUnscopeableReads(), with the reason each is exempt.
//
// readonly.yaml is a single `GET /**` allow whose header says it "intentionally
// exposes all Docker read endpoints", and it sets
// insecure_allow_read_exfiltration: true to say so at startup. Narrowing it to
// carve these three out would make it something other than what it claims to
// be, and it would still be wrong for the endpoints it cannot enumerate. The
// ownership and visibility middlewares are the layer that refuses these, and
// they run regardless of which rule admitted the request — so an operator
// running readonly.yaml WITH owner isolation or a visibility policy is still
// covered, and one running it without has asked for an unfiltered read proxy.
var presetsAllowedToAdmitUnscopeableLibpodReads = map[string]string{
	"readonly.yaml": "blanket GET /** behind insecure_allow_read_exfiltration: true",
}

// TestNoShippedPresetAdmitsAnUnscopeableLibpodRead evaluates every preset in
// configs/ — its top-level rules and each client profile's rules — against
// every path in filter.LibpodUnscopeableReads(), in both the bare and the
// version-prefixed spelling.
//
// It measures the verdict through filter.Evaluate rather than reading the YAML,
// because the risk is a broad glob rather than an explicit rule: a preset that
// never mentions stats can still admit it through `GET /libpod/containers/*`,
// and that is precisely the kind of reach a grep does not find. This is the
// guard that would have caught podman-readonly.yaml shipping an explicit
// `GET /libpod/pods/stats` allow next to an owner-isolation promise.
func TestNoShippedPresetAdmitsAnUnscopeableLibpodRead(t *testing.T) {
	t.Parallel()

	presets, err := filepath.Glob(filepath.Join("..", "..", "configs", "*.yaml"))
	if err != nil {
		t.Fatalf("glob configs: %v", err)
	}
	if len(presets) == 0 {
		t.Fatal("no presets found; the glob is wrong and this test proves nothing")
	}

	for _, preset := range presets {
		name := filepath.Base(preset)
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.Load(preset)
			if err != nil {
				t.Fatalf("load preset %s: %v", name, err)
			}

			ruleSets := map[string][]config.RuleConfig{"<root>": cfg.Rules}
			for _, profile := range cfg.Clients.Profiles {
				ruleSets["profile:"+profile.Name] = profile.Rules
			}

			exemption, exempt := presetsAllowedToAdmitUnscopeableLibpodReads[name]
			for setName, rules := range ruleSets {
				compiled := compileDrydockRules(t, rules)
				for _, read := range filter.LibpodUnscopeableReads() {
					for _, path := range []string{read.Path, "/v5.8.1" + read.Path} {
						action, index, _ := filter.Evaluate(compiled, httptest.NewRequest(http.MethodGet, path, nil))
						allowed := action == filter.ActionAllow
						if allowed && !exempt {
							t.Errorf("%s %s allows GET %s at rule %d; the preset promises isolation it cannot deliver on this endpoint — remove the rule or narrow the glob", name, setName, path, index)
						}
						if !allowed && exempt && setName == "<root>" {
							t.Errorf("%s %s denies GET %s but is listed exempt (%s); drop the exemption", name, setName, path, exemption)
						}
					}
				}
			}
		})
	}
}
