package filter_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

// TestNoShippedPresetAdmitsANativePodmanCreate evaluates every preset in
// configs/ and every compose example's policy, their top-level rules and
// each client profile's, against Podman's native container and pod create
// routes in the bare and the version-prefixed spelling.
//
// 2.2.6 made a host UTS or cgroup namespace on a native container create,
// and a host PID, IPC, user or UTS namespace on a pod create, need a gate
// that is off by default. No shipped policy admits either route, so none of
// them refuses anything it allowed on 2.2.5. A preset that starts admitting
// one has to say in its own request_body block which of those namespaces
// its client needs, and this test is where that gets noticed.
//
// The verdict comes from filter.Evaluate rather than from reading the YAML,
// so a broad glob that reaches the routes counts the same as a rule that
// names them.
func TestNoShippedPresetAdmitsANativePodmanCreate(t *testing.T) {
	t.Parallel()

	var policies []string
	for _, pattern := range []string{
		filepath.Join("..", "..", "configs", "*.yaml"),
		filepath.Join("..", "..", "..", "examples", "compose", "*", "sockguard*.yaml"),
	} {
		found, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		if len(found) == 0 {
			t.Fatalf("no policies match %s; the glob is wrong and this test proves nothing", pattern)
		}
		policies = append(policies, found...)
	}

	routes := []string{"/libpod/containers/create", "/libpod/pods/create"}
	for _, policy := range policies {
		name := filepath.Join(filepath.Base(filepath.Dir(policy)), filepath.Base(policy))
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.Load(policy)
			if err != nil {
				t.Fatalf("load %s: %v", name, err)
			}
			ruleSets := map[string][]config.RuleConfig{"<root>": cfg.Rules}
			for _, profile := range cfg.Clients.Profiles {
				ruleSets["profile:"+profile.Name] = profile.Rules
			}
			for setName, rules := range ruleSets {
				compiled := compileDrydockRules(t, rules)
				for _, route := range routes {
					for _, path := range []string{route, "/v5.8.6" + route} {
						action, index, _ := filter.Evaluate(compiled, httptest.NewRequest(http.MethodPost, path, nil))
						if action == filter.ActionAllow {
							t.Errorf("%s %s allows POST %s at rule %d; decide which request_body.libpod_container_create and libpod_pod_create host namespace gates its client needs, then exempt it here", name, setName, path, index)
						}
					}
				}
			}
		})
	}
}
