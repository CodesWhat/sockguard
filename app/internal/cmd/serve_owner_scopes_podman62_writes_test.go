package cmd

import (
	"net/http"
	"testing"
)

// TestServeChainPodman62WritesTwoOwners drives the Podman 6.2 writes the route
// catalog gained (exec kill, volume rename, the manifest list family) through
// the whole serve chain with owners A and B. Every request A sends that names
// B's resource, or reaches the manifest store at all, must be refused before
// the daemon sees it.
func TestServeChainPodman62WritesTwoOwners(t *testing.T) {
	h := newTenancyHarness(t, true, nil)
	seedTwoOwners(h.daemon)
	h.daemon.add("exec", "aexec", "", func(r *tenantRes) { r.container = h.daemon.find("container", "a-web").id })
	// A manifest list is an image in Podman's store, so the lists the attempts
	// name are seeded as images too: a check that treated {name} as an image
	// would find B's.
	h.daemon.add("image", "b-list:1", "B", nil)
	before := h.daemon.mutations()

	attempts := []tenantAttempt{
		{"kill B exec session", "POST", "/v5.8.1/libpod/exec/bexec/kill?signal=KILL", ""},
		{"remove B exec session", "POST", "/v5.8.1/libpod/exec/bexec/remove", ""},

		{"rename B volume", "POST", "/v5.8.1/libpod/volumes/b-vol/rename?name=a-stolen", ""},
		{"rename B volume by body", "POST", "/v5.8.1/libpod/volumes/b-vol/rename", `{"name":"a-stolen"}`},
		{"rename A volume onto B volume", "POST", "/v5.8.1/libpod/volumes/a-vol/rename?name=b-vol", ""},
		{"rename A volume onto B volume by body", "POST", "/v5.8.1/libpod/volumes/a-vol/rename", `{"name":"b-vol"}`},
		{"rename A volume to a free name", "POST", "/v5.8.1/libpod/volumes/a-vol/rename?name=a-renamed", ""},

		{"manifest create over B list", "POST", "/v5.8.1/libpod/manifests/create?name=b-list:1&images=a-image:1", ""},
		{"manifest create from B image", "POST", "/v5.8.1/libpod/manifests/create?name=a-list:1&images=b-image:1", ""},
		{"manifest create of A list", "POST", "/v5.8.1/libpod/manifests/create?name=a-list:1", ""},
		{"manifest modify B list (POST)", "POST", "/v5.8.1/libpod/manifests/b-list:1?operation=update", `{"images":["a-image:1"]}`},
		{"manifest modify B list (PUT)", "PUT", "/v5.8.1/libpod/manifests/b-list:1", `{"images":["a-image:1"],"operation":"update"}`},
		{"manifest delete B list", "DELETE", "/v5.8.1/libpod/manifests/b-list:1", ""},
		{"manifest add B image to a list", "POST", "/v5.8.1/libpod/manifests/a-list:1/add", `{"images":["b-image:1"]}`},
		{"manifest add to B list", "POST", "/v5.8.1/libpod/manifests/b-list:1/add", `{"images":["a-image:1"]}`},
		{"manifest registry push of B list", "POST", "/v5.8.1/libpod/manifests/b-list:1/registry/registry.example/stolen:1", ""},
		{"manifest push of B list", "POST", "/v5.8.1/libpod/manifests/b-list:1/push?destination=registry.example/stolen:1", ""},
		{"manifest exists of B list", "GET", "/v5.8.1/libpod/manifests/b-list:1/exists", ""},
		{"manifest json of B list", "GET", "/v5.8.1/libpod/manifests/b-list:1/json", ""},
	}
	for _, a := range attempts {
		status, body := h.do(ownerScopesIPA, a.method, a.path, a.body)
		requireRefused(t, a.label, status, body)
	}
	if after := h.daemon.mutations(); len(after) != len(before) {
		t.Errorf("daemon saw requests from refused attempts: %v", after[len(before):])
	}
	for _, name := range []string{"b-vol"} {
		if owner, ok := h.daemon.ownerOf("volume", name); !ok || owner != "B" {
			t.Errorf("volume %s owner = %q (found %v), want B untouched", name, owner, ok)
		}
	}
	if owner, ok := h.daemon.ownerOf("volume", "a-vol"); !ok || owner != "A" {
		t.Errorf("volume a-vol owner = %q (found %v), want A untouched", owner, ok)
	}

	// Positive control: the same exec verb on A's own session works, so the
	// refusals above are the owner check and not a dead route.
	if status, body := h.do(ownerScopesIPA, http.MethodPost, "/v5.8.1/libpod/exec/aexec/kill?signal=KILL", ""); status >= 400 {
		t.Errorf("A kills own exec session: status = %d, want success; body %s", status, body)
	}
}
