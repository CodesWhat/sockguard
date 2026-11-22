package cmd

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// seedTwoOwners fills the daemon with a victim (B) and an attacker (A) of
// every kind, plus the legacy-link aliases that dockerd resolves to B's
// containers under a name that looks like A's.
func seedTwoOwners(d *tenancyDaemon) {
	for _, c := range []struct{ name, owner string }{
		{"a-web", "A"}, {"b-web", "B"}, {"b-db", "B"},
		// dockerd answers to "a-web/alias" with the container the link points at.
		{"a-web/alias", "B"},
	} {
		d.add("container", c.name, c.owner, nil)
	}
	d.add("volume", "a-vol", "A", func(r *tenantRes) { r.data = "vol-data-of-A" })
	d.add("volume", "b-vol", "B", func(r *tenantRes) { r.data = "vol-data-of-B"; r.labels["note"] = "B-PRIVATE-NOTE" })
	d.add("network", "a-net", "A", nil)
	d.add("network", "b-net", "B", nil)
	d.add("network", "a-net/alias", "B", nil)
	d.add("secret", "a-secret", "A", func(r *tenantRes) { r.data = "data-of-A" })
	d.add("secret", "b-secret", "B", func(r *tenantRes) { r.data = "data-of-B" })
	d.add("image", "a-image:1", "A", nil)
	d.add("image", "b-image:1", "B", nil)
	d.add("service", "a-svc", "A", nil)
	d.add("service", "b-svc", "B", nil)
	d.add("task", "a-task", "A", nil)
	d.add("task", "b-task", "B", nil)
	d.add("exec", "bexec", "", func(r *tenantRes) { r.container = d.find("container", "b-web").id })
}

// requireRefused fails unless status is a refusal the owner layer produces.
func requireRefused(t *testing.T, label string, status int, body string) {
	t.Helper()
	if status != http.StatusForbidden && status != http.StatusNotFound {
		t.Errorf("%s: status = %d, want 403 or 404; body %s", label, status, body)
	}
	for _, leak := range []string{"B-PRIVATE-NOTE", "vol-data-of-B", "data-of-B", "B-LOG-OR-ARCHIVE-DATA", "B-UNLOCK-KEY", "B-DOCKERFILE-STEP"} {
		if strings.Contains(body, leak) {
			t.Errorf("%s: response leaks B data %q: %s", label, leak, body)
		}
	}
}

type tenantAttempt struct {
	label, method, path, body string
}

// TestServeChainTwoOwnersCannotReachEachOther runs, through the whole serve
// chain with owners A and B in one instance, the bypass classes the
// single-owner suite proves for one owner: every request A sends that names,
// references, links, mounts, attaches to or prefix-matches a resource of B is
// refused before the daemon sees it.
func TestServeChainTwoOwnersCannotReachEachOther(t *testing.T) {
	h := newTenancyHarness(t, false, nil)
	seedTwoOwners(h.daemon)
	before := h.daemon.mutations()

	prefixFor := func(kind, name string) string {
		t.Helper()
		h.daemon.mu.Lock()
		defer h.daemon.mu.Unlock()
		victim := h.daemon.find(kind, name)
		if victim == nil {
			t.Fatalf("missing seeded %s %s", kind, name)
		}
		for n := 4; n < len(victim.id); n++ {
			prefix := victim.id[:n]
			if h.daemon.find(kind, prefix) == victim {
				return prefix
			}
		}
		t.Fatalf("seeded %s %s has no unique proper ID prefix", kind, name)
		return ""
	}
	bNetworkPrefix := prefixFor("network", "b-net")
	bContainerPrefix := prefixFor("container", "b-web")
	bSecretPrefix := prefixFor("secret", "b-secret")
	aNetworkPrefix := prefixFor("network", "a-net")
	aContainerPrefix := prefixFor("container", "a-web")
	aSecretPrefix := prefixFor("secret", "a-secret")

	svc := func(spec string) string {
		return `{"Name":"x-svc","TaskTemplate":{"ContainerSpec":{"Image":"a-image:1"` + spec + `}}}`
	}
	attempts := []tenantAttempt{
		// TaskTemplate.Networks and service-level networks onto B's network.
		{"service attaches B network", "POST", "/v1.45/services/create", `{"Name":"x-svc","TaskTemplate":{"ContainerSpec":{"Image":"a-image:1"},"Networks":[{"Target":"b-net"}]}}`},
		{"service attaches B network by top-level Networks", "POST", "/v1.45/services/create", `{"Name":"x-svc","TaskTemplate":{"ContainerSpec":{"Image":"a-image:1"}},"Networks":[{"Target":"b-net"}]}`},
		{"service mounts B image", "POST", "/v1.45/services/create", svc(`,"Mounts":[{"Type":"image","Source":"b-image:1","Target":"/m"}]`)},
		{"service runs B image", "POST", "/v1.45/services/create", `{"Name":"x-svc","TaskTemplate":{"ContainerSpec":{"Image":"b-image:1"}}}`},
		{"service mounts B volume", "POST", "/v1.45/services/create", svc(`,"Mounts":[{"Type":"volume","Source":"b-vol","Target":"/m"}]`)},
		{"service uses B secret", "POST", "/v1.45/services/create", svc(`,"Secrets":[{"SecretName":"b-secret","SecretID":"x","File":{"Name":"s"}}]`)},
		{"service update of B service", "POST", "/v1.45/services/b-svc/update?version=1", `{"Name":"b-svc"}`},

		// Container create: image, image mount, links, namespaces, networks, binds.
		{"container runs B image", "POST", "/v1.45/containers/create?name=x1", `{"Image":"b-image:1"}`},
		{"container mounts B image", "POST", "/v1.45/containers/create?name=x2", `{"Image":"a-image:1","HostConfig":{"Mounts":[{"Type":"image","Source":"b-image:1","Target":"/m"}]}}`},
		{"container links B container", "POST", "/v1.45/containers/create?name=x3", `{"Image":"a-image:1","HostConfig":{"Links":["b-web:alias"]}}`},
		{"container links B container by slash name", "POST", "/v1.45/containers/create?name=x4", `{"Image":"a-image:1","HostConfig":{"Links":["/b-web:alias"]}}`},
		{"container links B alias under an A-looking name", "POST", "/v1.45/containers/create?name=x5", `{"Image":"a-image:1","HostConfig":{"Links":["a-web/alias:x"]}}`},
		{"container joins B network namespace", "POST", "/v1.45/containers/create?name=x6", `{"Image":"a-image:1","HostConfig":{"NetworkMode":"container:b-web"}}`},
		{"container joins B pid namespace by slash name", "POST", "/v1.45/containers/create?name=x7", `{"Image":"a-image:1","HostConfig":{"PidMode":"container:/b-web"}}`},
		{"container endpoint on B network", "POST", "/v1.45/containers/create?name=x8", `{"Image":"a-image:1","NetworkingConfig":{"EndpointsConfig":{"b-net":{}}}}`},
		{"container binds B volume", "POST", "/v1.45/containers/create?name=x9", `{"Image":"a-image:1","HostConfig":{"Binds":["b-vol:/data"]}}`},
		{"container mounts B volume", "POST", "/v1.45/containers/create?name=x10", `{"Image":"a-image:1","HostConfig":{"Mounts":[{"Type":"volume","Source":"b-vol","Target":"/data"}]}}`},
		{"container volumes-from B container", "POST", "/v1.45/containers/create?name=x11", `{"Image":"a-image:1","HostConfig":{"VolumesFrom":["b-web"]}}`},

		// Builds are refused whatever they build from.
		{"build FROM B image", "POST", "/v1.45/build?t=a-built:1&dockerfile=Dockerfile", "FROM b-image:1\n"},
		{"build with B image as cache source", "POST", "/v1.45/build?t=a-built:1&cachefrom=%5B%22b-image%3A1%22%5D", ""},

		// Volume create over B's existing volume returns none of B's data.
		{"volume create over B volume", "POST", "/v1.45/volumes/create", `{"Name":"b-vol"}`},
		{"volume create over B volume, lowercase name key", "POST", "/v1.45/volumes/create", `{"name":"b-vol"}`},
		{"volume inspect B volume", "GET", "/v1.45/volumes/b-vol", ""},
		{"volume delete B volume", "DELETE", "/v1.45/volumes/b-vol", ""},

		// Swarm.
		{"swarm leave", "POST", "/v1.45/swarm/leave?force=1", ""},
		{"swarm unlockkey", "GET", "/v1.45/swarm/unlockkey", ""},

		// Networks, including a slash-bearing name dockerd resolves to B's.
		{"network connect B network", "POST", "/v1.45/networks/b-net/connect", `{"Container":"a-web"}`},
		{"network disconnect B network", "POST", "/v1.45/networks/b-net/disconnect", `{"Container":"a-web","Force":true}`},
		{"network connect A network with B container", "POST", "/v1.45/networks/a-net/connect", `{"Container":"b-web"}`},
		{"network disconnect B container from A network", "POST", "/v1.45/networks/a-net/disconnect", `{"Container":"b-web"}`},
		{"network connect slash-bearing alias of B network", "POST", "/v1.45/networks/a-net/alias/connect", `{"Container":"a-web"}`},
		{"network delete B network", "DELETE", "/v1.45/networks/b-net", ""},
		{"network inspect B network by ID prefix", "GET", "/v1.45/networks/" + bNetworkPrefix, ""},

		// Secrets by name and by ID prefix.
		{"secret inspect B secret by name", "GET", "/v1.45/secrets/b-secret", ""},
		{"secret inspect B secret by ID prefix", "GET", "/v1.45/secrets/" + bSecretPrefix, ""},
		{"secret delete B secret by ID prefix", "DELETE", "/v1.45/secrets/" + bSecretPrefix, ""},
		{"secret update B secret", "POST", "/v1.45/secrets/b-secret/update?version=1", `{}`},

		// Exec, archive, logs, attach and the other container verbs on B's container.
		{"exec create in B container", "POST", "/v1.45/containers/b-web/exec", `{"Cmd":["id"]}`},
		{"exec start of B exec session", "POST", "/v1.45/exec/bexec/start", `{"Detach":true}`},
		{"exec inspect of B exec session", "GET", "/v1.45/exec/bexec/json", ""},
		{"exec resize of B exec session", "POST", "/v1.45/exec/bexec/resize?h=10&w=10", ""},
		{"archive read of B container", "GET", "/v1.45/containers/b-web/archive?path=/etc", ""},
		{"archive stat of B container", "HEAD", "/v1.45/containers/b-web/archive?path=/etc", ""},
		{"archive write into B container", "PUT", "/v1.45/containers/b-web/archive?path=/", "x"},
		{"logs of B container", "GET", "/v1.45/containers/b-web/logs?stdout=1", ""},
		{"attach to B container", "POST", "/v1.45/containers/b-web/attach?stream=1&stdout=1", ""},
		{"attach websocket of B container", "GET", "/v1.45/containers/b-web/attach/ws?stream=1", ""},
		{"stop B container", "POST", "/v1.45/containers/b-web/stop", ""},
		{"kill B container", "POST", "/v1.45/containers/b-web/kill", ""},
		{"rename B container", "POST", "/v1.45/containers/b-web/rename?name=stolen", ""},
		{"delete B container", "DELETE", "/v1.45/containers/b-web?force=1", ""},
		{"B container by ID prefix", "POST", "/v1.45/containers/" + bContainerPrefix + "/stop", ""},
		{"B container by slash-bearing name", "POST", "/v1.45/containers/a-web/alias/stop", ""},

		// Images.
		{"image inspect B image", "GET", "/v1.45/images/b-image:1/json", ""},
		{"image delete B image", "DELETE", "/v1.45/images/b-image:1", ""},
		{"image tag B image", "POST", "/v1.45/images/b-image:1/tag?repo=a-image&tag=stolen", ""},
		{"image tag onto B's name", "POST", "/v1.45/images/a-image:1/tag?repo=b-image&tag=1", ""},
		{"image pull onto B's name", "POST", "/v1.45/images/create?fromImage=b-image&tag=1", ""},
		{"image push B image", "POST", "/v1.45/images/b-image:1/push", ""},
		{"image get B image", "GET", "/v1.45/images/b-image:1/get", ""},
		{"commit B container", "POST", "/v1.45/commit?container=b-web&repo=a-image&tag=c", ""},
		{"commit onto B's image name", "POST", "/v1.45/commit?container=a-web&repo=b-image&tag=1", ""},

		// Services and tasks.
		{"service inspect B", "GET", "/v1.45/services/b-svc", ""},
		{"service delete B", "DELETE", "/v1.45/services/b-svc", ""},
		{"service logs B", "GET", "/v1.45/services/b-svc/logs?stdout=1", ""},
		{"task inspect B", "GET", "/v1.45/tasks/b-task", ""},
		{"task logs B", "GET", "/v1.45/tasks/b-task/logs?stdout=1", ""},
	}
	for _, a := range attempts {
		status, body := h.do(ownerScopesIPA, a.method, a.path, a.body)
		requireRefused(t, a.label, status, body)
	}
	if after := h.daemon.mutations(); len(after) != len(before) {
		t.Errorf("daemon saw mutations from refused requests: %v", after[len(before):])
	}

	// B's state is exactly as seeded.
	for kind, names := range map[string][]string{
		"container": {"b-web", "b-db", "a-web/alias"}, "volume": {"b-vol"}, "network": {"b-net", "a-net/alias"},
		"secret": {"b-secret"}, "image": {"b-image:1"}, "service": {"b-svc"}, "task": {"b-task"},
	} {
		for _, name := range names {
			if owner, ok := h.daemon.ownerOf(kind, name); !ok || owner != "B" {
				t.Errorf("%s %s owner = %q (found %v), want B untouched", kind, name, owner, ok)
			}
		}
	}
	if got := h.daemon.dataOf("secret", "b-secret"); got != "data-of-B" {
		t.Errorf("B secret data = %q, want data-of-B", got)
	}
	if got := h.daemon.dataOf("volume", "b-vol"); got != "vol-data-of-B" {
		t.Errorf("B volume data = %q, want vol-data-of-B", got)
	}

	// Prefix controls must resolve B's resources when B requests them; an
	// absent or ambiguous prefix must not masquerade as an ownership refusal.
	for _, path := range []string{
		"/v1.45/networks/" + bNetworkPrefix,
		"/v1.45/containers/" + bContainerPrefix + "/json",
		"/v1.45/secrets/" + bSecretPrefix,
	} {
		if status, body := h.do(ownerScopesIPB, http.MethodGet, path, ""); status != http.StatusOK {
			t.Errorf("B inspects own resource by ID prefix %s: status = %d, want 200; body %s", path, status, body)
		}
	}

	// Positive controls: the same verbs on A's own resources work, so the
	// refusals above are the owner check and not a dead route.
	for _, a := range []tenantAttempt{
		{"A inspects own container", "GET", "/v1.45/containers/a-web/json", ""},
		{"A stops own container", "POST", "/v1.45/containers/a-web/stop", ""},
		{"A inspects own volume", "GET", "/v1.45/volumes/a-vol", ""},
		{"A connects own network", "POST", "/v1.45/networks/a-net/connect", `{"Container":"a-web"}`},
		{"A inspects own secret", "GET", "/v1.45/secrets/a-secret", ""},
		{"A reads own logs", "GET", "/v1.45/containers/a-web/logs?stdout=1", ""},
		{"A inspects own network by ID prefix", "GET", "/v1.45/networks/" + aNetworkPrefix, ""},
		{"A stops own container by ID prefix", "POST", "/v1.45/containers/" + aContainerPrefix + "/stop", ""},
		{"A inspects own secret by ID prefix", "GET", "/v1.45/secrets/" + aSecretPrefix, ""},
		{"A deletes own secret by ID prefix", "DELETE", "/v1.45/secrets/" + aSecretPrefix, ""},
	} {
		if status, body := h.do(ownerScopesIPA, a.method, a.path, a.body); status >= 400 {
			t.Errorf("%s: status = %d, want success; body %s", a.label, status, body)
		}
	}
	status, body := h.do(ownerScopesIPA, http.MethodPost, "/v1.45/containers/create?name=a-new", `{"Image":"a-image:1"}`)
	if status != http.StatusCreated {
		t.Errorf("A creates own container: status %d, body %s", status, body)
	}
	if owner, _ := h.daemon.ownerOf("container", "a-new"); owner != "A" {
		t.Errorf("A's new container owner = %q, want A", owner)
	}

	// The mirror: B cannot reach A's.
	for _, a := range []tenantAttempt{
		{"B inspects A container", "GET", "/v1.45/containers/a-web/json", ""},
		{"B stops A container", "POST", "/v1.45/containers/a-web/stop", ""},
		{"B volume create over A volume", "POST", "/v1.45/volumes/create", `{"Name":"a-vol"}`},
		{"B inspects A secret", "GET", "/v1.45/secrets/a-secret", ""},
		{"B runs A image", "POST", "/v1.45/containers/create?name=y1", `{"Image":"a-image:1"}`},
	} {
		status, body := h.do(ownerScopesIPB, a.method, a.path, a.body)
		if status != http.StatusForbidden && status != http.StatusNotFound {
			t.Errorf("%s: status = %d, want refusal; body %s", a.label, status, body)
		}
		if strings.Contains(body, "vol-data-of-A") {
			t.Errorf("%s: leaks A data: %s", a.label, body)
		}
	}
}

// TestServeChainTwoOwnersListsAndPrunesStayScoped proves list endpoints hide
// the other owner's resources, system/df narrows, and a prune removes only the
// caller's own.
func TestServeChainTwoOwnersListsAndPrunesStayScoped(t *testing.T) {
	h := newTenancyHarness(t, false, nil)
	seedTwoOwners(h.daemon)

	label := func(owner string) string { return `"` + tenancyLabelKey + `":"` + owner + `"` }
	for _, path := range []string{
		"/v1.45/containers/json?all=1", "/v1.45/images/json", "/v1.45/volumes", "/v1.45/networks",
		"/v1.45/secrets", "/v1.45/services", "/v1.45/tasks",
	} {
		for _, who := range []struct{ name, remote, mine, theirs string }{
			{"A", ownerScopesIPA, "A", "B"},
			{"B", ownerScopesIPB, "B", "A"},
		} {
			status, body := h.do(who.remote, http.MethodGet, path, "")
			if status != http.StatusOK {
				t.Errorf("%s GET %s: status %d, body %s", who.name, path, status, body)
				continue
			}
			if !strings.Contains(body, label(who.mine)) {
				t.Errorf("%s GET %s: own resources missing: %s", who.name, path, body)
			}
			if strings.Contains(body, label(who.theirs)) || strings.Contains(body, "B-PRIVATE-NOTE") && who.name == "A" {
				t.Errorf("%s GET %s shows the other owner's resource: %s", who.name, path, body)
			}
		}
	}

	// system/df keeps only the caller's items and drops build cache.
	status, body := h.do(ownerScopesIPA, http.MethodGet, "/v1.45/system/df", "")
	if status != http.StatusOK {
		t.Fatalf("system/df status %d: %s", status, body)
	}
	var df map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &df); err != nil {
		t.Fatalf("decode df: %v\n%s", err, body)
	}
	for _, leak := range []string{"b-web", "b-vol", "b-image", "B-DOCKERFILE-STEP", "bc-B", "B-PRIVATE-NOTE"} {
		if strings.Contains(body, leak) {
			t.Errorf("A system/df leaks %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "a-web") || !strings.Contains(body, "a-vol") {
		t.Errorf("A system/df lost its own items: %s", body)
	}

	// Prunes narrow to the caller.
	for _, p := range []string{"/v1.45/containers/prune", "/v1.45/volumes/prune", "/v1.45/networks/prune", "/v1.45/images/prune"} {
		if status, body := h.do(ownerScopesIPA, http.MethodPost, p, ""); status != http.StatusOK {
			t.Errorf("A POST %s: status %d, body %s", p, status, body)
		}
	}
	for kind, name := range map[string]string{"container": "b-web", "volume": "b-vol", "network": "b-net", "image": "b-image:1"} {
		if owner, ok := h.daemon.ownerOf(kind, name); !ok || owner != "B" {
			t.Errorf("A's prune touched B's %s %s (found %v, owner %q)", kind, name, ok, owner)
		}
	}
	for kind, name := range map[string]string{"container": "a-web", "volume": "a-vol", "network": "a-net", "image": "a-image:1"} {
		if h.daemon.exists(kind, name) {
			t.Errorf("A's prune did not remove its own %s %s", kind, name)
		}
	}
	// A prune that already names filters keeps the owner narrowing.
	filters := url.QueryEscape(`{"label":["x=y"]}`)
	if status, _ := h.do(ownerScopesIPB, http.MethodPost, "/v1.45/volumes/prune?filters="+filters, ""); status != http.StatusOK {
		t.Errorf("B prune with its own filters status = %d", status)
	}
}

// TestServeChainTwoOwnersPodmanRoutesStayScoped is the same for Podman's
// native routes, where a create can replace, ignore or return an existing
// resource.
func TestServeChainTwoOwnersPodmanRoutesStayScoped(t *testing.T) {
	h := newTenancyHarness(t, true, nil)
	seedTwoOwners(h.daemon)
	before := h.daemon.mutations()

	secretLabels := url.QueryEscape("{}")
	for _, a := range []tenantAttempt{
		{"libpod secret replace over B secret", "POST", "/v1.45/libpod/secrets/create?name=b-secret&replace=true&labels=" + secretLabels, "stolen"},
		{"libpod secret ignore over B secret", "POST", "/v1.45/libpod/secrets/create?name=b-secret&ignore=true", "x"},
		{"libpod secret replace by case-variant flag", "POST", "/v1.45/libpod/secrets/create?name=b-secret&Replace=true", "x"},
		{"libpod volume create over B volume", "POST", "/v1.45/libpod/volumes/create", `{"Name":"b-vol"}`},
		{"libpod network create ignoreIfExists over B network", "POST", "/v1.45/libpod/networks/create?ignoreIfExists=true", `{"name":"b-net"}`},
		{"libpod network create ignoreIfExists, case-variant key", "POST", "/v1.45/libpod/networks/create?ignoreIfExists=true", `{"Name":"b-net"}`},
		{"libpod container uses B image", "POST", "/v1.45/libpod/containers/create", `{"name":"x1","image":"b-image:1"}`},
		{"libpod container joins B container namespace", "POST", "/v1.45/libpod/containers/create", `{"name":"x2","image":"a-image:1","netns":{"nsmode":"container","value":"b-web"}}`},
		{"libpod inspect B network", "GET", "/v1.45/libpod/networks/b-net/json", ""},
		{"libpod host-wide stats", "GET", "/v1.45/libpod/containers/stats", ""},
		{"libpod pod prune", "POST", "/v1.45/libpod/pods/prune", ""},
		{"libpod system prune", "POST", "/v1.45/libpod/system/prune", ""},
		{"libpod build", "POST", "/v1.45/libpod/build?t=x", ""},
	} {
		status, body := h.do(ownerScopesIPA, a.method, a.path, a.body)
		requireRefused(t, a.label, status, body)
	}
	if after := h.daemon.mutations(); len(after) != len(before) {
		t.Errorf("daemon saw mutations from refused requests: %v", after[len(before):])
	}
	if got := h.daemon.dataOf("secret", "b-secret"); got != "data-of-B" {
		t.Errorf("B secret data = %q, want data-of-B", got)
	}
	if owner, _ := h.daemon.ownerOf("secret", "b-secret"); owner != "B" {
		t.Errorf("B secret owner = %q after A's replace, want B", owner)
	}

	// Own names still work, and a second owner's create of a fresh name too.
	for _, a := range []struct{ remote, path, body string }{
		{ownerScopesIPA, "/v1.45/libpod/secrets/create?name=a-new&replace=true", "a-data"},
		{ownerScopesIPB, "/v1.45/libpod/volumes/create", `{"Name":"b-new"}`},
		{ownerScopesIPB, "/v1.45/libpod/networks/create?ignoreIfExists=true", `{"name":"b-newnet"}`},
	} {
		if status, body := h.do(a.remote, http.MethodPost, a.path, a.body); status >= 400 {
			t.Errorf("own create %s: status %d, body %s", a.path, status, body)
		}
	}
	if owner, _ := h.daemon.ownerOf("secret", "a-new"); owner != "A" {
		t.Errorf("new secret owner = %q, want A", owner)
	}
}
