package responsefilter

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// routeOptionCase is one route of Filter.ModifyResponse's dispatch together
// with the two facts that have to hold for it: an option that cannot rewrite
// any field of its body leaves the body alone, and an option that can still
// rewrites it.
//
// unrelated is RedactHostTopology for every route but /info, because
// RedactHostTopology only ever rewrites GET /info's Containerd,
// FirewallBackend, DiscoveredDevices and NRI fields. /info gets
// RedactContainerEnv instead, which is the option no /info field carries.
type routeOptionCase struct {
	name string
	// method is the request method the route is reached on. Only the two
	// libpod network-inspect spellings care, and only because the bare
	// /libpod/networks/{name} form is GET-only.
	method string
	path   string
	// upstream is the daemon's body, spelled with the indentation a decode
	// and re-encode round trip would flatten. That is what makes the
	// byte-identical assertion below detect a rewrite that changed nothing:
	// a route that parsed this body and wrote it back would emit compact
	// JSON even with no field redacted.
	upstream string
	// sentinel is a substring of upstream that relevant removes.
	sentinel  string
	unrelated Options
	relevant  Options
}

var routeOptionCases = []routeOptionCase{
	{
		name:      "container inspect",
		method:    http.MethodGet,
		path:      "/v1.53/containers/abc123/json",
		upstream:  "{\n\t\"Id\": \"abc123\",\n\t\"Config\": {\"Env\": [\"SECRET=shh\"]}\n}",
		sentinel:  "SECRET=shh",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactContainerEnv: true},
	},
	{
		name:      "container inspect, sensitive data only",
		method:    http.MethodGet,
		path:      "/v1.53/containers/abc123/json",
		upstream:  "{\n\t\"Id\": \"abc123\",\n\t\"Mounts\": [{\"Source\": \"/srv/host-secret\"}]\n}",
		sentinel:  "/srv/host-secret",
		unrelated: Options{RedactSensitiveData: true},
		relevant:  Options{RedactMountPaths: true},
	},
	{
		name:      "image inspect",
		method:    http.MethodGet,
		path:      "/v1.53/images/myapp/json",
		upstream:  "{\n\t\"Id\": \"sha256:aa\",\n\t\"Config\": {\"Env\": [\"SECRET=shh\"]}\n}",
		sentinel:  "SECRET=shh",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactContainerEnv: true},
	},
	{
		name:      "image inspect, network topology only",
		method:    http.MethodGet,
		path:      "/v1.53/images/myapp/json",
		upstream:  "{\n\t\"GraphDriver\": {\"Name\": \"overlay2\", \"Data\": {\"UpperDir\": \"/var/lib/docker/overlay2/aa/diff\"}}\n}",
		sentinel:  "/var/lib/docker/overlay2/aa/diff",
		unrelated: Options{RedactNetworkTopology: true},
		relevant:  Options{RedactMountPaths: true},
	},
	{
		name:      "container list",
		method:    http.MethodGet,
		path:      "/v1.53/containers/json",
		upstream:  "[\n\t{\"Id\": \"abc123\", \"Mounts\": [{\"Source\": \"/srv/host-secret\"}]}\n]",
		sentinel:  "/srv/host-secret",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactMountPaths: true},
	},
	{
		name:      "network list",
		method:    http.MethodGet,
		path:      "/v1.53/networks",
		upstream:  "[\n\t{\"Name\": \"bridge\", \"IPAM\": {\"Config\": [{\"Subnet\": \"10.42.0.0/16\"}]}}\n]",
		sentinel:  "10.42.0.0/16",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactNetworkTopology: true},
	},
	{
		name:      "network inspect",
		method:    http.MethodGet,
		path:      "/v1.53/networks/bridge",
		upstream:  "{\n\t\"Name\": \"bridge\",\n\t\"IPAM\": {\"Config\": [{\"Subnet\": \"10.42.0.0/16\"}]}\n}",
		sentinel:  "10.42.0.0/16",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactNetworkTopology: true},
	},
	{
		name:      "volume list",
		method:    http.MethodGet,
		path:      "/v1.53/volumes",
		upstream:  "{\n\t\"Volumes\": [{\"Name\": \"data\", \"Mountpoint\": \"/var/lib/docker/volumes/data/_data\"}]\n}",
		sentinel:  "/var/lib/docker/volumes/data/_data",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactMountPaths: true},
	},
	{
		name:      "volume inspect",
		method:    http.MethodGet,
		path:      "/v1.53/volumes/data",
		upstream:  "{\n\t\"Name\": \"data\",\n\t\"Mountpoint\": \"/var/lib/docker/volumes/data/_data\"\n}",
		sentinel:  "/var/lib/docker/volumes/data/_data",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactMountPaths: true},
	},
	{
		name:      "swarm unlock key",
		method:    http.MethodGet,
		path:      "/v1.53/swarm/unlockkey",
		upstream:  "{\n\t\"UnlockKey\": \"SWMKEY-1-abcdef\"\n}",
		sentinel:  "SWMKEY-1-abcdef",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactSensitiveData: true},
	},
	{
		name:      "info",
		method:    http.MethodGet,
		path:      "/v1.53/info",
		upstream:  "{\n\t\"Containerd\": {\"Address\": \"/run/containerd/containerd.sock\"}\n}",
		sentinel:  "/run/containerd/containerd.sock",
		unrelated: Options{RedactContainerEnv: true},
		relevant:  Options{RedactHostTopology: true},
	},
	{
		name:      "system data usage",
		method:    http.MethodGet,
		path:      "/v1.53" + SystemDataUsagePath,
		upstream:  "{\n\t\"Containers\": [{\"Mounts\": [{\"Source\": \"/srv/host-secret\"}]}]\n}",
		sentinel:  "/srv/host-secret",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactMountPaths: true},
	},
	{
		name:      "service list",
		method:    http.MethodGet,
		path:      "/v1.53/services",
		upstream:  "[\n\t{\"ID\": \"svc-1\", \"Spec\": {\"TaskTemplate\": {\"ContainerSpec\": {\"Env\": [\"SECRET=shh\"]}}}}\n]",
		sentinel:  "SECRET=shh",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactContainerEnv: true},
	},
	{
		name:      "service inspect",
		method:    http.MethodGet,
		path:      "/v1.53/services/svc-1",
		upstream:  "{\n\t\"ID\": \"svc-1\",\n\t\"Spec\": {\"TaskTemplate\": {\"ContainerSpec\": {\"Env\": [\"SECRET=shh\"]}}}\n}",
		sentinel:  "SECRET=shh",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactContainerEnv: true},
	},
	{
		name:      "task list",
		method:    http.MethodGet,
		path:      "/v1.53/tasks",
		upstream:  "[\n\t{\"ID\": \"task-1\", \"Spec\": {\"ContainerSpec\": {\"Env\": [\"SECRET=shh\"]}}}\n]",
		sentinel:  "SECRET=shh",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactContainerEnv: true},
	},
	{
		name:      "task inspect",
		method:    http.MethodGet,
		path:      "/v1.53/tasks/task-1",
		upstream:  "{\n\t\"ID\": \"task-1\",\n\t\"Spec\": {\"ContainerSpec\": {\"Env\": [\"SECRET=shh\"]}}\n}",
		sentinel:  "SECRET=shh",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactContainerEnv: true},
	},
	{
		name:      "secret list",
		method:    http.MethodGet,
		path:      "/v1.53/secrets",
		upstream:  "[\n\t{\"ID\": \"sec-1\", \"Spec\": {\"Data\": \"c2hoCg==\"}}\n]",
		sentinel:  "c2hoCg==",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactSensitiveData: true},
	},
	{
		name:      "secret inspect",
		method:    http.MethodGet,
		path:      "/v1.53/secrets/sec-1",
		upstream:  "{\n\t\"ID\": \"sec-1\",\n\t\"Spec\": {\"Data\": \"c2hoCg==\"}\n}",
		sentinel:  "c2hoCg==",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactSensitiveData: true},
	},
	{
		name:      "config list",
		method:    http.MethodGet,
		path:      "/v1.53/configs",
		upstream:  "[\n\t{\"ID\": \"cfg-1\", \"Spec\": {\"Data\": \"c2hoCg==\"}}\n]",
		sentinel:  "c2hoCg==",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactSensitiveData: true},
	},
	{
		name:      "config inspect",
		method:    http.MethodGet,
		path:      "/v1.53/configs/cfg-1",
		upstream:  "{\n\t\"ID\": \"cfg-1\",\n\t\"Spec\": {\"Data\": \"c2hoCg==\"}\n}",
		sentinel:  "c2hoCg==",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactSensitiveData: true},
	},
	{
		name:      "plugin list",
		method:    http.MethodGet,
		path:      "/v1.53/plugins",
		upstream:  "[\n\t{\"Name\": \"myplugin\", \"Settings\": {\"Env\": [\"API_KEY=secret\"]}}\n]",
		sentinel:  "API_KEY=secret",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactContainerEnv: true},
	},
	{
		name:      "plugin inspect",
		method:    http.MethodGet,
		path:      "/v1.53/plugins/myplugin/json",
		upstream:  "{\n\t\"Name\": \"myplugin\",\n\t\"Settings\": {\"Env\": [\"API_KEY=secret\"]}\n}",
		sentinel:  "API_KEY=secret",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactContainerEnv: true},
	},
	{
		name:      "node list",
		method:    http.MethodGet,
		path:      "/v1.53/nodes",
		upstream:  "[\n\t{\"ID\": \"node-1\", \"Status\": {\"Addr\": \"10.0.0.1\"}}\n]",
		sentinel:  "10.0.0.1",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactNetworkTopology: true},
	},
	{
		name:      "node inspect",
		method:    http.MethodGet,
		path:      "/v1.53/nodes/node-1",
		upstream:  "{\n\t\"ID\": \"node-1\",\n\t\"Status\": {\"Addr\": \"10.0.0.1\"}\n}",
		sentinel:  "10.0.0.1",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactNetworkTopology: true},
	},
	{
		name:      "swarm inspect",
		method:    http.MethodGet,
		path:      "/v1.53/swarm",
		upstream:  "{\n\t\"JoinTokens\": {\"Worker\": \"SWMTKN-1-worker\"}\n}",
		sentinel:  "SWMTKN-1-worker",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactSensitiveData: true},
	},
	{
		name:      "libpod container inspect",
		method:    http.MethodGet,
		path:      "/v5.8.1/libpod/containers/abc123/json",
		upstream:  "{\n\t\"Id\": \"abc123\",\n\t\"Config\": {\"Env\": [\"SECRET=shh\"]}\n}",
		sentinel:  "SECRET=shh",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactContainerEnv: true},
	},
	{
		name:      "libpod image inspect",
		method:    http.MethodGet,
		path:      "/v5.8.1/libpod/images/myapp/json",
		upstream:  "{\n\t\"Id\": \"sha256:aa\",\n\t\"Config\": {\"Env\": [\"SECRET=shh\"]}\n}",
		sentinel:  "SECRET=shh",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactContainerEnv: true},
	},
	{
		name:      "libpod volume inspect",
		method:    http.MethodGet,
		path:      "/v5.8.1/libpod/volumes/data/json",
		upstream:  "{\n\t\"Name\": \"data\",\n\t\"Mountpoint\": \"/var/lib/containers/storage/volumes/data/_data\"\n}",
		sentinel:  "/var/lib/containers/storage/volumes/data/_data",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactMountPaths: true},
	},
	{
		name:      "libpod volume list",
		method:    http.MethodGet,
		path:      "/v5.8.1/libpod/volumes/json",
		upstream:  "[\n\t{\"Name\": \"data\", \"Mountpoint\": \"/var/lib/containers/storage/volumes/data/_data\"}\n]",
		sentinel:  "/var/lib/containers/storage/volumes/data/_data",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactMountPaths: true},
	},
	{
		name:      "libpod network list",
		method:    http.MethodGet,
		path:      "/v5.8.1/libpod/networks/json",
		upstream:  "[\n\t{\"name\": \"podman\", \"subnets\": [{\"subnet\": \"10.88.0.0/16\"}]}\n]",
		sentinel:  "10.88.0.0/16",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactNetworkTopology: true},
	},
	{
		name:      "libpod network inspect",
		method:    http.MethodGet,
		path:      "/v5.8.1/libpod/networks/podman/json",
		upstream:  "{\n\t\"name\": \"podman\",\n\t\"subnets\": [{\"subnet\": \"10.88.0.0/16\"}]\n}",
		sentinel:  "10.88.0.0/16",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactNetworkTopology: true},
	},
	{
		name:      "libpod network inspect, bare spelling",
		method:    http.MethodGet,
		path:      "/v5.8.1/libpod/networks/podman",
		upstream:  "{\n\t\"name\": \"podman\",\n\t\"subnets\": [{\"subnet\": \"10.88.0.0/16\"}]\n}",
		sentinel:  "10.88.0.0/16",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactNetworkTopology: true},
	},
	{
		name:      "libpod secret inspect",
		method:    http.MethodGet,
		path:      "/v5.8.1/libpod/secrets/sec-1/json",
		upstream:  "{\n\t\"ID\": \"sec-1\",\n\t\"SecretData\": \"c2hoCg==\"\n}",
		sentinel:  "c2hoCg==",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactSensitiveData: true},
	},
	{
		name:      "libpod secret list",
		method:    http.MethodGet,
		path:      "/v5.8.1/libpod/secrets/json",
		upstream:  "[\n\t{\"ID\": \"sec-1\", \"SecretData\": \"c2hoCg==\"}\n]",
		sentinel:  "c2hoCg==",
		unrelated: Options{RedactHostTopology: true},
		relevant:  Options{RedactSensitiveData: true},
	},
}

// newRouteResponseForTest builds the upstream response a route case is run
// against. The ETag is the second half of the passthrough assertion:
// writeResponseBody clears it through ClearUpstreamRepresentationHeaders, so
// an ETag that survives proves the body was never substituted, independently
// of whether any field would have changed.
func newRouteResponseForTest(t *testing.T, tc routeOptionCase) *http.Response {
	t.Helper()

	resp := newResponseForTest(t, tc.method, tc.path, tc.upstream)
	resp.Header.Set("ETag", `"upstream-validator"`)
	return resp
}

// TestModifyResponse_UnrelatedOptionLeavesRouteUntouched pins the fix for
// dispatching on Enabled(): an enabled option that cannot rewrite a field of
// a route's body must leave that route's response exactly as the daemon sent
// it, headers included. Before the per-route gates, container inspect and
// image inspect decoded and re-encoded on any of the five options, which
// flattened the body and turned an oversized or malformed one into a 502 on
// a read no enabled option applied to.
func TestModifyResponse_UnrelatedOptionLeavesRouteUntouched(t *testing.T) {
	t.Parallel()

	for _, tc := range routeOptionCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			filter := New(tc.unrelated)
			resp := newRouteResponseForTest(t, tc)

			if err := filter.ModifyResponse(resp); err != nil {
				t.Fatalf("ModifyResponse() error = %v, want nil", err)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if string(body) != tc.upstream {
				t.Fatalf("body = %q, want byte-identical passthrough %q", body, tc.upstream)
			}
			if got := resp.Header.Get("ETag"); got != `"upstream-validator"` {
				t.Fatalf("ETag = %q, want the upstream validator preserved", got)
			}
			if resp.ContentLength != int64(len(tc.upstream)) {
				t.Fatalf("ContentLength = %d, want %d", resp.ContentLength, len(tc.upstream))
			}
		})
	}
}

// TestModifyResponse_RelevantOptionStillRedactsRoute is the other half: the
// per-route gates must not have narrowed a route out of a policy that does
// apply to it.
func TestModifyResponse_RelevantOptionStillRedactsRoute(t *testing.T) {
	t.Parallel()

	for _, tc := range routeOptionCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			filter := New(tc.relevant)
			resp := newRouteResponseForTest(t, tc)

			if err := filter.ModifyResponse(resp); err != nil {
				t.Fatalf("ModifyResponse() error = %v, want nil", err)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if strings.Contains(string(body), tc.sentinel) {
				t.Fatalf("body = %s, want %q redacted", body, tc.sentinel)
			}
		})
	}
}

// TestModifyResponse_UnrelatedOptionPassesUnparseableInspectBody is the
// reported symptom rather than its shape: an inspect body this package cannot
// parse was answered with a 502 when the only enabled option was one that
// could not have rewritten it. Every other route already returned early on
// its own options, so the two inspect handlers are the whole set.
func TestModifyResponse_UnrelatedOptionPassesUnparseableInspectBody(t *testing.T) {
	t.Parallel()

	paths := []string{
		"/v1.53/containers/abc123/json",
		"/v1.53/images/myapp/json",
		"/v5.8.1/libpod/containers/abc123/json",
		"/v5.8.1/libpod/images/myapp/json",
	}
	const upstream = "{\"Config\": {\"Env\": [\"SECRET=shh\"]}} trailing garbage"

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			filter := New(Options{RedactHostTopology: true})
			resp := newResponseForTest(t, http.MethodGet, path, upstream)

			if err := filter.ModifyResponse(resp); err != nil {
				t.Fatalf("ModifyResponse() error = %v, want nil", err)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if string(body) != upstream {
				t.Fatalf("body = %q, want byte-identical passthrough", body)
			}
		})
	}
}
