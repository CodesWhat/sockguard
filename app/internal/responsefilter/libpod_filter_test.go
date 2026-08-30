package responsefilter

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Every fixture in this file is transcribed from Podman v5.8.1's own types,
// named at the fixture that uses it. The version matters: internal/cmd's
// rules.go pins the same release, and the two libpod shapes that differ from
// their Docker-compat siblings (network inspect, secret inspect) differ in
// ways no amount of reading the Docker API reference would reveal.
//
// Each family gets two legs. The libpod leg asserts the sensitive value is
// gone. The compat leg asserts the Docker-compat path still redacts an
// equivalent value, so the libpod assertion cannot start passing because the
// filter stopped running — the anti-vacuity check
// TestLibpodSystemDataUsageHasNothingToRedact established for this package.

// allRedactions turns on every response-side option. It is what an operator
// who changed nothing gets: RedactContainerEnv, RedactMountPaths,
// RedactNetworkTopology and RedactSensitiveData all default to true.
var allRedactions = Options{
	RedactContainerEnv:    true,
	RedactMountPaths:      true,
	RedactNetworkTopology: true,
	RedactSensitiveData:   true,
	RedactHostTopology:    true,
}

// libpodBodyForTest runs one GET request/response pair through the filter and
// returns the body the client would receive.
func libpodBodyForTest(t *testing.T, opts Options, path, upstream string) string {
	t.Helper()
	return libpodBodyForMethodTest(t, opts, http.MethodGet, path, upstream)
}

// libpodBodyForMethodTest is libpodBodyForTest for a request that is not a
// GET. Only the bare /libpod/networks/{name} inspect alias is method-sensitive
// — Podman serves a different handler with a different body on DELETE of the
// same path — so everything else uses the GET wrapper above.
func libpodBodyForMethodTest(t *testing.T, opts Options, method, path, upstream string) string {
	t.Helper()

	resp := newResponseForTest(t, method, path, upstream)
	if err := New(opts).ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse(%s %s): %v", method, path, err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body (%s %s): %v", method, path, err)
	}
	return string(body)
}

// assertAbsent fails when any sentinel survived into body.
func assertAbsent(t *testing.T, label, body string, sentinels ...string) {
	t.Helper()
	for _, sentinel := range sentinels {
		if strings.Contains(body, sentinel) {
			t.Errorf("%s: %q survived redaction in %s", label, sentinel, body)
		}
	}
}

// assertPresent fails when a value that must NOT be redacted went missing.
// Redacting a whole body would pass every assertAbsent in this file, so each
// family also pins something the client still needs.
func assertPresent(t *testing.T, label, body string, wanted ...string) {
	t.Helper()
	for _, want := range wanted {
		if !strings.Contains(body, want) {
			t.Errorf("%s: %q was removed but should survive; got %s", label, want, body)
		}
	}
}

func libpodLegacyCNIPluginsForTest(t *testing.T, body string) []map[string]any {
	t.Helper()

	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decode legacy CNI response: %v", err)
	}
	var network map[string]any
	switch value := decoded.(type) {
	case map[string]any:
		network = value
	case []any:
		if len(value) != 1 {
			t.Fatalf("legacy CNI response has %d array elements, want 1", len(value))
		}
		var ok bool
		network, ok = value[0].(map[string]any)
		if !ok {
			t.Fatalf("legacy CNI array element has type %T, want object", value[0])
		}
	default:
		t.Fatalf("legacy CNI response has type %T, want object or array", decoded)
	}
	values, ok := network["plugins"].([]any)
	if !ok {
		t.Fatalf("legacy CNI plugins has type %T, want array", network["plugins"])
	}
	plugins := make([]map[string]any, 0, len(values))
	for i, value := range values {
		plugin, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("legacy CNI plugin %d has type %T, want object", i, value)
		}
		plugins = append(plugins, plugin)
	}
	if len(plugins) == 0 {
		t.Fatal("legacy CNI response has no plugins")
	}
	return plugins
}

func addStaleRepresentationMetadata(resp *http.Response) {
	for _, name := range []string{
		"Accept-Ranges",
		"Content-Digest",
		"Content-Encoding",
		"Content-Language",
		"Content-Length",
		"Content-Location",
		"Content-Range",
		"Digest",
		"ETag",
		"Last-Modified",
		"Repr-Digest",
		"Trailer",
		"Transfer-Encoding",
	} {
		resp.Header.Set(name, "stale-upstream-value")
	}
	resp.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp.Header.Set("X-Upstream-Metadata", "keep-me")
	resp.TransferEncoding = []string{"chunked"}
	resp.Trailer = http.Header{
		"Digest":             []string{"sha-256=:stale-upstream-trailer:"},
		"X-Upstream-Trailer": []string{"must-not-reach-client"},
	}
}

func assertRewrittenRepresentationMetadata(t *testing.T, resp *http.Response) {
	t.Helper()
	for _, name := range []string{
		"Accept-Ranges",
		"Content-Digest",
		"Content-Encoding",
		"Content-Language",
		"Content-Location",
		"Content-Range",
		"Digest",
		"ETag",
		"Last-Modified",
		"Repr-Digest",
		"Trailer",
		"Transfer-Encoding",
	} {
		if got := resp.Header.Values(name); len(got) != 0 {
			t.Errorf("%s = %#v, want cleared after body rewrite", name, got)
		}
	}
	if got, want := resp.Header.Get("Content-Length"), strconv.FormatInt(resp.ContentLength, 10); got != want {
		t.Errorf("Content-Length = %q, want rewritten length %q", got, want)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want preserved JSON type", got)
	}
	if got := resp.Header.Get("X-Upstream-Metadata"); got != "keep-me" {
		t.Errorf("X-Upstream-Metadata = %q, want unrelated metadata preserved", got)
	}
	if resp.TransferEncoding != nil {
		t.Errorf("TransferEncoding = %#v, want fixed-length rewritten response", resp.TransferEncoding)
	}
	if len(resp.Trailer) != 0 {
		t.Errorf("Trailer = %#v, want cleared after body rewrite", resp.Trailer)
	}
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

// libpodContainerInspectUpstream is a GET /libpod/containers/{id}/json body:
// libpod/define.InspectContainerData at v5.8.1.
//
// The keys this exercises are the ones that decide whether the compat handler
// can be reused. Config.Env, Mounts[].Source, HostConfig.Binds,
// HostConfig.NetworkMode and the NetworkSettings address block all carry the
// identical json tags Docker uses, which is why modifyContainerInspect is
// routed here rather than reimplemented. AdditionalMACAddresses is the one
// field on this shape Docker has no counterpart for: it sits on
// InspectBasicNetworkConfig, so it appears both at NetworkSettings level and
// inside each Networks entry, and it is a list of MAC addresses.
const libpodContainerInspectUpstream = `{
  "Id": "ctr-a",
  "Name": "team-a-web",
  "Config": {"Env": ["PATH=/usr/bin", "DB_PASSWORD=libpod-env-secret"], "Labels": {"owner": "team-a"}},
  "Mounts": [{"Type": "bind", "Source": "/host/team-a-secrets", "Destination": "/run/secrets"}],
  "HostConfig": {
    "Binds": ["/host/team-a-binds:/data:rw"],
    "NetworkMode": "container:ctr-b-netns"
  },
  "NetworkSettings": {
    "Bridge": "podman1",
    "SandboxID": "sandbox-abcdef",
    "SandboxKey": "/run/netns/netns-abcdef",
    "EndpointID": "endpoint-abcdef",
    "Gateway": "10.89.0.1",
    "IPAddress": "10.89.0.7",
    "IPPrefixLen": 24,
    "MacAddress": "aa:bb:cc:00:00:07",
    "AdditionalMACAddresses": ["aa:bb:cc:00:00:08"],
    "SecondaryIPAddresses": [{"Addr": "10.89.0.9", "PrefixLen": 24}],
    "Networks": {
      "team-a-net": {
        "NetworkID": "net-team-a",
        "Gateway": "10.89.0.1",
        "IPAddress": "10.89.0.7",
        "MacAddress": "aa:bb:cc:00:00:07",
        "AdditionalMACAddresses": ["aa:bb:cc:00:00:0a"],
        "SecondaryIPv6Addresses": [{"Addr": "fd00::9", "PrefixLen": 64}]
      }
    }
  }
}`

// libpodCompatContainerInspectUpstream is the same container as a Docker
// Engine body, for the anti-vacuity leg.
const libpodCompatContainerInspectUpstream = `{
  "Id": "ctr-a",
  "Config": {"Env": ["DB_PASSWORD=compat-env-secret"]},
  "Mounts": [{"Source": "/host/compat-secrets", "Destination": "/run/secrets"}],
  "HostConfig": {"Binds": ["/host/compat-binds:/data:rw"], "NetworkMode": "container:other"},
  "NetworkSettings": {"Bridge": "docker0", "IPAddress": "172.17.0.4", "Networks": {"bridge": {"NetworkID": "compat-net", "IPAddress": "172.17.0.4"}}}
}`

func TestLibpodContainerInspectIsRedacted(t *testing.T) {
	t.Parallel()

	t.Run("libpod", func(t *testing.T) {
		t.Parallel()
		body := libpodBodyForTest(t, allRedactions, "/v5.8.1/libpod/containers/ctr-a/json", libpodContainerInspectUpstream)
		assertAbsent(t, "libpod container inspect", body,
			"libpod-env-secret",
			"/host/team-a-secrets",
			"/host/team-a-binds",
			"container:ctr-b-netns",
			"podman1",
			"sandbox-abcdef",
			"/run/netns/netns-abcdef",
			"endpoint-abcdef",
			"10.89.0.1",
			"10.89.0.7",
			"10.89.0.9",
			"fd00::9",
			"aa:bb:cc:00:00:07",
			"aa:bb:cc:00:00:08",
			"aa:bb:cc:00:00:0a",
			"net-team-a",
		)
		// The response is redacted, not emptied: identity and the owner label
		// a monitoring client actually reads must survive.
		assertPresent(t, "libpod container inspect", body, `"ctr-a"`, `"team-a"`, "team-a-net")
	})

	t.Run("compat is still redacted", func(t *testing.T) {
		t.Parallel()
		body := libpodBodyForTest(t, allRedactions, "/v1.51/containers/ctr-a/json", libpodCompatContainerInspectUpstream)
		assertAbsent(t, "compat container inspect", body,
			"compat-env-secret", "/host/compat-secrets", "/host/compat-binds",
			"container:other", "docker0", "172.17.0.4", "compat-net",
		)
	})
}

func TestLibpodObjectRewriteClearsStaleRepresentationMetadata(t *testing.T) {
	t.Parallel()
	resp := newResponseForTest(t, http.MethodGet, "/v5.8.1/libpod/containers/ctr-a/json", libpodContainerInspectUpstream)
	addStaleRepresentationMetadata(resp)

	if err := New(allRedactions).ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse() error = %v, want nil", err)
	}

	assertRewrittenRepresentationMetadata(t, resp)
}

// libpodContainerListUpstream is a GET /libpod/containers/json body:
// []entities.ListContainer at v5.8.1. Mounts is a []string, not the array of
// objects Docker's ContainerSummary carries, and pkg/ps/ps.go fills it from
// Container.UserVolumes(), which specgen builds out of mount DESTINATIONS.
const libpodContainerListUpstream = `[{"Id":"ctr-a","Names":["team-a-web"],"Mounts":["/run/secrets","/data"],"Networks":["team-a-net"],"Labels":{"owner":"team-a"}}]`

// TestLibpodContainerListIsNotRewritten pins the one endpoint in the libpod
// read family that is deliberately passed through, and why. Two things would
// break if it were routed to modifyContainerList: nothing in the body is a
// host path to redact, and redactMountObjects would reject the []string
// Mounts as an unexpected type, turning every `podman ps` into a 502.
func TestLibpodContainerListIsNotRewritten(t *testing.T) {
	t.Parallel()

	t.Run("libpod list is returned byte for byte", func(t *testing.T) {
		t.Parallel()
		body := libpodBodyForTest(t, allRedactions, "/v5.8.1/libpod/containers/json", libpodContainerListUpstream)
		if body != libpodContainerListUpstream {
			t.Fatalf("libpod container list was rewritten:\n got: %s\nwant: %s", body, libpodContainerListUpstream)
		}
	})

	t.Run("Mounts entries are container-side destinations", func(t *testing.T) {
		t.Parallel()
		var list []struct {
			Mounts []string `json:"Mounts"`
		}
		if err := json.Unmarshal([]byte(libpodContainerListUpstream), &list); err != nil {
			t.Fatalf("decode libpod container list: %v", err)
		}
		if len(list) == 0 || len(list[0].Mounts) == 0 {
			t.Fatal("fixture has no Mounts, so it proves nothing")
		}
	})

	t.Run("compat list is still redacted", func(t *testing.T) {
		t.Parallel()
		const compat = `[{"Id":"ctr-a","Mounts":[{"Source":"/host/compat-secrets"}],"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.4"}}}}]`
		body := libpodBodyForTest(t, allRedactions, "/v1.51/containers/json", compat)
		assertAbsent(t, "compat container list", body, "/host/compat-secrets", "172.17.0.4")
	})
}

// ---------------------------------------------------------------------------
// Volumes
// ---------------------------------------------------------------------------

// libpodVolumeInspectUpstream is a GET /libpod/volumes/{name}/json body:
// entities.VolumeConfigResponse, which embeds libpod/define.InspectVolumeData
// with no wrapper key, so Mountpoint lands at the top level under the same
// json tag Docker uses.
const libpodVolumeInspectUpstream = `{"Name":"vol-a","Driver":"local","Mountpoint":"/var/lib/containers/storage/volumes/vol-a/_data","Labels":{"owner":"team-a"},"Scope":"local"}`

// libpodVolumeListUpstream is a GET /libpod/volumes/json body. libpod.ListVolumes
// writes abi.VolumeList's []*entities.VolumeListReport straight to the wire, so
// this is a BARE ARRAY — not Docker's {"Volumes":[…],"Warnings":[…]} envelope.
const libpodVolumeListUpstream = `[{"Name":"vol-a","Mountpoint":"/var/lib/containers/storage/volumes/vol-a/_data","Labels":{"owner":"team-a"}},` +
	`{"Name":"vol-b","Mountpoint":"/var/lib/containers/storage/volumes/vol-b/_data","Labels":{"owner":"team-b"}}]`

func TestLibpodVolumeMountpointIsRedacted(t *testing.T) {
	t.Parallel()

	t.Run("libpod inspect", func(t *testing.T) {
		t.Parallel()
		body := libpodBodyForTest(t, allRedactions, "/v5.8.1/libpod/volumes/vol-a/json", libpodVolumeInspectUpstream)
		assertAbsent(t, "libpod volume inspect", body, "/var/lib/containers/storage/volumes/vol-a/_data")
		assertPresent(t, "libpod volume inspect", body, `"vol-a"`, `"team-a"`)
	})

	t.Run("libpod list", func(t *testing.T) {
		t.Parallel()
		body := libpodBodyForTest(t, allRedactions, "/v5.8.1/libpod/volumes/json", libpodVolumeListUpstream)
		assertAbsent(t, "libpod volume list", body,
			"/var/lib/containers/storage/volumes/vol-a/_data",
			"/var/lib/containers/storage/volumes/vol-b/_data",
		)
		assertPresent(t, "libpod volume list", body, `"vol-a"`, `"vol-b"`)
		if !strings.HasPrefix(strings.TrimSpace(body), "[") {
			t.Errorf("libpod volume list envelope changed shape: %s", body)
		}
	})

	t.Run("compat is still redacted", func(t *testing.T) {
		t.Parallel()
		const compatInspect = `{"Name":"vol-a","Mountpoint":"/var/lib/docker/volumes/vol-a/_data"}`
		body := libpodBodyForTest(t, allRedactions, "/v1.51/volumes/vol-a", compatInspect)
		assertAbsent(t, "compat volume inspect", body, "/var/lib/docker/volumes/vol-a/_data")

		const compatList = `{"Volumes":[{"Name":"vol-a","Mountpoint":"/var/lib/docker/volumes/vol-a/_data"}],"Warnings":[]}`
		listBody := libpodBodyForTest(t, allRedactions, "/v1.51/volumes", compatList)
		assertAbsent(t, "compat volume list", listBody, "/var/lib/docker/volumes/vol-a/_data")
	})
}

func TestLibpodStreamingListRewriteClearsStaleRepresentationMetadata(t *testing.T) {
	t.Parallel()
	resp := newResponseForTest(t, http.MethodGet, "/v5.8.1/libpod/volumes/json", libpodVolumeListUpstream)
	addStaleRepresentationMetadata(resp)

	if err := New(allRedactions).ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse() error = %v, want nil", err)
	}

	assertRewrittenRepresentationMetadata(t, resp)
}

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

// libpodNetworkInspectUpstream is a GET /libpod/networks/{id}/json body:
// entities.NetworkInspectReport, which embeds go.podman.io/common's
// libnetwork types.Network and adds the lowercase-keyed containers map.
//
// Not one key here is a key redactNetworkTopology looks for. There is no
// IPAM, no Status, no capitalized Containers and no Peers; the addresses live
// in subnets/routes/network_dns_servers and the per-container disclosure in
// the lowercase containers map.
const libpodNetworkInspectUpstream = `{
  "name": "team-a-net",
  "id": "net-team-a",
  "driver": "bridge",
  "network_interface": "podman1",
  "subnets": [{"subnet": "10.89.0.0/24", "gateway": "10.89.0.1", "lease_range": {"start_ip": "10.89.0.10", "end_ip": "10.89.0.20"}}],
  "routes": [{"destination": "10.90.0.0/24", "gateway": "10.89.0.254", "metric": 100}],
  "network_dns_servers": ["10.89.0.53"],
  "ipv6_enabled": false,
  "internal": false,
  "dns_enabled": true,
  "labels": {"owner": "team-a"},
  "ipam_options": {"driver": "host-local"},
  "containers": {
    "ctr-b": {"name": "team-b-web", "interfaces": {"eth0": {"subnets": [{"ipnet": "10.89.0.42/24", "gateway": "10.89.0.1"}], "mac_address": "aa:bb:cc:00:00:42"}}}
  }
}`

// libpodNetworkListUpstream is a GET /libpod/networks/json body: a bare array
// of types.Network, with no containers map.
const libpodNetworkListUpstream = `[{"name":"team-a-net","id":"net-team-a","network_interface":"podman1",` +
	`"subnets":[{"subnet":"10.89.0.0/24","gateway":"10.89.0.1"}],"network_dns_servers":["10.89.0.53"],"labels":{"owner":"team-a"}}]`

// libpodLegacyCNIInspectUpstream is the raw CNI conflist returned by network
// inspect from Podman v2.2.1 through v3.4.4. The bridge fixture and its
// topology values come from v3.4.4's cni/87-podman-bridge.conflist; labels and
// the resource name are the non-topology metadata that callers still need.
const libpodLegacyCNIInspectUpstream = `{
  "cniVersion": "0.4.0",
  "name": "team-a-net",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "cni-podman0",
      "isGateway": true,
      "ipMasq": true,
      "hairpinMode": true,
      "ipam": {
        "type": "host-local",
        "routes": [{"dst": "0.0.0.0/0"}],
        "ranges": [[{"subnet": "10.88.0.0/16", "gateway": "10.88.0.1"}]]
      }
    },
    {"type": "portmap", "capabilities": {"portMappings": true}},
    {"type": "firewall"},
    {"type": "tuning"}
  ],
  "labels": {"owner": "team-a", "purpose": "monitoring"}
}`

// Podman v2.2.1 through v3.4.4 writes the selected host parent interface to a
// macvlan plugin's master field. Native inspect returns that raw field.
const libpodLegacyCNIMacVLANInspectUpstream = `{
  "cniVersion": "0.4.0",
  "name": "team-a-macvlan",
  "plugins": [
    {
      "type": "macvlan",
      "master": "enp3s0",
      "mode": "bridge",
      "ipam": {"type": "dhcp"}
    }
  ],
  "labels": {"owner": "team-a"}
}`

// host-local kept this flat form for backward compatibility after ranges was
// added. Podman returns a hand-authored valid conflist byte-for-byte on inspect,
// so both representations can reach the response filter.
const libpodLegacyCNIFlatIPAMInspectUpstream = `{
  "cniVersion": "0.4.0",
  "name": "team-a-flat-ipam",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "cni-podman9",
      "ipam": {
        "type": "host-local",
        "subnet": "10.77.0.0/24",
        "rangeStart": "10.77.0.10",
        "rangeEnd": "10.77.0.200",
        "gateway": "10.77.0.1",
        "customAllocatorMetadata": "keep-me"
      }
    }
  ],
  "labels": {"owner": "team-a"}
}`

// Podman v2/v3 list reports embed libcni.NetworkConfigList. encoding/json
// therefore exposes the Go field names Plugins and Bytes, and each plugin is
// another NetworkConfig with its own Bytes copy. Those byte slices are base64
// representations of the complete raw CNI documents, including every value
// removed from the structured inspect form.
const libpodLegacyCNIBridgeBytes = `{"type":"bridge","bridge":"cni-podman0","isGateway":true,"ipMasq":true,"hairpinMode":true,"ipam":{"type":"host-local","routes":[{"dst":"0.0.0.0/0"}],"ranges":[[{"subnet":"10.88.0.0/16","gateway":"10.88.0.1"}]]}}`

func libpodLegacyCNIListUpstream(t *testing.T) (string, string, string) {
	t.Helper()
	conflistBytes := base64.StdEncoding.EncodeToString([]byte(libpodLegacyCNIInspectUpstream))
	bridgeBytes := base64.StdEncoding.EncodeToString([]byte(libpodLegacyCNIBridgeBytes))
	payload := []map[string]any{{
		"Name":         "team-a-net",
		"CNIVersion":   "0.4.0",
		"DisableCheck": false,
		"Plugins": []any{
			map[string]any{
				"Network": map[string]any{
					"cniVersion": "0.4.0",
					"name":       "team-a-net",
					"type":       "bridge",
					"ipam":       map[string]any{"type": "host-local"},
					"dns":        map[string]any{},
				},
				"Bytes": bridgeBytes,
			},
			map[string]any{
				"Network": map[string]any{"type": "portmap", "capabilities": map[string]any{"portMappings": true}, "dns": map[string]any{}},
				"Bytes":   base64.StdEncoding.EncodeToString([]byte(`{"type":"portmap","capabilities":{"portMappings":true}}`)),
			},
		},
		"Bytes":  conflistBytes,
		"Labels": map[string]any{"owner": "team-a", "purpose": "monitoring"},
	}}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal legacy CNI list fixture: %v", err)
	}
	return string(body), conflistBytes, bridgeBytes
}

// libpodNetworkTopologySentinels are the values that must not survive on
// either libpod network route.
var libpodNetworkTopologySentinels = []string{
	"podman1",
	"10.89.0.0/24",
	"10.89.0.1",
	"10.89.0.10",
	"10.89.0.20",
	"10.90.0.0/24",
	"10.89.0.254",
	"10.89.0.53",
	"team-b-web",
	"10.89.0.42/24",
	"aa:bb:cc:00:00:42",
}

func TestLibpodNetworkTopologyIsRedacted(t *testing.T) {
	t.Parallel()

	t.Run("libpod inspect, bare object", func(t *testing.T) {
		t.Parallel()
		body := libpodBodyForTest(t, allRedactions, "/v5.8.1/libpod/networks/net-team-a/json", libpodNetworkInspectUpstream)
		assertAbsent(t, "libpod network inspect", body, libpodNetworkTopologySentinels...)
		// ipam_options names the allocator, not an address, and maps onto
		// Docker's IPAM.Driver/Options, which the compat redactor also keeps.
		assertPresent(t, "libpod network inspect", body, `"team-a-net"`, `"net-team-a"`, "host-local", `"team-a"`)
	})

	t.Run("libpod inspect, single-element array envelope", func(t *testing.T) {
		t.Parallel()
		upstream := "[" + libpodNetworkInspectUpstream + "]"
		body := libpodBodyForTest(t, allRedactions, "/v5.8.1/libpod/networks/net-team-a/json", upstream)
		assertAbsent(t, "libpod network inspect (array)", body, libpodNetworkTopologySentinels...)
		if !strings.HasPrefix(strings.TrimSpace(body), "[") {
			t.Errorf("array envelope was not preserved: %s", body)
		}
		var decoded []map[string]any
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatalf("decode filtered array: %v", err)
		}
		if len(decoded) != 1 {
			t.Fatalf("array envelope holds %d elements, want 1", len(decoded))
		}
	})

	// register_networks.go at v5.8.1 points BOTH GET /libpod/networks/{name}/json
	// and the bare GET /libpod/networks/{name} at libpod.InspectNetwork, on
	// consecutive lines, with a swagger:operation block on only the first.
	// Redacting the suffixed spelling alone would leave the identical body
	// reachable one path segment away.
	t.Run("libpod inspect, bare path with no /json suffix", func(t *testing.T) {
		t.Parallel()
		body := libpodBodyForTest(t, allRedactions, "/v5.8.1/libpod/networks/net-team-a", libpodNetworkInspectUpstream)
		assertAbsent(t, "libpod network inspect (bare path)", body, libpodNetworkTopologySentinels...)
		assertPresent(t, "libpod network inspect (bare path)", body, `"team-a-net"`, `"net-team-a"`, "host-local")
	})

	// create and prune are collection actions only on POST. Podman's GET
	// /libpod/networks/{name} route still inspects networks with either name,
	// so method-independent keyword reservation would leak their topology.
	t.Run("libpod inspect, bare path with action-shaped network name", func(t *testing.T) {
		t.Parallel()
		for _, path := range []string{
			"/libpod/networks/create",
			"/v5.8.1/libpod/networks/prune",
		} {
			body := libpodBodyForTest(t, allRedactions, path, libpodNetworkInspectUpstream)
			assertAbsent(t, path, body, libpodNetworkTopologySentinels...)
			assertPresent(t, path, body, `"team-a-net"`, `"net-team-a"`, "host-local")
		}
	})

	t.Run("libpod list", func(t *testing.T) {
		t.Parallel()
		body := libpodBodyForTest(t, allRedactions, "/v5.8.1/libpod/networks/json", libpodNetworkListUpstream)
		assertAbsent(t, "libpod network list", body, "podman1", "10.89.0.0/24", "10.89.0.1", "10.89.0.53")
		assertPresent(t, "libpod network list", body, `"team-a-net"`, `"net-team-a"`)
	})

	// The bare-path alias must not swallow the collection-level routes that
	// share its shape. POST /libpod/networks/create answers with a full
	// types.Network (abi.NetworkCreate returns the filled-in network), so
	// treating it as an inspect would strip the subnet out of the reply to the
	// client that just chose it.
	t.Run("collection routes are not the bare inspect alias", func(t *testing.T) {
		t.Parallel()
		const created = `{"name":"team-a-net","id":"net-team-a","network_interface":"podman1",` +
			`"subnets":[{"subnet":"10.89.0.0/24","gateway":"10.89.0.1"}]}`
		for _, tc := range []struct{ method, path, upstream string }{
			{http.MethodPost, "/v5.8.1/libpod/networks/create", created},
			{http.MethodPost, "/v5.8.1/libpod/networks/prune", `[{"Id":"net-team-a","Err":null}]`},
			{http.MethodDelete, "/v5.8.1/libpod/networks/net-team-a", `[{"Name":"team-a-net","Err":null}]`},
		} {
			body := libpodBodyForMethodTest(t, allRedactions, tc.method, tc.path, tc.upstream)
			if body != tc.upstream {
				t.Errorf("%s %s was rewritten:\n got: %s\nwant: %s", tc.method, tc.path, body, tc.upstream)
			}
		}
	})

	t.Run("compat is still redacted", func(t *testing.T) {
		t.Parallel()
		const compatInspect = `{"Name":"bridge","Id":"compat-net","IPAM":{"Driver":"default","Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]},` +
			`"Containers":{"ctr-b":{"Name":"compat-web","IPv4Address":"172.17.0.4/16"}},"Peers":[{"Name":"node-1","IP":"10.0.0.1"}]}`
		body := libpodBodyForTest(t, allRedactions, "/v1.51/networks/compat-net", compatInspect)
		assertAbsent(t, "compat network inspect", body, "172.17.0.0/16", "172.17.0.1", "compat-web", "172.17.0.4/16", "node-1", "10.0.0.1")
	})
}

func TestLibpodLegacyCNINetworkTopologyIsRedacted(t *testing.T) {
	t.Parallel()

	legacySentinels := []string{"cni-podman0", "0.0.0.0/0", "10.88.0.0/16", "10.88.0.1"}

	// v2.2.1 and v3.0.0 wrote the complete reports slice. v3.1.0 through
	// v3.4.4 wrote reports[0]. Exercise both envelopes, both inspect aliases,
	// versioned and unversioned routing, and action-shaped network names.
	inspectCases := []struct {
		name, path, upstream string
		wantArray            bool
	}{
		{"v2.2 array, versioned suffixed path", "/v2.2.1/libpod/networks/team-a-net/json", "[" + libpodLegacyCNIInspectUpstream + "]", true},
		{"v3.0 array, bare create-named GET", "/libpod/networks/create", "[" + libpodLegacyCNIInspectUpstream + "]", true},
		{"v3.1 object, unversioned suffixed path", "/libpod/networks/team-a-net/json", libpodLegacyCNIInspectUpstream, false},
		{"v3.4 object, versioned prune-named GET", "/v3.4.4/libpod/networks/prune", libpodLegacyCNIInspectUpstream, false},
	}
	for _, tc := range inspectCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := libpodBodyForTest(t, allRedactions, tc.path, tc.upstream)
			assertAbsent(t, tc.name, body, legacySentinels...)
			assertPresent(t, tc.name, body, `"team-a-net"`, `"team-a"`, `"monitoring"`, `"host-local"`, `"portmap"`, `"hairpinMode":true`)
			if got := strings.HasPrefix(strings.TrimSpace(body), "["); got != tc.wantArray {
				t.Errorf("array envelope = %v, want %v; body: %s", got, tc.wantArray, body)
			}
		})
	}

	for _, path := range []string{"/libpod/networks/json", "/v2.2.1/libpod/networks/json", "/v3.4.4/libpod/networks/json"} {
		t.Run("legacy list "+path, func(t *testing.T) {
			t.Parallel()
			upstream, conflistBytes, bridgeBytes := libpodLegacyCNIListUpstream(t)
			body := libpodBodyForTest(t, allRedactions, path, upstream)
			assertAbsent(t, path, body, append(legacySentinels, conflistBytes, bridgeBytes, `"Bytes"`)...)
			assertPresent(t, path, body, `"team-a-net"`, `"team-a"`, `"monitoring"`, `"host-local"`, `"portmap"`, `"portMappings":true`)
		})
	}

	// Podman 4.0 switched these routes to types.Network; keep the modern leg
	// explicit so adding CNI handling cannot narrow the v4/v5 behavior.
	t.Run("v4 modern object", func(t *testing.T) {
		t.Parallel()
		body := libpodBodyForTest(t, allRedactions, "/v4.0.0/libpod/networks/net-team-a/json", libpodNetworkInspectUpstream)
		assertAbsent(t, "v4 modern inspect", body, libpodNetworkTopologySentinels...)
		assertPresent(t, "v4 modern inspect", body, `"team-a-net"`, `"team-a"`, `"host-local"`)
	})

	// Collection writes and removal reports are not reads, even when their
	// response happens to contain a legacy CNI object.
	t.Run("legacy write responses pass through", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct{ method, path string }{
			{http.MethodPost, "/v3.4.4/libpod/networks/create"},
			{http.MethodPost, "/libpod/networks/prune"},
			{http.MethodDelete, "/v3.4.4/libpod/networks/team-a-net"},
		} {
			body := libpodBodyForMethodTest(t, allRedactions, tc.method, tc.path, libpodLegacyCNIInspectUpstream)
			if body != libpodLegacyCNIInspectUpstream {
				t.Errorf("%s %s was rewritten:\n got: %s\nwant: %s", tc.method, tc.path, body, libpodLegacyCNIInspectUpstream)
			}
		}
	})
}

func TestLibpodLegacyCNIMacVLANMasterIsRedacted(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, path, upstream string
	}{
		{
			name:     "v2 array on versioned suffixed path",
			path:     "/v2.2.1/libpod/networks/team-a-macvlan/json",
			upstream: "[" + libpodLegacyCNIMacVLANInspectUpstream + "]",
		},
		{
			name:     "v3 object on unversioned action-named bare path",
			path:     "/libpod/networks/create",
			upstream: libpodLegacyCNIMacVLANInspectUpstream,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := libpodBodyForTest(t, allRedactions, tc.path, tc.upstream)
			assertAbsent(t, tc.name, body, "enp3s0")
			assertPresent(t, tc.name, body,
				`"mode":"bridge"`,
				`"type":"macvlan"`,
				`"type":"dhcp"`,
				`"owner":"team-a"`,
			)
			plugins := libpodLegacyCNIPluginsForTest(t, body)
			if got := plugins[0]["master"]; got != redactedValue {
				t.Errorf("master = %#v, want %q", got, redactedValue)
			}
		})
	}
}

func TestLibpodLegacyCNIFlatHostLocalTopologyIsRedacted(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, path, upstream string
	}{
		{
			name:     "v2 array on versioned suffixed path",
			path:     "/v2.2.1/libpod/networks/team-a-flat-ipam/json",
			upstream: "[" + libpodLegacyCNIFlatIPAMInspectUpstream + "]",
		},
		{
			name:     "v3 object on versioned action-named bare path",
			path:     "/v3.4.4/libpod/networks/prune",
			upstream: libpodLegacyCNIFlatIPAMInspectUpstream,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := libpodBodyForTest(t, allRedactions, tc.path, tc.upstream)
			assertAbsent(t, tc.name, body, "10.77.0.0/24", "10.77.0.10", "10.77.0.200", "10.77.0.1")
			assertPresent(t, tc.name, body,
				`"type":"bridge"`,
				`"type":"host-local"`,
				`"customAllocatorMetadata":"keep-me"`,
				`"owner":"team-a"`,
			)

			plugins := libpodLegacyCNIPluginsForTest(t, body)
			ipam, ok := plugins[0]["ipam"].(map[string]any)
			if !ok {
				t.Fatalf("ipam has type %T, want object", plugins[0]["ipam"])
			}
			for _, key := range []string{"subnet", "gateway", "rangeStart", "rangeEnd"} {
				if got := ipam[key]; got != redactedValue {
					t.Errorf("ipam.%s = %#v, want %q", key, got, redactedValue)
				}
			}
		})
	}
}

// TestLibpodNetworkShapeHasNoCompatKeys pins the finding the separate
// redactor rests on: Podman's native network object shares no field name with
// the Docker-compat body, so porting the compat predicate to the libpod path
// without porting the field names would have matched the route and redacted
// nothing. If this fails because Podman adopted a compat key, that is the
// signal to revisit redactLibpodNetworkTopology, and this is where the news
// arrives.
func TestLibpodNetworkShapeHasNoCompatKeys(t *testing.T) {
	t.Parallel()

	var network map[string]json.RawMessage
	if err := json.Unmarshal([]byte(libpodNetworkInspectUpstream), &network); err != nil {
		t.Fatalf("decode libpod network: %v", err)
	}

	for _, compatKey := range []string{"IPAM", "Status", "Containers", "Peers"} {
		if _, present := network[compatKey]; present {
			t.Errorf("libpod network carries the compat key %q; redactNetworkTopology may now be reusable", compatKey)
		}
	}

	// The libpod keys the redactor does look for must all be here, or the
	// redaction assertions above are testing an empty body.
	wantKeys := []string{"containers", "network_dns_servers", "network_interface", "routes", "subnets"}
	var missing []string
	for _, key := range wantKeys {
		if _, present := network[key]; !present {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("libpod network fixture is missing %v, so the redaction assertions prove nothing", missing)
	}
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// libpodSecretInspectUpstream is a GET /libpod/secrets/{name}/json?showsecret=true
// body: entities.SecretInfoReport at v5.8.1.
//
// The plaintext is at the TOP LEVEL under SecretData. Spec here is
// {Name, Driver{Name,Options}, Labels} and has no Data field at all, which is
// exactly why redactSecretPayload's original Spec.Data rewrite was a no-op on
// this shape.
const libpodSecretInspectUpstream = `{
  "ID": "sec-a",
  "CreatedAt": "2026-08-01T00:00:00Z",
  "UpdatedAt": "2026-08-01T00:00:00Z",
  "Spec": {"Name": "team-a-db", "Driver": {"Name": "file", "Options": {}}, "Labels": {"owner": "team-a"}},
  "SecretData": "hunter2-libpod-plaintext"
}`

// libpodSecretListUpstream is a GET /libpod/secrets/json body: a bare array of
// the same report type.
const libpodSecretListUpstream = `[{"ID":"sec-a","Spec":{"Name":"team-a-db","Labels":{"owner":"team-a"}},"SecretData":"hunter2-list-plaintext"},` +
	`{"ID":"sec-b","Spec":{"Name":"team-b-db","Labels":{"owner":"team-b"}}}]`

func TestLibpodSecretDataIsRedacted(t *testing.T) {
	t.Parallel()

	t.Run("libpod inspect", func(t *testing.T) {
		t.Parallel()
		body := libpodBodyForTest(t, allRedactions, "/v5.8.1/libpod/secrets/team-a-db/json?showsecret=true", libpodSecretInspectUpstream)
		assertAbsent(t, "libpod secret inspect", body, "hunter2-libpod-plaintext")
		assertPresent(t, "libpod secret inspect", body, `"sec-a"`, "team-a-db")
	})

	t.Run("libpod list", func(t *testing.T) {
		t.Parallel()
		body := libpodBodyForTest(t, allRedactions, "/v5.8.1/libpod/secrets/json", libpodSecretListUpstream)
		assertAbsent(t, "libpod secret list", body, "hunter2-list-plaintext")
		assertPresent(t, "libpod secret list", body, `"sec-a"`, `"sec-b"`)
	})

	t.Run("podman docker-compat inspect", func(t *testing.T) {
		t.Parallel()
		// compat.InspectSecret reads ?showsecret= before it branches on
		// IsLibpodRequest, and SecretInfoReportCompat embeds SecretInfoReport,
		// so the compat path promotes SecretData to the top level too.
		const compat = `{"ID":"sec-a","Spec":{"Name":"team-a-db"},"SecretData":"hunter2-compat-plaintext","Version":{"Index":1}}`
		body := libpodBodyForTest(t, allRedactions, "/v1.51/secrets/sec-a?showsecret=true", compat)
		assertAbsent(t, "podman compat secret inspect", body, "hunter2-compat-plaintext")
	})

	t.Run("docker swarm spec data is still redacted", func(t *testing.T) {
		t.Parallel()
		const swarm = `{"ID":"sec-a","Spec":{"Name":"team-a-db","Data":"aHVudGVyMi1zd2FybQ=="}}`
		body := libpodBodyForTest(t, allRedactions, "/v1.51/secrets/sec-a", swarm)
		assertAbsent(t, "docker swarm secret inspect", body, "aHVudGVyMi1zd2FybQ==")
	})
}

// TestLibpodSecretShapeHasNoSpecData pins the shape difference that made the
// gap invisible: the compat redactor's only rewrite target does not exist on
// Podman's report.
func TestLibpodSecretShapeHasNoSpecData(t *testing.T) {
	t.Parallel()

	var report struct {
		Spec       map[string]json.RawMessage `json:"Spec"`
		SecretData *string                    `json:"SecretData"`
	}
	if err := json.Unmarshal([]byte(libpodSecretInspectUpstream), &report); err != nil {
		t.Fatalf("decode libpod secret: %v", err)
	}
	if _, present := report.Spec["Data"]; present {
		t.Error("libpod secret Spec carries Data; redactSecretPayload's compat rewrite may now be sufficient")
	}
	if report.SecretData == nil || *report.SecretData == "" {
		t.Fatal("fixture carries no SecretData, so the redaction assertion proves nothing")
	}
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

// TestLibpodPathPredicates pins the prefix definition and the list/inspect
// split. A list path that matched an inspect predicate would route
// /libpod/volumes/json into modifyVolumeInspect, which decodes an object and
// would fail closed on the bare array Podman actually sends.
func TestLibpodPathPredicates(t *testing.T) {
	t.Parallel()

	if got, want := LibpodPathPrefix, "/libpod"; got != want {
		t.Fatalf("LibpodPathPrefix = %q, want %q", got, want)
	}
	if LibpodSystemDataUsagePath != LibpodPathPrefix+SystemDataUsagePath {
		t.Fatalf("LibpodSystemDataUsagePath = %q, want %q", LibpodSystemDataUsagePath, LibpodPathPrefix+SystemDataUsagePath)
	}

	inspectCases := []struct {
		normPath   string
		collection string
		want       bool
	}{
		{"/libpod/containers/ctr-a/json", "containers", true},
		{"/libpod/volumes/vol-a/json", "volumes", true},
		{"/libpod/networks/net-a/json", "networks", true},
		{"/libpod/secrets/sec-a/json", "secrets", true},
		{"/libpod/volumes/json", "volumes", false},
		{"/libpod/networks/json", "networks", false},
		{"/libpod/secrets/json", "secrets", false},
		{"/libpod/containers/json", "containers", false},
		{"/libpod/containers//json", "containers", false},
		{"/libpod/containers/ctr-a/logs", "containers", false},
		{"/libpod/containers/ctr-a/json/extra", "containers", false},
		{"/containers/ctr-a/json", "containers", false},
		{"/libpod/system/df", "system", false},
	}
	for _, tc := range inspectCases {
		if got := isLibpodInspectPath(tc.normPath, tc.collection); got != tc.want {
			t.Errorf("isLibpodInspectPath(%q, %q) = %v, want %v", tc.normPath, tc.collection, got, tc.want)
		}
	}

	networkInspectCases := []struct {
		method   string
		normPath string
		want     bool
	}{
		{http.MethodGet, "/libpod/networks/net-a/json", true},
		{http.MethodGet, "/libpod/networks/net-a", true},
		{http.MethodGet, "/libpod/networks/json", false},
		{http.MethodGet, "/libpod/networks/create", true},
		{http.MethodGet, "/libpod/networks/prune", true},
		{http.MethodGet, "/libpod/networks/net-a/exists", false},
		{http.MethodGet, "/libpod/networks/", false},
		{http.MethodGet, "/libpod/networksfoo", false},
		{http.MethodGet, "/networks/net-a", false},
		// The bare alias is GET-only: DELETE /libpod/networks/{name} is a
		// different handler returning a removal report, and POST create/prune
		// are collection routes excluded by name above.
		{http.MethodDelete, "/libpod/networks/net-a", false},
		{http.MethodPost, "/libpod/networks/create", false},
		// The suffixed spelling stays method-independent, matching how every
		// other inspect predicate in this package is written.
		{http.MethodDelete, "/libpod/networks/net-a/json", true},
	}
	for _, tc := range networkInspectCases {
		if got := isLibpodNetworkInspectPath(tc.method, tc.normPath); got != tc.want {
			t.Errorf("isLibpodNetworkInspectPath(%q, %q) = %v, want %v", tc.method, tc.normPath, got, tc.want)
		}
	}

	libpodCases := map[string]bool{
		"/libpod/containers/json": true,
		"/libpod/system/df":       true,
		"/libpod":                 false,
		"/libpodx/containers":     false,
		"/containers/json":        false,
		"/system/df":              false,
	}
	for normPath, want := range libpodCases {
		if got := isLibpodPath(normPath); got != want {
			t.Errorf("isLibpodPath(%q) = %v, want %v", normPath, got, want)
		}
	}
}

// TestLibpodRedactionRespectsIndividualOptions proves each family is gated by
// the option that names it, so a deployment that turned one off does not lose
// the others and a deployment that turned all of them off gets an untouched
// body.
func TestLibpodRedactionRespectsIndividualOptions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		opts     Options
		path     string
		upstream string
		sentinel string
		redacted bool
	}{
		{
			name:     "volume mountpoint needs redact_mount_paths",
			opts:     Options{RedactSensitiveData: true},
			path:     "/v5.8.1/libpod/volumes/vol-a/json",
			upstream: libpodVolumeInspectUpstream,
			sentinel: "/var/lib/containers/storage/volumes/vol-a/_data",
		},
		{
			name:     "volume mountpoint is redacted when it is on",
			opts:     Options{RedactMountPaths: true},
			path:     "/v5.8.1/libpod/volumes/vol-a/json",
			upstream: libpodVolumeInspectUpstream,
			sentinel: "/var/lib/containers/storage/volumes/vol-a/_data",
			redacted: true,
		},
		{
			name:     "network topology needs redact_network_topology",
			opts:     Options{RedactSensitiveData: true},
			path:     "/v5.8.1/libpod/networks/net-team-a/json",
			upstream: libpodNetworkInspectUpstream,
			sentinel: "10.89.0.42/24",
		},
		{
			name:     "network topology is redacted when it is on",
			opts:     Options{RedactNetworkTopology: true},
			path:     "/v5.8.1/libpod/networks/net-team-a/json",
			upstream: libpodNetworkInspectUpstream,
			sentinel: "10.89.0.42/24",
			redacted: true,
		},
		{
			name:     "secret data needs redact_sensitive_data",
			opts:     Options{RedactMountPaths: true},
			path:     "/v5.8.1/libpod/secrets/team-a-db/json",
			upstream: libpodSecretInspectUpstream,
			sentinel: "hunter2-libpod-plaintext",
		},
		{
			name:     "secret data is redacted when it is on",
			opts:     Options{RedactSensitiveData: true},
			path:     "/v5.8.1/libpod/secrets/team-a-db/json",
			upstream: libpodSecretInspectUpstream,
			sentinel: "hunter2-libpod-plaintext",
			redacted: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := libpodBodyForTest(t, tc.opts, tc.path, tc.upstream)
			if got := strings.Contains(body, tc.sentinel); got == tc.redacted {
				t.Fatalf("%q present = %v, want %v; body: %s", tc.sentinel, got, !tc.redacted, body)
			}
		})
	}

	t.Run("no option leaves every libpod body untouched", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct{ path, upstream string }{
			{"/v5.8.1/libpod/containers/ctr-a/json", libpodContainerInspectUpstream},
			{"/v5.8.1/libpod/volumes/json", libpodVolumeListUpstream},
			{"/v5.8.1/libpod/networks/net-team-a/json", libpodNetworkInspectUpstream},
			{"/v5.8.1/libpod/secrets/json", libpodSecretListUpstream},
		} {
			if body := libpodBodyForTest(t, Options{}, tc.path, tc.upstream); body != tc.upstream {
				t.Errorf("%s was rewritten with no options set:\n got: %s\nwant: %s", tc.path, body, tc.upstream)
			}
		}
	})
}

// TestLibpodMalformedBodiesFailClosed pins that a body this package cannot
// parse into the shape it expects ends as a rejection rather than a relay of
// the daemon's original bytes.
func TestLibpodMalformedBodiesFailClosed(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, path, upstream string }{
		{"network inspect truncated", "/v5.8.1/libpod/networks/net-a/json", `{"name":"net-a"`},
		{"network inspect array truncated", "/v5.8.1/libpod/networks/net-a/json", `[{"name":"net-a"}`},
		{"network inspect trailing document", "/v5.8.1/libpod/networks/net-a/json", `{"name":"net-a"}{"name":"net-b"}`},
		{"network inspect array trailing document", "/v5.8.1/libpod/networks/net-a/json", `[{"name":"net-a"}][{"name":"net-b"}]`},
		{"network subnets wrong type", "/v5.8.1/libpod/networks/net-a/json", `{"name":"net-a","subnets":{"subnet":"10.89.0.0/24"}}`},
		{"network containers wrong type", "/v5.8.1/libpod/networks/net-a/json", `{"name":"net-a","containers":["ctr-a"]}`},
		{"legacy network plugins wrong type", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":{"type":"bridge"}}`},
		{"legacy network plugins null", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":null}`},
		{"legacy network plugin wrong type", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":["bridge"]}`},
		{"legacy network plugin null", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[null]}`},
		{"legacy network macvlan master wrong type", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"macvlan","master":42}]}`},
		{"legacy network macvlan master null", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"macvlan","master":null}]}`},
		{"legacy network ipam wrong type", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":"host-local"}]}`},
		{"legacy network ipam null", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":null}]}`},
		{"legacy network flat ipam subnet wrong type", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"subnet":42}}]}`},
		{"legacy network flat ipam subnet null", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"subnet":null}}]}`},
		{"legacy network flat ipam gateway wrong type", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"gateway":42}}]}`},
		{"legacy network flat ipam gateway null", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"gateway":null}}]}`},
		{"legacy network flat ipam rangeStart wrong type", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"rangeStart":42}}]}`},
		{"legacy network flat ipam rangeStart null", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"rangeStart":null}}]}`},
		{"legacy network flat ipam rangeEnd wrong type", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"rangeEnd":42}}]}`},
		{"legacy network flat ipam rangeEnd null", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"rangeEnd":null}}]}`},
		{"legacy network routes wrong type", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"routes":{}}}]}`},
		{"legacy network route wrong type", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"routes":["0.0.0.0/0"]}}]}`},
		{"legacy network ranges wrong type", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"ranges":{}}}]}`},
		{"legacy network ranges null", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"ranges":null}}]}`},
		{"legacy network range set wrong type", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"ranges":[{"subnet":"10.88.0.0/16"}]}}]}`},
		{"legacy network range wrong type", "/v3.4.4/libpod/networks/net-a/json", `{"name":"net-a","plugins":[{"type":"bridge","ipam":{"ranges":[["10.88.0.0/16"]]}}]}`},
		{"legacy list Plugins wrong type", "/v3.4.4/libpod/networks/json", `[{"Name":"net-a","Plugins":{}}]`},
		{"legacy list plugin wrong type", "/v3.4.4/libpod/networks/json", `[{"Name":"net-a","Plugins":["bridge"]}]`},
		{"legacy list top-level Bytes wrong type", "/v3.4.4/libpod/networks/json", `[{"Name":"net-a","Plugins":[],"Bytes":42}]`},
		{"legacy list top-level Bytes null", "/v3.4.4/libpod/networks/json", `[{"Name":"net-a","Plugins":[],"Bytes":null}]`},
		{"legacy list nested Bytes wrong type", "/v3.4.4/libpod/networks/json", `[{"Name":"net-a","Plugins":[{"Network":{"type":"bridge"},"Bytes":42}],"Bytes":"e30="}]`},
		{"legacy list Network wrong type", "/v3.4.4/libpod/networks/json", `[{"Name":"net-a","Plugins":[{"Network":"bridge","Bytes":"e30="}],"Bytes":"e30="}]`},
		{"volume list is not an array", "/v5.8.1/libpod/volumes/json", `{"Volumes":[]}`},
		{"secret list is not an array", "/v5.8.1/libpod/secrets/json", `{"ID":"sec-a"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := newResponseForTest(t, "GET", tc.path, tc.upstream)
			if err := New(allRedactions).ModifyResponse(resp); err == nil {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected rejection, got nil and body %s", body)
			}
		})
	}
}
