package responsefilter

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// allRedactionOptions turns on every response-side option at once, so a
// route's mutator branches into every arm it has.
var allRedactionOptions = Options{
	RedactContainerEnv:    true,
	RedactMountPaths:      true,
	RedactNetworkTopology: true,
	RedactSensitiveData:   true,
	RedactHostTopology:    true,
}

// listPartialDecodeCases covers every route that reaches streamArrayResponse
// with a declared itemFields set. Each body carries the fields its route's
// mutator redacts, plus fields no option can reach, plus at least one field
// that shares a name with something a DIFFERENT route redacts — so a set
// copied from the wrong route shows up as a difference rather than as a pass.
var listPartialDecodeCases = []struct {
	name string
	path string
	body string
}{
	{
		name: "containers",
		path: "/v1.53/containers/json",
		body: `[{"Id":"c-1","Names":["/api"],"Image":"img","Command":"/bin/api","Created":1768000000,"Ports":[{"IP":"0.0.0.0","PrivatePort":8080,"PublicPort":18080,"Type":"tcp"}],"Labels":{"z":"last","a":"first"},"State":"running","Status":"Up 6 hours","HostConfig":{"NetworkMode":"api_backend"},"NetworkSettings":{"Bridge":"docker0","SandboxID":"sb-1","IPAddress":"172.24.0.9","IPPrefixLen":16,"MacAddress":"02:42:ac:18:00:09","SecondaryIPAddresses":[{"Addr":"10.0.0.2"}],"Networks":{"api_backend":{"NetworkID":"net-1","EndpointID":"ep-1","Gateway":"172.24.0.1","IPAddress":"172.24.0.9","IPPrefixLen":16,"MacAddress":"02:42:ac:18:00:09"}}},"Mounts":[{"Type":"bind","Source":"/srv/secrets","Destination":"/run/secrets","RW":false},{"Type":"volume","Name":"logs","Source":"/var/lib/docker/volumes/logs/_data","Destination":"/var/log"}],"Spec":{"Data":"not-a-secret-here"}},{"Id":"c-2","Names":["/bare"],"Mounts":[],"HostConfig":{},"NetworkSettings":{}}]`,
	},
	{
		name: "networks",
		path: "/v1.53/networks",
		body: `[{"Name":"api_backend","Id":"net-1","Created":"2026-01-14T09:12:44Z","Scope":"local","Driver":"bridge","EnableIPv6":false,"IPAM":{"Driver":"default","Options":null,"Config":[{"Subnet":"172.24.0.0/16","Gateway":"172.24.0.1"}]},"Internal":false,"Attachable":true,"Ingress":false,"Status":{"172.24.0.0/16":{"IPsInUse":3,"IPsAvailable":65530}},"Containers":{"c-1":{"Name":"api","IPv4Address":"172.24.0.9/16","MacAddress":"02:42:ac:18:00:09"}},"Peers":[{"Name":"node-1","IP":"10.0.0.5"}],"Options":{"com.docker.network.bridge.name":"br-api"},"Labels":{"z":"last","a":"first"}},{"Name":"bare","Id":"net-2"}]`,
	},
	{
		name: "services",
		path: "/v1.53/services",
		body: `[{"ID":"srv-1","Version":{"Index":42},"CreatedAt":"2026-01-14T09:12:44Z","Spec":{"Name":"api","TaskTemplate":{"ContainerSpec":{"Image":"img","Env":["DB_PASS=hunter2","LANG=C.UTF-8"],"Mounts":[{"Type":"bind","Source":"/srv/secrets","Target":"/run/secrets"}],"Secrets":[{"SecretID":"sec-1","SecretName":"prod-db"}],"Configs":[{"ConfigID":"cfg-1","ConfigName":"app.conf"}]}}},"PreviousSpec":{"TaskTemplate":{"ContainerSpec":{"Env":["DB_PASS=old"],"Mounts":[{"Source":"/srv/old"}]}}},"Endpoint":{"Spec":{"Mode":"vip"},"VirtualIPs":[{"NetworkID":"net-1","Addr":"10.0.0.2/24"}]},"UpdateStatus":{"State":"completed"}},{"ID":"srv-2"}]`,
	},
	{
		name: "tasks",
		path: "/v1.53/tasks",
		body: `[{"ID":"task-1","Version":{"Index":7},"ServiceID":"srv-1","NodeID":"node-1","Slot":1,"Spec":{"ContainerSpec":{"Env":["API_KEY=xyz"],"Mounts":[{"Type":"bind","Source":"/srv/tasks","Target":"/work"}],"Secrets":[{"SecretID":"sec-1","SecretName":"prod-db"}]}},"Status":{"State":"running","Message":"started","ContainerStatus":{"ContainerID":"ctr-1","PID":42,"ExitCode":0}},"DesiredState":"running","NetworksAttachments":[{"Addresses":["10.0.0.10/24"],"Network":{"ID":"net-1","IPAMOptions":{"Configs":[{"Subnet":"10.0.0.0/24"}]}}}]},{"ID":"task-2"}]`,
	},
	{
		name: "secrets",
		path: "/v1.53/secrets",
		body: `[{"ID":"sec-1","Version":{"Index":3},"CreatedAt":"2026-01-14T09:12:44Z","UpdatedAt":"2026-01-14T09:12:44Z","Spec":{"Name":"prod-db","Labels":{"z":"last","a":"first"},"Data":"c3VwZXJzZWNyZXQ="}},{"ID":"sec-2","SecretData":"cG9kbWFuLXNlY3JldA==","Spec":{"Name":"podman"}},{"ID":"sec-3","Spec":{"Name":"no-data"}}]`,
	},
	{
		name: "configs",
		path: "/v1.53/configs",
		body: `[{"ID":"cfg-1","Version":{"Index":2},"Spec":{"Name":"app.conf","Labels":{"tier":"backend"},"Data":"Y29uZmlnLWRhdGE="}},{"ID":"cfg-2","Spec":{"Name":"empty"}}]`,
	},
	{
		name: "plugins",
		path: "/v1.53/plugins",
		body: `[{"Id":"plug-1","Name":"vieux/sshfs","Enabled":true,"Settings":{"Env":["DEBUG=1","PASSWORD=hunter2"],"Args":[],"Devices":[{"Name":"dev","Path":"/dev/fuse"}],"Mounts":[{"Name":"keys","Source":"/root/.ssh","Destination":"/keys"}]},"Config":{"Description":"sshFS","Env":[{"Name":"DEBUG","Value":"1"}],"Mounts":[{"Name":"keys","Source":"/root/.ssh","Destination":"/keys"}],"PropagatedMount":"/var/lib/docker/plugins/propagated","Linux":{"Devices":[{"Name":"fuse","Path":"/dev/fuse"}]}}},{"Id":"plug-2","Name":"bare"}]`,
	},
	{
		name: "nodes",
		path: "/v1.53/nodes",
		body: `[{"ID":"node-1","Version":{"Index":11},"Spec":{"Role":"manager","Availability":"active","Labels":{"zone":"us-east-1"}},"Description":{"Hostname":"node-1","Platform":{"Architecture":"x86_64","OS":"linux"},"TLSInfo":{"TrustRoot":"pem-root","CertIssuerSubject":"cn=swarm","CertIssuerPublicKey":"pubkey"}},"Status":{"State":"ready","Addr":"10.0.0.5"},"ManagerStatus":{"Leader":true,"Reachability":"reachable","Addr":"10.0.0.5:2377"}},{"ID":"node-2","Status":{"State":"ready"}}]`,
	},
	{
		name: "libpod volumes",
		path: "/v5.8.1/libpod/volumes/json",
		body: `[{"Name":"logs","Driver":"local","Mountpoint":"/var/lib/containers/storage/volumes/logs/_data","CreatedAt":"2026-01-14T09:12:44Z","Labels":{"z":"last","a":"first"},"Scope":"local","Options":{}},{"Name":"bare"}]`,
	},
	{
		name: "libpod networks modern",
		path: "/v5.8.1/libpod/networks/json",
		body: `[{"name":"podman","id":"net-1","driver":"bridge","network_interface":"podman0","created":"2026-01-14T09:12:44Z","subnets":[{"subnet":"10.88.0.0/16","gateway":"10.88.0.1"}],"routes":[{"destination":"0.0.0.0/0","gateway":"10.88.0.1"}],"network_dns_servers":["10.88.0.1"],"ipv6_enabled":false,"internal":false,"dns_enabled":true,"ipam_options":{"driver":"host-local"},"labels":{"z":"last","a":"first"},"containers":{"ctr-1":{"name":"api","interfaces":{"eth0":{"subnets":[{"ipnet":"10.88.0.5/16"}],"mac_address":"aa:bb:cc:dd:ee:ff"}}}}},{"name":"bare","id":"net-2"}]`,
	},
	{
		name: "libpod networks legacy CNI",
		path: "/v5.8.1/libpod/networks/json",
		body: `[{"Name":"podman","CNIVersion":"0.4.0","Bytes":"eyJjbmlWZXJzaW9uIjoiMC40LjAifQ==","Plugins":[{"Network":{"type":"bridge","capabilities":{"ips":true}},"Bytes":"eyJ0eXBlIjoiYnJpZGdlIn0="}]},{"Name":"bare"}]`,
	},
	{
		name: "libpod secrets",
		path: "/v5.8.1/libpod/secrets/json",
		body: `[{"ID":"sec-1","CreatedAt":"2026-01-14T09:12:44Z","UpdatedAt":"2026-01-14T09:12:44Z","SecretData":"cG9kbWFuLXNlY3JldA==","Spec":{"Name":"podman","Driver":{"Name":"file"},"Labels":{"z":"last","a":"first"}}},{"ID":"sec-2","Spec":{"Name":"no-data"}}]`,
	},
}

// TestListPartialDecodeMatchesFullDecode is the guard on the one way declaring
// itemFields can be wrong.
//
// Every route below is run twice over the same body — once with the partial
// decode on, which is production, and once with it off, which decodes each
// element whole the way the code did before itemFields existed. The two must
// agree as JSON. They can only disagree if a route's declared set is missing a
// key its mutator reaches for, because that key reaches the mutator as absent
// under the partial decode and as present under the full one, which is exactly
// a redaction that silently did not happen.
//
// It compares decoded values rather than bytes on purpose: the partial decode
// re-emits untouched fields as the daemon's own bytes, so the two encodings
// legitimately differ in nested key order and string escaping while carrying
// the same document. TestListPartialDecodeKeepsUntouchedBytes pins that
// difference from the other side.
func TestListPartialDecodeMatchesFullDecode(t *testing.T) {
	for _, tc := range listPartialDecodeCases {
		t.Run(tc.name, func(t *testing.T) {
			partial := runListRoute(t, tc.path, tc.body, true)
			full := runListRoute(t, tc.path, tc.body, false)

			if !reflect.DeepEqual(partial, full) {
				t.Fatalf("partial decode produced a different document than the full decode\npartial: %v\nfull:    %v", partial, full)
			}
		})
	}
}

// TestListPartialDecodeRedactsEveryCase is the companion assertion: the bodies
// above must actually be redacted, so a bug that made both halves of the
// differential do nothing cannot pass it.
func TestListPartialDecodeRedactsEveryCase(t *testing.T) {
	for _, tc := range listPartialDecodeCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := newResponseForTest(t, http.MethodGet, tc.path, tc.body)
			f := New(allRedactionOptions)
			if err := f.ModifyResponse(resp); err != nil {
				t.Fatalf("ModifyResponse() error = %v, want nil", err)
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read rewritten body: %v", err)
			}
			if string(got) == tc.body {
				t.Fatal("ModifyResponse() returned the body unchanged, want a redacted one")
			}
		})
	}
}

// runListRoute drives ModifyResponse over one list body and returns the
// rewritten body decoded, with partialDecode either on or off.
func runListRoute(t *testing.T, path, body string, partialDecode bool) any {
	t.Helper()

	original := listItemPartialDecode
	listItemPartialDecode = partialDecode
	defer func() { listItemPartialDecode = original }()

	resp := newResponseForTest(t, http.MethodGet, path, body)
	f := New(allRedactionOptions)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse(partialDecode=%t) error = %v, want nil", partialDecode, err)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		t.Fatalf("rewritten body is not valid JSON: %v (body=%s)", err, raw)
	}
	return decoded
}

// TestListPartialDecodeKeepsUntouchedBytes proves the partial decode really is
// a passthrough and not a re-marshal that happens to agree.
//
// Two things only survive if the bytes are carried through untouched. A nested
// object's key order survives, where encoding/json sorts the keys of any map it
// marshals. And a \u escape survives, where a round trip through map[string]any
// decodes it to the character and re-encodes it as that character. Both are
// checked on fields no option reaches, alongside the redaction of the field one
// does.
func TestListPartialDecodeKeepsUntouchedBytes(t *testing.T) {
	const body = `[{"Zeta":{"z":1,"m":2,"a":3},"Alpha":"caf\u00e9","Created":1.500,"Mounts":[{"Source":"/srv/secrets"}]}]`

	resp := newResponseForTest(t, http.MethodGet, "/v1.53/containers/json", body)
	f := New(Options{RedactMountPaths: true})
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse() error = %v, want nil", err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}

	for _, want := range []string{
		`"Zeta":{"z":1,"m":2,"a":3}`,
		`"Alpha":"caf\u00e9"`,
		`"Created":1.500`,
		`"Mounts":[{"Source":"` + redactedValue + `"}]`,
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("rewritten body is missing %s\ngot: %s", want, got)
		}
	}
}

// TestListPartialDecodeCarriesDeletesAndAdds pins the two shapes of mutation
// the raw field map has to survive, both of which the libpod CNI network
// redactor performs: it deletes the base64 Bytes blob that would otherwise
// carry the whole unredacted conflist, and it rewrites declared fields in
// place. A delete that did not reach the output would forward the very copy
// the structured redaction exists to remove.
func TestListPartialDecodeCarriesDeletesAndAdds(t *testing.T) {
	const body = `[{"Name":"podman","CNIVersion":"0.4.0","Bytes":"eyJjbmlWZXJzaW9uIjoiMC40LjAifQ==","network_interface":"podman0","subnets":[{"subnet":"10.88.0.0/16"}]}]`

	resp := newResponseForTest(t, http.MethodGet, "/v5.8.1/libpod/networks/json", body)
	f := New(Options{RedactNetworkTopology: true})
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse() error = %v, want nil", err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}

	if strings.Contains(string(got), "Bytes") {
		t.Fatalf("rewritten body still carries the CNI Bytes blob\ngot: %s", got)
	}
	for _, want := range []string{
		`"network_interface":"` + redactedValue + `"`,
		`"subnets":[]`,
		`"CNIVersion":"0.4.0"`,
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("rewritten body is missing %s\ngot: %s", want, got)
		}
	}
}

// TestListPartialDecodeRejectsNonObjectItem keeps the fail-closed posture the
// full decode had: an array element that is not an object is refused rather
// than carried through as bytes nothing inspected.
func TestListPartialDecodeRejectsNonObjectItem(t *testing.T) {
	for _, body := range []string{
		`[{"Mounts":[]},"not-an-object"]`,
		`[[{"Mounts":[]}]]`,
		`[42]`,
		`[null,{"Mounts":[]}]`,
	} {
		t.Run(body, func(t *testing.T) {
			resp := newResponseForTest(t, http.MethodGet, "/v1.53/containers/json", body)
			f := New(Options{RedactMountPaths: true})
			err := f.ModifyResponse(resp)
			if body == `[null,{"Mounts":[]}]` {
				// null decodes into a nil map on both paths, which is what the
				// full decode has always accepted.
				if err != nil {
					t.Fatalf("ModifyResponse() error = %v, want nil for a null element", err)
				}
				return
			}
			if err == nil {
				t.Fatal("ModifyResponse() error = nil, want a rejection for a non-object array element")
			}
		})
	}
}
