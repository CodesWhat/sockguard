package compat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	dtypes "github.com/docker/docker/api/types"
	dcontainer "github.com/docker/docker/api/types/container"
	dimage "github.com/docker/docker/api/types/image"
	dnetwork "github.com/docker/docker/api/types/network"
	dswarm "github.com/docker/docker/api/types/swarm"
	dsystem "github.com/docker/docker/api/types/system"
	dvolume "github.com/docker/docker/api/types/volume"
	mcontainer "github.com/moby/moby/api/types/container"
	mimage "github.com/moby/moby/api/types/image"
	mnetwork "github.com/moby/moby/api/types/network"
	mplugin "github.com/moby/moby/api/types/plugin"
	mswarm "github.com/moby/moby/api/types/swarm"
	msystem "github.com/moby/moby/api/types/system"
	mvolume "github.com/moby/moby/api/types/volume"

	"github.com/codeswhat/sockguard/v3/app/internal/ownership"
	"github.com/codeswhat/sockguard/v3/app/internal/responsefilter"
	"github.com/codeswhat/sockguard/v3/app/internal/visibility"
)

// libTypes is one wire shape as each client library declares it. Fixtures are
// generated from both declarations, so a field only one library has still gets
// exercised, and every output is decoded into both.
type libTypes struct {
	moby   reflect.Type
	docker reflect.Type
}

func one[M, D any]() libTypes {
	return libTypes{moby: reflect.TypeFor[M](), docker: reflect.TypeFor[D]()}
}

func list[M, D any]() libTypes {
	return libTypes{moby: reflect.TypeFor[[]M](), docker: reflect.TypeFor[[]D]()}
}

type endpoint struct {
	name  string
	path  string
	types libTypes
	// ownLibOnly decodes a moby/api fixture only into moby/api. /system/df
	// changed shape between the two (Engine API 1.52), so it is not a valid
	// docker v28 body.
	ownLibOnly bool
	// scoped marks list endpoints visibility and ownership filter by label.
	scoped bool
	// mutate adjusts the generated JSON (a worker's /info has no Cluster).
	mutate func(map[string]any)
}

var endpoints = []endpoint{
	{name: "container inspect", path: "/v1.53/containers/abc/json", types: one[mcontainer.InspectResponse, dcontainer.InspectResponse]()},
	{name: "container list", path: "/v1.53/containers/json", types: list[mcontainer.Summary, dcontainer.Summary](), scoped: true},
	{name: "image inspect", path: "/v1.53/images/busybox/json", types: one[mimage.InspectResponse, dimage.InspectResponse]()},
	{name: "network list", path: "/v1.53/networks", types: list[mnetwork.Summary, dnetwork.Summary](), scoped: true},
	{name: "network inspect", path: "/v1.53/networks/abc", types: one[mnetwork.Inspect, dnetwork.Inspect]()},
	{name: "volume list", path: "/v1.53/volumes", types: one[mvolume.ListResponse, dvolume.ListResponse](), scoped: true},
	{name: "volume inspect", path: "/v1.53/volumes/vol", types: one[mvolume.Volume, dvolume.Volume]()},
	{name: "plugin list", path: "/v1.53/plugins", types: list[mplugin.Plugin, dtypes.Plugin]()},
	{name: "plugin inspect", path: "/v1.53/plugins/p/json", types: one[mplugin.Plugin, dtypes.Plugin]()},
	{name: "system df", path: "/v1.53/system/df", types: one[msystem.DiskUsage, dtypes.DiskUsage](), ownLibOnly: true, scoped: true},
	{name: "info manager", path: "/v1.53/info", types: one[msystem.Info, dsystem.Info]()},
	{name: "info worker", path: "/v1.53/info", types: one[msystem.Info, dsystem.Info](), mutate: func(m map[string]any) {
		if sw, ok := m["Swarm"].(map[string]any); ok {
			delete(sw, "Cluster")
		}
	}},
	{name: "service list", path: "/v1.53/services", types: list[mswarm.Service, dswarm.Service]()},
	{name: "service inspect", path: "/v1.53/services/s", types: one[mswarm.Service, dswarm.Service]()},
	{name: "task list", path: "/v1.53/tasks", types: list[mswarm.Task, dswarm.Task]()},
	{name: "task inspect", path: "/v1.53/tasks/t", types: one[mswarm.Task, dswarm.Task]()},
	{name: "node list", path: "/v1.53/nodes", types: list[mswarm.Node, dswarm.Node]()},
	{name: "node inspect", path: "/v1.53/nodes/n", types: one[mswarm.Node, dswarm.Node]()},
	{name: "swarm inspect", path: "/v1.53/swarm", types: one[mswarm.Swarm, dswarm.Swarm]()},
	{name: "swarm unlock key", path: "/v1.53/swarm/unlockkey", types: one[mswarm.UnlockKeyResponse, dswarm.UnlockKeyResponse]()},
	{name: "config list", path: "/v1.53/configs", types: list[mswarm.Config, dswarm.Config]()},
	{name: "config inspect", path: "/v1.53/configs/c", types: one[mswarm.Config, dswarm.Config]()},
	{name: "secret list", path: "/v1.53/secrets", types: list[mswarm.Secret, dswarm.Secret]()},
	{name: "secret inspect", path: "/v1.53/secrets/s", types: one[mswarm.Secret, dswarm.Secret]()},
}

// policy is one combination of the redaction flags.
type policy struct {
	name string
	opts responsefilter.Options
}

func policies() []policy {
	flags := []struct {
		name string
		set  func(*responsefilter.Options, bool)
	}{
		{"container_env", func(o *responsefilter.Options, v bool) { o.RedactContainerEnv = v }},
		{"mount_paths", func(o *responsefilter.Options, v bool) { o.RedactMountPaths = v }},
		{"network_topology", func(o *responsefilter.Options, v bool) { o.RedactNetworkTopology = v }},
		{"sensitive_data", func(o *responsefilter.Options, v bool) { o.RedactSensitiveData = v }},
	}
	all := responsefilter.Options{RedactHostTopology: true}
	for _, f := range flags {
		f.set(&all, true)
	}
	out := []policy{{"all on", all}}
	for _, f := range flags {
		off, only := all, responsefilter.Options{RedactHostTopology: true}
		f.set(&off, false)
		f.set(&only, true)
		out = append(out, policy{"all on except " + f.name, off}, policy{"only " + f.name, only})
	}
	return out
}

func generate(t *testing.T, ep endpoint, typ reflect.Type) []byte {
	t.Helper()
	raw, err := json.Marshal(fillValue(typ).Interface())
	if err != nil {
		t.Fatalf("marshal %s fixture from %s: %v", ep.name, typ, err)
	}
	if ep.mutate == nil {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("remarshal %s fixture: %v", ep.name, err)
	}
	ep.mutate(m)
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatalf("remarshal %s fixture: %v", ep.name, err)
	}
	return raw
}

// decodeTargets returns the types body must decode into.
//
// A fixture generated from docker v28's types uses plain strings where moby/api
// has netip.Addr, so it is only a valid body for docker v28. The moby/api
// fixture is strict enough for both libraries.
func decodeTargets(ep endpoint, source string) map[string]reflect.Type {
	if source == "docker/docker" {
		return map[string]reflect.Type{"docker/docker": ep.types.docker}
	}
	if ep.ownLibOnly {
		return map[string]reflect.Type{"moby/api": ep.types.moby}
	}
	return map[string]reflect.Type{"moby/api": ep.types.moby, "docker/docker": ep.types.docker}
}

func decodeInto(body []byte, typ reflect.Type) error {
	return json.Unmarshal(body, reflect.New(typ).Interface())
}

func assertDecodes(t *testing.T, what string, body []byte, ep endpoint, source string) {
	t.Helper()
	for lib, typ := range decodeTargets(ep, source) {
		if err := decodeInto(body, typ); err != nil {
			t.Errorf("%s: decode into %s %s: %v\nbody: %s", what, lib, typ, err, truncate(body))
		}
	}
}

func truncate(b []byte) string {
	if len(b) > 600 {
		return string(b[:600]) + "..."
	}
	return string(b)
}

func response(path string, body []byte) *http.Response {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

func redact(t *testing.T, opts responsefilter.Options, path string, body []byte) []byte {
	t.Helper()
	resp := response(path, body)
	if err := responsefilter.New(opts).ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse %s: %v", path, err)
	}
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read redacted %s: %v", path, err)
	}
	return out
}

type sources struct {
	name string
	typ  reflect.Type
}

func fixtureSources(ep endpoint) []sources {
	return []sources{{"moby/api", ep.types.moby}, {"docker/docker", ep.types.docker}}
}

// TestRedactedResponsesDecodeIntoClientTypes drives the response filter over
// daemon-shaped fixtures for every endpoint it rewrites and decodes the result
// into the real client types of both libraries.
func TestRedactedResponsesDecodeIntoClientTypes(t *testing.T) {
	for _, ep := range endpoints {
		for _, src := range fixtureSources(ep) {
			fixture := generate(t, ep, src.typ)
			// A fixture the clients cannot decode before redaction is a bug in
			// the fixture, not in Sockguard. Say so instead of blaming the filter.
			assertDecodes(t, "raw fixture (not Sockguard's fault)", fixture, ep, src.name)
			if t.Failed() {
				t.FailNow()
			}
			for _, pol := range policies() {
				t.Run(fmt.Sprintf("%s/from %s/%s", ep.name, src.name, pol.name), func(t *testing.T) {
					out := redact(t, pol.opts, ep.path, fixture)
					assertDecodes(t, "redacted", out, ep, src.name)
				})
			}
		}
	}
}

// expectedRedactions names, per endpoint, fields the filter must change with
// every flag on. A path is dot-separated; "[]" takes the first array element
// and "*" the only value of a map. Derived from responsefilter/filter.go.
var expectedRedactions = map[string][]string{
	"container inspect": {"Config.Env", "Mounts.[].Source", "LogPath", "NetworkSettings.Networks.*.IPAddress", "NetworkSettings.SandboxKey", "NetworkSettings.Ports.*.[].HostIp"},
	"container list":    {"[].Mounts.[].Source", "[].NetworkSettings.Networks.*.IPAddress", "[].Ports.[].IP"},
	"image inspect":     {"Config.Env"},
	"network list":      {"[].IPAM.Config"},
	"network inspect":   {"IPAM.Config", "Services.*.VIP", "Services.*.Tasks.[].EndpointIP"},
	"volume list":       {"Volumes.[].Mountpoint"},
	"volume inspect":    {"Mountpoint"},
	"plugin list":       {"[].Settings.Env", "[].Config.PropagatedMount"},
	"plugin inspect":    {"Settings.Env", "Config.PropagatedMount"},
	"system df":         {"VolumeUsage.Items.[].Mountpoint", "ContainerUsage.Items.[].Mounts.[].Source"},
	"info manager":      {"Swarm.NodeAddr", "Containerd", "DefaultAddressPools.[].Base"},
	"info worker":       {"Swarm.NodeAddr", "Containerd", "DefaultAddressPools.[].Base"},
	"service list":      {"[].Spec.TaskTemplate.ContainerSpec.Env", "[].Endpoint.VirtualIPs"},
	"service inspect":   {"Spec.TaskTemplate.ContainerSpec.Env", "Endpoint.VirtualIPs"},
	"task list":         {"[].Spec.ContainerSpec.Env", "[].NetworksAttachments.[].Addresses"},
	"task inspect":      {"Spec.ContainerSpec.Env", "NetworksAttachments.[].Addresses"},
	"node list":         {"[].Status.Addr", "[].ManagerStatus.Addr"},
	"node inspect":      {"Status.Addr", "ManagerStatus.Addr"},
	"swarm inspect":     {"JoinTokens.Worker", "JoinTokens.Manager"},
	"swarm unlock key":  {"UnlockKey"},
	"config list":       {"[].Spec.Data"},
	"config inspect":    {"Spec.Data"},
	"secret list":       {"[].Spec.Data"},
	"secret inspect":    {"Spec.Data"},
}

// valueAt walks a decoded JSON document along path. ok is false when a segment
// is absent, which for the redacted body means the filter removed the field.
func valueAt(doc any, path string) (any, bool) {
	cur := doc
	for _, seg := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case []any:
			if seg != "[]" || len(node) == 0 {
				return nil, false
			}
			cur = node[0]
		case map[string]any:
			if seg == "*" {
				if len(node) != 1 {
					return nil, false
				}
				for _, v := range node {
					cur = v
				}
				continue
			}
			v, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = v
		default:
			return nil, false
		}
	}
	return cur, true
}

// TestRedactionRewritesEveryEndpoint keeps the decode test honest: with every
// flag on, each endpoint must change the fields the filter targets there,
// otherwise the decode would pass over an endpoint the filter silently stopped
// handling. Values are compared decoded, so re-encoding alone cannot satisfy it.
func TestRedactionRewritesEveryEndpoint(t *testing.T) {
	all := policies()[0].opts
	for _, ep := range endpoints {
		paths, ok := expectedRedactions[ep.name]
		if !ok {
			t.Errorf("%s: no expected redactions listed", ep.name)
			continue
		}
		src := fixtureSources(ep)[0]
		fixture := generate(t, ep, src.typ)
		out := redact(t, all, ep.path, fixture)
		var before, after any
		if err := json.Unmarshal(fixture, &before); err != nil {
			t.Fatalf("%s: decode fixture: %v", ep.name, err)
		}
		if err := json.Unmarshal(out, &after); err != nil {
			t.Fatalf("%s: decode output: %v", ep.name, err)
		}
		for _, path := range paths {
			was, present := valueAt(before, path)
			if !present {
				t.Errorf("%s: fixture has no %s; fix the expectation table", ep.name, path)
				continue
			}
			if now, present := valueAt(after, path); present && reflect.DeepEqual(was, now) {
				t.Errorf("%s: %s unchanged with every flag on (%v)", ep.name, path, was)
			}
		}
	}
}

// TestScopedListsDecodeThroughVisibilityAndOwnership runs the label-scoped
// list endpoints through visibility and ownership, which re-encode bodies,
// stacked in front of the response filter the way the proxy chains them.
func TestScopedListsDecodeThroughVisibilityAndOwnership(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, ep := range endpoints {
		if !ep.scoped {
			continue
		}
		for _, src := range fixtureSources(ep) {
			fixture := generate(t, ep, src.typ)
			for _, pol := range []policy{policies()[0], {"all off", responsefilter.Options{}}} {
				t.Run(fmt.Sprintf("%s/from %s/%s", ep.name, src.name, pol.name), func(t *testing.T) {
					upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						resp := response(r.URL.Path, fixture)
						if err := responsefilter.New(pol.opts).ModifyResponse(resp); err != nil {
							t.Errorf("ModifyResponse: %v", err)
						}
						body, _ := io.ReadAll(resp.Body)
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write(body)
					})
					vis := visibility.MiddlewareWithRoundTripper(unreachable{}, logger, visibility.Options{
						VisibleResourceLabels: []string{visibleLabelKey + "=true"},
					})
					own := ownership.MiddlewareWithRoundTripper(unreachable{}, logger, ownership.Options{
						Owner:    ownerLabelValue,
						LabelKey: ownerLabelKey,
					})
					handler := vis(own(upstream))

					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ep.path, nil))
					if rec.Code != http.StatusOK {
						t.Fatalf("status %d: %s", rec.Code, truncate(rec.Body.Bytes()))
					}
					if strings.TrimSpace(rec.Body.String()) == "" {
						t.Fatal("empty body")
					}
					assertDecodes(t, "after visibility+ownership", rec.Body.Bytes(), ep, src.name)
				})
			}
		}
	}
}

// unreachable fails any upstream inspect: list reads must not need one.
type unreachable struct{}

func (unreachable) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("unexpected upstream round trip")
}
