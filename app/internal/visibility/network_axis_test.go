package visibility

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
	"github.com/codeswhat/sockguard/v3/app/internal/responsefilter"
)

// dockerListNetworksBody is a Docker /containers/json body: the summary form
// carries NetworkSettings.Networks keyed by network name. The last four items
// are the shapes that must read as "attached to no networks".
const dockerListNetworksBody = `[
  {"Id":"a","Names":["/traefik"],"Image":"traefik:v3","Labels":{"tier":"edge"},"NetworkSettings":{"Networks":{"proxy":{"NetworkID":"n1"},"backend":{"NetworkID":"n2"}}}},
  {"Id":"b","Names":["/db"],"Image":"postgres:16","Labels":{"tier":"edge"},"NetworkSettings":{"Networks":{"backend":{"NetworkID":"n2"}}}},
  {"Id":"c","Names":["/case"],"Image":"x:1","NetworkSettings":{"Networks":{"Proxy":{}}}},
  {"Id":"d","Names":["/nullnets"],"Image":"x:1","NetworkSettings":{"Networks":null}},
  {"Id":"e","Names":["/emptynets"],"Image":"x:1","NetworkSettings":{"Networks":{}}},
  {"Id":"f","Names":["/nosettings"],"Image":"x:1"},
  {"Id":"g","Names":["/nullsettings"],"Image":"x:1","NetworkSettings":null}
]`

// libpodListNetworksBody is a /libpod/containers/json body: ListContainer has
// a top-level Networks array of names, and no NetworkSettings.
const libpodListNetworksBody = `[
  {"Id":"a","Names":["traefik"],"Image":"traefik:v3","Networks":["proxy","backend"]},
  {"Id":"b","Names":["db"],"Image":"postgres:16","Networks":["backend"]},
  {"Id":"d","Names":["nullnets"],"Image":"x:1","Networks":null},
  {"Id":"e","Names":["emptynets"],"Image":"x:1","Networks":[]},
  {"Id":"f","Names":["nonets"],"Image":"x:1"}
]`

func networkListHandler(t *testing.T, opts Options, body, path string) []string {
	t.Helper()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	})
	handler := middlewareWithDeps(testVisibilityLogger(), opts, visibilityDeps{})(upstream)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var items []struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode response: %v; body: %s", err, rec.Body.String())
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	return ids
}

func TestNetworkAxisFiltersContainerLists(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opts Options
		body string
		path string
		want string
	}{
		{name: "docker single network", opts: Options{Networks: []string{"proxy"}}, body: dockerListNetworksBody, path: "/v1.53/containers/json", want: "a"},
		{name: "docker either network", opts: Options{Networks: []string{"proxy", "backend"}}, body: dockerListNetworksBody, path: "/containers/json", want: "a,b"},
		{name: "docker case sensitive", opts: Options{Networks: []string{"Proxy"}}, body: dockerListNetworksBody, path: "/containers/json", want: "c"},
		{name: "docker unknown network hides all", opts: Options{Networks: []string{"nope"}}, body: dockerListNetworksBody, path: "/containers/json", want: ""},
		{name: "docker AND name pattern", opts: Options{Networks: []string{"backend"}, NamePatterns: []string{"db"}}, body: dockerListNetworksBody, path: "/containers/json", want: "b"},
		{name: "docker AND image pattern", opts: Options{Networks: []string{"backend"}, ImagePatterns: []string{"traefik:*"}}, body: dockerListNetworksBody, path: "/containers/json", want: "a"},
		{name: "libpod array", opts: Options{Networks: []string{"proxy"}}, body: libpodListNetworksBody, path: "/libpod/containers/json", want: "a"},
		{name: "libpod versioned", opts: Options{Networks: []string{"backend"}}, body: libpodListNetworksBody, path: "/v5.0.0/libpod/containers/json", want: "a,b"},
		{name: "libpod AND name pattern", opts: Options{Networks: []string{"backend"}, NamePatterns: []string{"db"}}, body: libpodListNetworksBody, path: "/libpod/containers/json", want: "b"},
		{name: "libpod missing and null networks hidden", opts: Options{Networks: []string{"nope"}}, body: libpodListNetworksBody, path: "/libpod/containers/json", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := strings.Join(networkListHandler(t, tt.opts, tt.body, tt.path), ",")
			if got != tt.want {
				t.Fatalf("visible ids = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNetworkAxisDoesNotTouchImageLists(t *testing.T) {
	t.Parallel()
	body := `[{"Id":"i1","RepoTags":["a:1"]},{"Id":"i2","RepoTags":null}]`
	got := strings.Join(networkListHandler(t, Options{Networks: []string{"proxy"}}, body, "/images/json"), ",")
	if got != "i1,i2" {
		t.Fatalf("image ids = %q, want both untouched", got)
	}
}

func TestNetworkAxisMalformedNetworksFailsClosed(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[{"Id":"a","Names":["/a"],"Image":"x","Networks":"proxy"}]`)
	})
	handler := middlewareWithDeps(testVisibilityLogger(), Options{Networks: []string{"proxy"}}, visibilityDeps{})(upstream)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/libpod/containers/json", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "proxy") {
		t.Fatalf("502 body leaked the upstream payload: %s", rec.Body.String())
	}
}

func TestNetworkAxisContainerReadsReturn404WhenHidden(t *testing.T) {
	t.Parallel()
	paths := []string{
		"/containers/abc/json",
		"/v1.53/containers/abc/logs",
		"/containers/abc/stats",
		"/containers/abc/top",
		"/containers/abc/changes",
		"/containers/abc/export",
		"/containers/abc/archive",
		"/libpod/containers/abc/json",
		"/libpod/containers/abc/exists",
		"/libpod/containers/abc/top",
		"/libpod/containers/abc/healthcheck",
		"/exec/sess/json",
		"/libpod/exec/sess/json",
	}
	for _, path := range paths {
		for _, tt := range []struct {
			name     string
			networks []string
			want     int
		}{
			{name: "attached", networks: []string{"proxy", "backend"}, want: http.StatusNoContent},
			{name: "other network only", networks: []string{"backend"}, want: http.StatusNotFound},
			{name: "no networks", networks: nil, want: http.StatusNotFound},
		} {
			t.Run(tt.name+" "+path, func(t *testing.T) {
				t.Parallel()
				meta := &resourceMeta{names: []string{"/c"}, image: "x:1", networks: tt.networks}
				deps := visibilityDeps{
					inspectExec: func(context.Context, string) (string, bool, error) { return "parent", true, nil },
					inspectResourceMeta: func(_ context.Context, kind dockerresource.Kind, _ string) (*resourceMeta, bool, error) {
						if kind != dockerresource.KindContainer {
							t.Errorf("meta inspected for kind %q, want container", kind)
						}
						return meta, true, nil
					},
				}
				reached := false
				handler := middlewareWithDeps(testVisibilityLogger(), Options{Networks: []string{"proxy"}}, deps)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached = true
					w.WriteHeader(http.StatusNoContent)
				}))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
				if rec.Code != tt.want || reached != (tt.want == http.StatusNoContent) {
					t.Fatalf("status = %d reached = %v, want status %d", rec.Code, reached, tt.want)
				}
			})
		}
	}
}

func TestNetworkAxisANDsWithLabelsOnInspect(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		labels map[string]string
		nets   []string
		want   int
	}{
		{name: "both pass", labels: map[string]string{"tier": "edge"}, nets: []string{"proxy"}, want: http.StatusNoContent},
		{name: "label fails", labels: map[string]string{"tier": "dev"}, nets: []string{"proxy"}, want: http.StatusNotFound},
		{name: "network fails", labels: map[string]string{"tier": "edge"}, nets: []string{"backend"}, want: http.StatusNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			deps := visibilityDeps{
				inspectResourceDetails: func(context.Context, dockerresource.Kind, string) (*resourceDetails, bool, error) {
					return &resourceDetails{labels: tt.labels, meta: &resourceMeta{networks: tt.nets}}, true, nil
				},
			}
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"tier=edge"},
				Networks:              []string{"proxy"},
			}, deps)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/abc/json", nil))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestNetworkAxisDoesNotGateImageInspect(t *testing.T) {
	t.Parallel()
	deps := visibilityDeps{
		inspectResourceMeta: func(context.Context, dockerresource.Kind, string) (*resourceMeta, bool, error) {
			t.Error("image inspect must not fetch meta for a networks-only policy")
			return nil, false, nil
		},
	}
	handler := middlewareWithDeps(testVisibilityLogger(), Options{Networks: []string{"proxy"}}, deps)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/images/alpine/json", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestNetworkAxisWarnModeWouldDeny(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"warn", "audit"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			deps := visibilityDeps{
				inspectResourceMeta: func(context.Context, dockerresource.Kind, string) (*resourceMeta, bool, error) {
					return &resourceMeta{networks: []string{"backend"}}, true, nil
				},
			}
			reached := false
			handler := middlewareWithDeps(testVisibilityLogger(), Options{Networks: []string{"proxy"}}, deps)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			}))
			meta := &logging.RequestMeta{RolloutMode: mode}
			req := httptest.NewRequest(http.MethodGet, "/containers/abc/json", nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if !reached || rec.Code != http.StatusNoContent {
				t.Fatalf("reached = %v status = %d, want forwarded 204", reached, rec.Code)
			}
			if meta.Decision != logging.DecisionWouldDeny || meta.ReasonCode != reasonCodeVisibilityPolicyHidResource {
				t.Fatalf("decision = %q reason = %q, want would_deny %q", meta.Decision, meta.ReasonCode, reasonCodeVisibilityPolicyHidResource)
			}
		})
	}
}

func TestNetworkAxisProfileMergesWithRoot(t *testing.T) {
	t.Parallel()
	opts := Options{
		Networks: []string{"proxy"},
		Profiles: map[string]Policy{
			"extra": {Networks: []string{"proxy", "edge"}},
			"plain": {},
		},
	}
	for _, tt := range []struct {
		profile string
		want    string
	}{
		{profile: "", want: "a"},
		{profile: "plain", want: "a"},
		{profile: "extra", want: "a,e"},
	} {
		t.Run("profile "+tt.profile, func(t *testing.T) {
			t.Parallel()
			o := opts
			o.ResolveProfile = func(*http.Request) (string, bool) { return tt.profile, tt.profile != "" }
			body := `[{"Id":"a","Names":["/a"],"Image":"x","NetworkSettings":{"Networks":{"proxy":{}}}},
				{"Id":"e","Names":["/e"],"Image":"x","NetworkSettings":{"Networks":{"edge":{}}}},
				{"Id":"z","Names":["/z"],"Image":"x","NetworkSettings":{"Networks":{"other":{}}}}]`
			got := strings.Join(networkListHandler(t, o, body, "/containers/json"), ",")
			if got != tt.want {
				t.Fatalf("visible ids = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNetworkAxisProfileOnlyPolicyIsEnforced(t *testing.T) {
	t.Parallel()
	opts := Options{
		Profiles:       map[string]Policy{"traefik": {Networks: []string{"proxy"}}},
		ResolveProfile: func(*http.Request) (string, bool) { return "traefik", true },
	}
	got := strings.Join(networkListHandler(t, opts, dockerListNetworksBody, "/containers/json"), ",")
	if got != "a" {
		t.Fatalf("visible ids = %q, want a", got)
	}
}

func TestCompilePolicyDedupesNetworksAndRejectsEmpty(t *testing.T) {
	t.Parallel()
	policy, err := compilePolicy(nil, nil, nil, []string{"proxy", "proxy", "edge"})
	if err != nil {
		t.Fatalf("compilePolicy() error = %v", err)
	}
	if got := strings.Join(policy.networks, ","); got != "proxy,edge" {
		t.Fatalf("networks = %q, want proxy,edge", got)
	}
	if _, err := compilePolicy(nil, nil, nil, []string{""}); err == nil {
		t.Fatal("compilePolicy() with empty network = nil error, want rejection")
	}
}

func TestNetworkAxisMisconfiguredEmptyEntryFailsClosed(t *testing.T) {
	t.Parallel()
	handler := middlewareWithDeps(testVisibilityLogger(), Options{Networks: []string{""}}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/json", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestNetworkAxisSystemDataUsageContainers(t *testing.T) {
	t.Parallel()
	modern := `{
	  "ContainerUsage":{"ActiveCount":2,"TotalCount":3,"Reclaimable":1,"TotalSize":2,"Items":[
	    {"Id":"c-proxy","Names":["/web"],"Image":"x:1","NetworkSettings":{"Networks":{"proxy":{}}}},
	    {"Id":"c-back","Names":["/db"],"Image":"y:1","NetworkSettings":{"Networks":{"backend":{}}}},
	    {"Id":"c-none","Names":["/n"],"Image":"z:1","NetworkSettings":{"Networks":null}}
	  ]},
	  "ImageUsage":{"ActiveCount":1,"TotalCount":1,"Reclaimable":1,"TotalSize":1,"Items":[{"Id":"sha256:i","RepoTags":["x:1"]}]},
	  "VolumeUsage":{"ActiveCount":1,"TotalCount":1,"Reclaimable":1,"TotalSize":1,"Items":[{"Name":"v1"}]}
	}`
	legacy := `{"LayersSize":1,
	  "Containers":[
	    {"Id":"c-proxy","Names":["/web"],"Image":"x:1","NetworkSettings":{"Networks":{"proxy":{}}}},
	    {"Id":"c-back","Names":["/db"],"Image":"y:1","NetworkSettings":{"Networks":{"backend":{}}}}
	  ],
	  "Images":[{"Id":"sha256:i","RepoTags":["x:1"]}],
	  "Volumes":[{"Name":"v1"}]}`
	for name, body := range map[string]string{"modern": modern, "legacy": legacy} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rec := getSystemDFForTest(t, systemDFHandlerForTest(t, Options{Networks: []string{"proxy"}}, body))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
			}
			out := rec.Body.String()
			for _, want := range []string{"c-proxy", "sha256:i", "v1"} {
				if !strings.Contains(out, want) {
					t.Errorf("%q missing from /system/df: %s", want, out)
				}
			}
			for _, hidden := range []string{"c-back", "c-none"} {
				if strings.Contains(out, hidden) {
					t.Errorf("%q leaked through /system/df: %s", hidden, out)
				}
			}
		})
	}
}

func TestNetworkAxisEventsWarning(t *testing.T) {
	t.Parallel()
	logger, buf := warnCapturingLogger()
	_ = middlewareWithDeps(logger, Options{
		Networks: []string{"proxy"},
		Profiles: map[string]Policy{"p": {Networks: []string{"edge"}}},
	}, visibilityDeps{})
	got := buf.String()
	if !strings.Contains(got, "visible_networks is set without any visible_resource_labels selector") || !strings.Contains(got, "/events") {
		t.Fatalf("log output = %q, want the visible_networks events warning", got)
	}
	if n := strings.Count(got, "visible_networks is set"); n != 1 {
		t.Fatalf("warning fired %d times, want once (profiles inherit the default's)", n)
	}
	if strings.Contains(got, "name/image patterns") {
		t.Fatalf("log output = %q, want no name/image warning for a networks-only policy", got)
	}

	logger, buf = warnCapturingLogger()
	_ = middlewareWithDeps(logger, Options{VisibleResourceLabels: []string{"a=b"}, Networks: []string{"proxy"}}, visibilityDeps{})
	if strings.Contains(buf.String(), "visible_networks") {
		t.Fatalf("log output = %q, want no warning when a label selector is set", buf.String())
	}

	logger, buf = warnCapturingLogger()
	_ = middlewareWithDeps(logger, Options{Profiles: map[string]Policy{"p": {Networks: []string{"edge"}}}}, visibilityDeps{})
	if !strings.Contains(buf.String(), "scope=\"profile p\"") {
		t.Fatalf("log output = %q, want a profile-scoped warning", buf.String())
	}
}

func TestDecodeContainerInspectNetworks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "docker inspect", body: `{"Name":"/a","Config":{"Image":"x"},"NetworkSettings":{"Networks":{"proxy":{"NetworkID":"n"},"backend":{}}}}`, want: "backend,proxy"},
		{name: "libpod inspect", body: `{"Name":"a","ImageName":"x","NetworkSettings":{"Networks":{"podman":{}}}}`, want: "podman"},
		{name: "null networks", body: `{"Name":"/a","NetworkSettings":{"Networks":null}}`, want: ""},
		{name: "no networks key", body: `{"Name":"/a","NetworkSettings":{}}`, want: ""},
		{name: "no network settings", body: `{"Name":"/a"}`, want: ""},
		{name: "host mode", body: `{"Name":"/a","NetworkSettings":{"Networks":{"host":{}}}}`, want: "host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			meta, err := decodeResourceMeta(strings.NewReader(tt.body), dockerresource.KindContainer)
			if err != nil {
				t.Fatalf("decodeResourceMeta() error = %v", err)
			}
			details, err := decodeResourceDetails(strings.NewReader(tt.body), dockerresource.KindContainer)
			if err != nil {
				t.Fatalf("decodeResourceDetails() error = %v", err)
			}
			for label, got := range map[string][]string{"meta": meta.networks, "details": details.meta.networks} {
				sorted := append([]string(nil), got...)
				for i := range sorted {
					for j := i + 1; j < len(sorted); j++ {
						if sorted[j] < sorted[i] {
							sorted[i], sorted[j] = sorted[j], sorted[i]
						}
					}
				}
				if joined := strings.Join(sorted, ","); joined != tt.want {
					t.Errorf("%s networks = %q, want %q", label, joined, tt.want)
				}
			}
		})
	}
}

// TestNetworkAxisSurvivesNetworkTopologyRedaction runs the real response
// redactor between a fake daemon and the visibility layer. The reverse proxy's
// ModifyResponse is the innermost layer in the serve chain, so visibility reads
// the body AFTER redact_network_topology has run. Redaction blanks addresses
// and identifiers but keeps the network names that key NetworkSettings.Networks,
// which is all this axis reads. The client sees the filtered, redacted list.
func TestNetworkAxisSurvivesNetworkTopologyRedaction(t *testing.T) {
	t.Parallel()
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[
		  {"Id":"a","Names":["/traefik"],"Image":"traefik:v3","NetworkSettings":{"Networks":{"proxy":{"NetworkID":"net-1","EndpointID":"ep-1","Gateway":"172.18.0.1","IPAddress":"172.18.0.5","MacAddress":"02:42:ac:12:00:05"}}}},
		  {"Id":"b","Names":["/db"],"Image":"postgres:16","NetworkSettings":{"Networks":{"backend":{"NetworkID":"net-secret-2","IPAddress":"172.19.0.2"}}}}
		]`)
	}))
	defer daemon.Close()
	target, err := url.Parse(daemon.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = responsefilter.New(responsefilter.Options{RedactNetworkTopology: true}).ModifyResponse

	handler := middlewareWithDeps(testVisibilityLogger(), Options{Networks: []string{"proxy"}}, visibilityDeps{})(proxy)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, "traefik") || strings.Contains(out, "postgres") || strings.Contains(out, "backend") {
		t.Fatalf("visible set wrong under redaction: %s", out)
	}
	for _, leaked := range []string{"172.18.0.5", "172.18.0.1", "02:42:ac:12:00:05"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("redaction did not apply to the returned item, %q present: %s", leaked, out)
		}
	}
}
