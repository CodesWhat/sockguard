package visibility

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

const (
	netListBody = `[
  {"Name":"proxy","Id":"n1","Driver":"bridge","Containers":{"c-web":{"Name":"web","IPv4Address":"172.18.0.2/16"},"c-db":{"Name":"db","IPv4Address":"172.18.0.3/16"}}},
  {"Name":"backend","Id":"n2","Driver":"bridge","Containers":{"c-db":{"Name":"db","IPv4Address":"172.19.0.2/16"}}},
  {"Name":"Proxy","Id":"n3","Driver":"bridge","Containers":null},
  {"Name":"bridge","Id":"n4","Driver":"bridge"}
]`
	netInspectBody = `{"Name":"proxy","Id":"n1","Driver":"bridge","Scope":"local","Containers":{"c-web":{"Name":"web","IPv4Address":"172.18.0.2/16"},"c-db":{"Name":"db","IPv4Address":"172.18.0.3/16"},"c-gone":{"Name":"gone"}}}`
)

// netDeps answers container lookups from a fixed table. A container missing
// from the table reads as not found.
func netDeps(table map[string]*resourceMeta) visibilityDeps {
	return visibilityDeps{
		inspectResourceMeta: func(_ context.Context, kind dockerresource.Kind, id string) (*resourceMeta, bool, error) {
			if kind != dockerresource.KindContainer {
				return nil, false, errors.New("unexpected kind " + string(kind))
			}
			meta, ok := table[id]
			return meta, ok, nil
		},
	}
}

var netTable = map[string]*resourceMeta{
	"c-web": {names: []string{"/web"}, image: "nginx:1", networks: []string{"proxy"}},
	"c-db":  {names: []string{"/db"}, image: "postgres:16", networks: []string{"proxy", "backend"}},
}

func serveNetworkRead(t *testing.T, opts Options, deps visibilityDeps, upstreamStatus int, upstreamBody, method, target string, meta *logging.RequestMeta) *httptest.ResponseRecorder {
	t.Helper()
	handler := middlewareWithDeps(testVisibilityLogger(), opts, deps)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", `"upstream"`)
		w.WriteHeader(upstreamStatus)
		_, _ = io.WriteString(w, upstreamBody)
	}))
	req := httptest.NewRequest(method, target, nil)
	if meta != nil {
		req = req.WithContext(logging.WithMeta(req.Context(), meta))
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

type networkItem struct {
	Name       string                     `json:"Name"`
	ID         string                     `json:"Id"`
	Driver     string                     `json:"Driver"`
	Containers map[string]json.RawMessage `json:"Containers"`
}

func decodeNetworkList(t *testing.T, rec *httptest.ResponseRecorder) []networkItem {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var items []networkItem
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode: %v; body: %s", err, rec.Body.String())
	}
	return items
}

func containerIDs(item networkItem) string {
	ids := make([]string, 0, len(item.Containers))
	for id := range item.Containers {
		ids = append(ids, id)
	}
	if len(ids) == 2 && ids[0] > ids[1] {
		ids[0], ids[1] = ids[1], ids[0]
	}
	return strings.Join(ids, ",")
}

func TestNetworkListIsNarrowedByVisibleNetworks(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"/networks", "/v1.53/networks"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			rec := serveNetworkRead(t, Options{Networks: []string{"proxy"}}, netDeps(netTable), http.StatusOK, netListBody, http.MethodGet, target, nil)
			items := decodeNetworkList(t, rec)
			if len(items) != 1 || items[0].Name != "proxy" || items[0].ID != "n1" || items[0].Driver != "bridge" {
				t.Fatalf("items = %+v, want only the exact-name proxy network with its fields intact", items)
			}
			if got := containerIDs(items[0]); got != "c-db,c-web" {
				t.Fatalf("containers = %q, want both attached visible containers", got)
			}
			if rec.Header().Get("Etag") != "" {
				t.Fatalf("upstream representation header survived the rewrite: %v", rec.Header())
			}
		})
	}
}

func TestNetworkListMatchesNamesExactlyAndCaseSensitively(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		networks []string
		want     string
	}{
		{[]string{"proxy", "backend"}, "proxy,backend"},
		{[]string{"Proxy"}, "Proxy"},
		{[]string{"prox"}, ""},
		{[]string{"nope"}, ""},
	} {
		rec := serveNetworkRead(t, Options{Networks: tt.networks}, netDeps(netTable), http.StatusOK, netListBody, http.MethodGet, "/networks", nil)
		var names []string
		for _, item := range decodeNetworkList(t, rec) {
			names = append(names, item.Name)
		}
		if got := strings.Join(names, ","); got != tt.want {
			t.Errorf("networks %v: got %q, want %q", tt.networks, got, tt.want)
		}
	}
}

func TestNetworkListEmptyResultIsAnEmptyArray(t *testing.T) {
	t.Parallel()
	rec := serveNetworkRead(t, Options{Networks: []string{"nope"}}, netDeps(netTable), http.StatusOK, netListBody, http.MethodGet, "/networks", nil)
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("body = %q, want []", rec.Body.String())
	}
}

func TestNetworkListNarrowsContainersToVisibleOnes(t *testing.T) {
	t.Parallel()
	// The name pattern hides db, so it disappears from the Containers map even
	// though the network itself is listed.
	opts := Options{Networks: []string{"proxy"}, NamePatterns: []string{"web*"}}
	items := decodeNetworkList(t, serveNetworkRead(t, opts, netDeps(netTable), http.StatusOK, netListBody, http.MethodGet, "/networks", nil))
	if len(items) != 1 || containerIDs(items[0]) != "c-web" {
		t.Fatalf("items = %+v, want proxy with only c-web", items)
	}
}

func TestNetworkListLooksEachContainerUpOnce(t *testing.T) {
	t.Parallel()
	calls := map[string]int{}
	deps := visibilityDeps{inspectResourceMeta: func(_ context.Context, _ dockerresource.Kind, id string) (*resourceMeta, bool, error) {
		calls[id]++
		return netTable[id], true, nil
	}}
	serveNetworkRead(t, Options{Networks: []string{"proxy", "backend"}}, deps, http.StatusOK, netListBody, http.MethodGet, "/networks", nil)
	if calls["c-db"] != 1 || calls["c-web"] != 1 {
		t.Fatalf("lookups = %v, want one per container across the whole list", calls)
	}
}

func TestNetworkListFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		deps visibilityDeps
	}{
		{"not an array", `{"Name":"proxy"}`, netDeps(netTable)},
		{"missing name", `[{"Id":"n1"}]`, netDeps(netTable)},
		{"non-string name", `[{"Name":7}]`, netDeps(netTable)},
		{"truncated array", `[{"Name":"proxy"}`, netDeps(netTable)},
		{"trailing bytes", `[] []`, netDeps(netTable)},
		{"malformed containers", `[{"Name":"proxy","Containers":[1]}]`, netDeps(netTable)},
		{"container lookup error", netListBody, visibilityDeps{inspectResourceMeta: func(context.Context, dockerresource.Kind, string) (*resourceMeta, bool, error) {
			return nil, false, errors.New("daemon down")
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := serveNetworkRead(t, Options{Networks: []string{"proxy"}}, tt.deps, http.StatusOK, tt.body, http.MethodGet, "/networks", nil)
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502; body: %s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "172.18") || strings.Contains(rec.Body.String(), "proxy") {
				t.Fatalf("502 body leaked the upstream payload: %s", rec.Body.String())
			}
		})
	}
}

func TestNetworkListPassesThroughUpstreamErrors(t *testing.T) {
	t.Parallel()
	rec := serveNetworkRead(t, Options{Networks: []string{"proxy"}}, netDeps(netTable), http.StatusInternalServerError, `{"message":"boom"}`, http.MethodGet, "/networks", nil)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "boom") {
		t.Fatalf("status = %d body = %s, want the upstream error untouched", rec.Code, rec.Body.String())
	}
}

func TestNetworkInspectListedNetworkNarrowsContainers(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"/networks/n1", "/v1.53/networks/proxy"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			rec := serveNetworkRead(t, Options{Networks: []string{"proxy"}, NamePatterns: []string{"web*"}}, netDeps(netTable), http.StatusOK, netInspectBody, http.MethodGet, target, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
			}
			var item networkItem
			if err := json.Unmarshal(rec.Body.Bytes(), &item); err != nil {
				t.Fatal(err)
			}
			if item.Name != "proxy" || item.ID != "n1" {
				t.Fatalf("inspect fields = %+v", item)
			}
			if got := containerIDs(item); got != "c-web" {
				t.Fatalf("containers = %q, want only c-web (db is hidden by the pattern, c-gone does not resolve)", got)
			}
			if !strings.Contains(rec.Body.String(), `"Scope":"local"`) {
				t.Fatalf("other inspect fields were dropped: %s", rec.Body.String())
			}
		})
	}
}

func TestNetworkInspectUnlistedNetworkReturns404(t *testing.T) {
	t.Parallel()
	body := strings.Replace(netInspectBody, `"Name":"proxy"`, `"Name":"secret-net"`, 1)
	rec := serveNetworkRead(t, Options{Networks: []string{"proxy"}}, netDeps(netTable), http.StatusOK, body, http.MethodGet, "/networks/abc123", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rec.Code, rec.Body.String())
	}
	for _, leak := range []string{"secret-net", "172.18", "Containers"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("404 body leaked %q: %s", leak, rec.Body.String())
		}
	}
	if rec.Header().Get("Etag") != "" {
		t.Fatalf("upstream representation header survived the 404: %v", rec.Header())
	}
}

func TestNetworkInspectUnlistedNetworkWarnModeForwardsAndRecordsWouldDeny(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"warn", "audit"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			meta := &logging.RequestMeta{RolloutMode: mode}
			body := strings.Replace(netInspectBody, `"Name":"proxy"`, `"Name":"other"`, 1)
			rec := serveNetworkRead(t, Options{Networks: []string{"proxy"}}, netDeps(netTable), http.StatusOK, body, http.MethodGet, "/networks/abc", meta)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"Name":"other"`) {
				t.Fatalf("status = %d body = %s, want the network forwarded", rec.Code, rec.Body.String())
			}
			if meta.Decision != logging.DecisionWouldDeny || meta.ReasonCode != reasonCodeVisibilityPolicyHidResource {
				t.Fatalf("decision = %q reason = %q, want would_deny %q", meta.Decision, meta.ReasonCode, reasonCodeVisibilityPolicyHidResource)
			}
		})
	}
}

func TestNetworkInspectFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		deps visibilityDeps
	}{
		{"not an object", `[]`, netDeps(netTable)},
		{"missing name", `{"Id":"n1"}`, netDeps(netTable)},
		{"malformed containers", `{"Name":"proxy","Containers":"x"}`, netDeps(netTable)},
		{"container lookup error", netInspectBody, visibilityDeps{inspectResourceMeta: func(context.Context, dockerresource.Kind, string) (*resourceMeta, bool, error) {
			return nil, false, errors.New("daemon down")
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := serveNetworkRead(t, Options{Networks: []string{"proxy"}}, tt.deps, http.StatusOK, tt.body, http.MethodGet, "/networks/n1", nil)
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502; body: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestNetworkInspectWithoutContainersMapIsForwarded(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`{"Name":"proxy","Id":"n1"}`, `{"Name":"proxy","Id":"n1","Containers":null}`} {
		rec := serveNetworkRead(t, Options{Networks: []string{"proxy"}}, netDeps(netTable), http.StatusOK, body, http.MethodGet, "/networks/n1", nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"Id":"n1"`) {
			t.Fatalf("body %s: status = %d out = %s", body, rec.Code, rec.Body.String())
		}
	}
}

func TestNetworkInspectUpstreamNotFoundPassesThrough(t *testing.T) {
	t.Parallel()
	rec := serveNetworkRead(t, Options{Networks: []string{"proxy"}}, netDeps(netTable), http.StatusNotFound, `{"message":"network x not found"}`, http.MethodGet, "/networks/x", nil)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "not found") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

// With label selectors configured too, the network read is both label-checked
// and name-checked.
func TestNetworkReadsANDLabelSelectorsWithVisibleNetworks(t *testing.T) {
	t.Parallel()
	deps := netDeps(netTable)
	deps.inspectResource = func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
		if kind == dockerresource.KindNetwork {
			return map[string]string{"tier": "edge"}, true, nil
		}
		return map[string]string{"tier": "edge"}, true, nil
	}
	opts := Options{VisibleResourceLabels: []string{"tier=edge"}, Networks: []string{"proxy"}}
	rec := serveNetworkRead(t, opts, deps, http.StatusOK, netInspectBody, http.MethodGet, "/networks/n1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("labeled and listed network: status = %d, want 200", rec.Code)
	}
	deps.inspectResource = func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
		return map[string]string{"tier": "other"}, true, nil
	}
	rec = serveNetworkRead(t, opts, deps, http.StatusOK, netInspectBody, http.MethodGet, "/networks/n1", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("label mismatch: status = %d, want 404", rec.Code)
	}
}

func TestNetworkAxisDoesNotNarrowNetworksWithoutTheAxis(t *testing.T) {
	t.Parallel()
	// A name pattern alone concerns containers and images, so the network
	// list is untouched.
	rec := serveNetworkRead(t, Options{NamePatterns: []string{"web*"}}, netDeps(netTable), http.StatusOK, netListBody, http.MethodGet, "/networks", nil)
	if items := decodeNetworkList(t, rec); len(items) != 4 {
		t.Fatalf("items = %d, want all 4 untouched", len(items))
	}
}

func TestNetworkAxisProfileNarrowsNetworks(t *testing.T) {
	t.Parallel()
	opts := Options{
		ResolveProfile: func(*http.Request) (string, bool) { return "edge", true },
		Profiles:       map[string]Policy{"edge": {Networks: []string{"backend"}}},
	}
	rec := serveNetworkRead(t, opts, netDeps(netTable), http.StatusOK, netListBody, http.MethodGet, "/networks", nil)
	items := decodeNetworkList(t, rec)
	if len(items) != 1 || items[0].Name != "backend" {
		t.Fatalf("items = %+v, want only the profile's backend network", items)
	}
}

func TestNetworkHeadIsAnsweredWithoutUpstreamRepresentation(t *testing.T) {
	t.Parallel()
	rec := serveNetworkRead(t, Options{Networks: []string{"proxy"}}, netDeps(netTable), http.StatusOK, "", http.MethodHead, "/networks", nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Etag") != "" {
		t.Fatalf("status = %d etag = %q, want 200 with the representation headers cleared", rec.Code, rec.Header().Get("Etag"))
	}
}

func TestCompilePolicyRejectsPaddedVisibleNetworks(t *testing.T) {
	t.Parallel()
	for _, entry := range []string{" proxy", "proxy ", "\tproxy", "proxy\n"} {
		if _, err := compilePolicy(nil, nil, nil, []string{entry}); err == nil {
			t.Errorf("compilePolicy accepted padded entry %q", entry)
		}
	}
	if _, err := compilePolicy(nil, nil, nil, []string{"proxy", "back end"}); err != nil {
		t.Errorf("compilePolicy rejected a name with an interior space: %v", err)
	}
}
