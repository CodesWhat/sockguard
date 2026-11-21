package cmd

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/testhelp"
	"github.com/codeswhat/sockguard/v3/app/internal/upstream"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

const ownerScopesLabelKey = "com.sockguard.owner"

// ownerScopesDaemon is a fake Docker daemon holding containers by name with
// their labels. It applies the label filter on GET /containers/json the way
// dockerd does, so the proxy's injected owner filter is what narrows a list.
type ownerScopesDaemon struct {
	mu         sync.Mutex
	containers map[string]map[string]string
	acted      []string
}

func (d *ownerScopesDaemon) seed(name, owner string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.containers[name] = map[string]string{ownerScopesLabelKey: owner}
}

func (d *ownerScopesDaemon) actions() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.acted...)
}

func (d *ownerScopesDaemon) labelOf(name string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	l, ok := d.containers[name]
	return l[ownerScopesLabelKey], ok
}

func labelFilterValues(raw string) []string {
	if raw == "" {
		return nil
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil
	}
	var out []string
	switch v := decoded["label"].(type) {
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	case map[string]any:
		for key := range v {
			out = append(out, key)
		}
	}
	return out
}

func (d *ownerScopesDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := r.URL.Path
	if i := strings.Index(path[1:], "/"); i >= 0 && strings.HasPrefix(path, "/v1.") {
		path = path[i+1:]
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && path == "/containers/json":
		want := labelFilterValues(r.URL.Query().Get("filters"))
		names := make([]string, 0, len(d.containers))
		for name := range d.containers {
			names = append(names, name)
		}
		sort.Strings(names)
		out := []map[string]any{}
		for _, name := range names {
			labels := d.containers[name]
			match := true
			for _, f := range want {
				k, v, _ := strings.Cut(f, "=")
				if labels[k] != v {
					match = false
				}
			}
			if match {
				out = append(out, map[string]any{"Id": name, "Names": []string{"/" + name}, "Labels": labels})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json"):
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": "sha256:1", "Config": map[string]any{"Labels": map[string]string{}}})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/json")
		labels, ok := d.containers[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"no such container"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": name, "Config": map[string]any{"Labels": labels}})
	case r.Method == http.MethodPost && path == "/containers/create":
		var body struct {
			Labels map[string]string `json:"Labels"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		name := r.URL.Query().Get("name")
		d.containers[name] = body.Labels
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"Id":"`+name+`"}`)
	default:
		d.acted = append(d.acted, r.Method+" "+path)
		w.WriteHeader(http.StatusNoContent)
	}
}

type ownerScopesHarness struct {
	t      *testing.T
	addr   string
	daemon *ownerScopesDaemon
	client *http.Client
}

const (
	ownerScopesIPA     = "192.0.2.1:4000"
	ownerScopesIPB     = "192.0.2.2:4000"
	ownerScopesIPAdmin = "192.0.2.3:4000"
	ownerScopesIPAnon  = "198.51.100.9:4000"
)

func strPtr(s string) *string { return &s }

// ownerScopesConfig is the shared two-tenant plus admin config. Profiles are
// picked by source IP because that is the selector in-process tests can
// drive; the owner choice downstream reads only clientacl.RequestProfile, so
// the selector kind does not change what is under test. Selector strength is
// a validation concern and is covered in the config package.
func ownerScopesConfig(socketPath string) config.Config {
	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Ownership.Owner = "root-owner"
	cfg.Ownership.LabelKey = ownerScopesLabelKey
	cfg.Ownership.InsecureAllowWeakOwnerSelection = true
	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/json"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/*/json"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/start"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodDelete, Path: "/containers/*"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	}
	cfg.Rules = rules
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{Name: "app-a", Rules: rules, Ownership: config.ClientProfileOwnershipConfig{Owner: strPtr("A")}},
		{Name: "app-b", Rules: rules, Ownership: config.ClientProfileOwnershipConfig{Owner: strPtr("B")}},
		{Name: "admin", Rules: rules, Ownership: config.ClientProfileOwnershipConfig{Owner: strPtr("ADM"), Scope: config.OwnershipScopeAll}},
	}
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{
		{Profile: "app-a", CIDRs: []string{"192.0.2.1/32"}},
		{Profile: "app-b", CIDRs: []string{"192.0.2.2/32"}},
		{Profile: "admin", CIDRs: []string{"192.0.2.3/32"}},
	}
	return cfg
}

func newOwnerScopesHarness(t *testing.T, tweak func(*config.Config)) *ownerScopesHarness {
	t.Helper()
	socketPath := shortSocketPath(t, "owner-scopes")
	_ = os.Remove(socketPath)
	daemon := &ownerScopesDaemon{containers: map[string]map[string]string{}}
	startUnixHTTPUpstream(t, socketPath, daemon)

	cfg := ownerScopesConfig(socketPath)
	if tweak != nil {
		tweak(&cfg)
	}
	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
	// The proxy reads the caller's source address from RemoteAddr; let the
	// test choose it per request.
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("X-Test-Remote"); v != "" {
			r.RemoteAddr = v
		}
		handler.ServeHTTP(w, r)
	})
	addr, _ := startProxyChainServer(t, wrapped)
	return &ownerScopesHarness{t: t, addr: addr, daemon: daemon, client: &http.Client{Timeout: 2 * time.Second}}
}

func (h *ownerScopesHarness) do(remote, method, path, body string) (int, string) {
	h.t.Helper()
	req, err := http.NewRequest(method, "http://"+h.addr+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Remote", remote)
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	out, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(out)
}

func (h *ownerScopesHarness) listNames(remote string) []string {
	h.t.Helper()
	status, body := h.do(remote, http.MethodGet, "/v1.45/containers/json?all=1", "")
	if status != http.StatusOK {
		h.t.Fatalf("list status = %d, body %s", status, body)
	}
	var items []struct {
		Id string `json:"Id"`
	}
	if err := json.Unmarshal([]byte(body), &items); err != nil {
		h.t.Fatalf("decode list: %v\n%s", err, body)
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.Id)
	}
	return names
}

func (h *ownerScopesHarness) create(remote, name string) {
	h.t.Helper()
	status, body := h.do(remote, http.MethodPost, "/v1.45/containers/create?name="+name, `{"Image":"alpine"}`)
	if status != http.StatusCreated {
		h.t.Fatalf("create %s status = %d, body %s", name, status, body)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestServeChainOwnerScopesIsolateProfilesByOwner proves that two profiles
// with different owners behind one sockguard cannot see or act on each
// other's containers, and that a request with no profile still runs under the
// root owner.
func TestServeChainOwnerScopesIsolateProfilesByOwner(t *testing.T) {
	h := newOwnerScopesHarness(t, nil)

	h.create(ownerScopesIPA, "a1")
	h.create(ownerScopesIPB, "b1")
	h.create(ownerScopesIPAnon, "r1")
	for name, want := range map[string]string{"a1": "A", "b1": "B", "r1": "root-owner"} {
		if got, ok := h.daemon.labelOf(name); !ok || got != want {
			t.Errorf("container %s owner label = %q (found %v), want %q", name, got, ok, want)
		}
	}

	for _, tc := range []struct {
		name, remote string
		want         []string
	}{
		{"A sees only A", ownerScopesIPA, []string{"a1"}},
		{"B sees only B", ownerScopesIPB, []string{"b1"}},
		{"anonymous sees only the root owner", ownerScopesIPAnon, []string{"r1"}},
	} {
		if got := h.listNames(tc.remote); !equalStrings(got, tc.want) {
			t.Errorf("%s: list = %v, want %v", tc.name, got, tc.want)
		}
	}

	type attempt struct{ method, path string }
	foreign := func(name string) []attempt {
		return []attempt{
			{http.MethodGet, "/v1.45/containers/" + name + "/json"},
			{http.MethodPost, "/v1.45/containers/" + name + "/start"},
			{http.MethodDelete, "/v1.45/containers/" + name},
		}
	}
	for _, tc := range []struct {
		who, remote, foreignName, ownName string
	}{
		{"A", ownerScopesIPA, "b1", "a1"},
		{"B", ownerScopesIPB, "a1", "b1"},
		{"anonymous", ownerScopesIPAnon, "a1", "r1"},
	} {
		for _, a := range foreign(tc.foreignName) {
			if status, _ := h.do(tc.remote, a.method, a.path, ""); status != http.StatusForbidden {
				t.Errorf("%s %s %s status = %d, want 403", tc.who, a.method, a.path, status)
			}
		}
		if status, _ := h.do(tc.remote, http.MethodPost, "/v1.45/containers/"+tc.ownName+"/start", ""); status != http.StatusNoContent {
			t.Errorf("%s start own container status = %d, want 204", tc.who, status)
		}
	}
	if got, want := h.daemon.actions(), []string{"POST /containers/a1/start", "POST /containers/b1/start", "POST /containers/r1/start"}; !equalStrings(got, want) {
		t.Errorf("daemon actions = %v, want only the three own-container starts %v", got, want)
	}
}

// TestServeChainOwnerScopeAllSpansOwners proves scope: all sees and acts on
// every owner's containers, while its creates are stamped with its own owner.
func TestServeChainOwnerScopeAllSpansOwners(t *testing.T) {
	h := newOwnerScopesHarness(t, nil)
	h.daemon.seed("a1", "A")
	h.daemon.seed("b1", "B")
	h.daemon.seed("r1", "root-owner")

	if got := h.listNames(ownerScopesIPAdmin); !equalStrings(got, []string{"a1", "b1", "r1"}) {
		t.Errorf("admin list = %v, want every owner's containers", got)
	}
	for _, name := range []string{"a1", "b1", "r1"} {
		if status, _ := h.do(ownerScopesIPAdmin, http.MethodGet, "/v1.45/containers/"+name+"/json", ""); status != http.StatusOK {
			t.Errorf("admin inspect %s status = %d, want 200", name, status)
		}
		if status, _ := h.do(ownerScopesIPAdmin, http.MethodPost, "/v1.45/containers/"+name+"/start", ""); status != http.StatusNoContent {
			t.Errorf("admin start %s status = %d, want 204", name, status)
		}
	}
	if status, _ := h.do(ownerScopesIPAdmin, http.MethodDelete, "/v1.45/containers/a1", ""); status != http.StatusNoContent {
		t.Errorf("admin delete a1 status = %d, want 204", status)
	}
	h.create(ownerScopesIPAdmin, "adm1")
	if got, _ := h.daemon.labelOf("adm1"); got != "ADM" {
		t.Errorf("admin create owner label = %q, want ADM", got)
	}
	// A tenant profile does not inherit the admin's reach.
	if status, _ := h.do(ownerScopesIPA, http.MethodGet, "/v1.45/containers/b1/json", ""); status != http.StatusForbidden {
		t.Errorf("tenant inspect of another owner status = %d, want 403", status)
	}
}

// TestServeChainOwnerScopesFollowReloadedConfig proves a chain rebuilt from a
// config whose profile owner changed (what a reload does) applies the new
// owner, and that dropping scope: all takes effect the same way.
func TestServeChainOwnerScopesFollowReloadedConfig(t *testing.T) {
	before := newOwnerScopesHarness(t, nil)
	before.create(ownerScopesIPA, "a1")
	if got, _ := before.daemon.labelOf("a1"); got != "A" {
		t.Fatalf("before reload owner label = %q, want A", got)
	}

	after := newOwnerScopesHarness(t, func(cfg *config.Config) {
		cfg.Clients.Profiles[0].Ownership.Owner = strPtr("C")
		cfg.Clients.Profiles[2].Ownership.Scope = ""
	})
	after.daemon.seed("a1", "A")
	after.create(ownerScopesIPA, "a2")
	if got, _ := after.daemon.labelOf("a2"); got != "C" {
		t.Errorf("after reload owner label = %q, want C", got)
	}
	if status, _ := after.do(ownerScopesIPA, http.MethodGet, "/v1.45/containers/a1/json", ""); status != http.StatusForbidden {
		t.Errorf("after reload inspect of the old owner's container status = %d, want 403", status)
	}
	if status, _ := after.do(ownerScopesIPAdmin, http.MethodGet, "/v1.45/containers/a1/json", ""); status != http.StatusForbidden {
		t.Errorf("after scope: all removed, admin inspect of another owner status = %d, want 403", status)
	}
}

// TestServeChainOwnerScopesInheritRootWhenUnset proves a profile with no
// ownership block of its own runs under the root owner.
func TestServeChainOwnerScopesInheritRootWhenUnset(t *testing.T) {
	h := newOwnerScopesHarness(t, func(cfg *config.Config) {
		cfg.Clients.Profiles[0].Ownership = config.ClientProfileOwnershipConfig{}
	})
	h.create(ownerScopesIPA, "a1")
	if got, _ := h.daemon.labelOf("a1"); got != "root-owner" {
		t.Errorf("inheriting profile owner label = %q, want root-owner", got)
	}
}

func TestOwnerScopesGroupProfilesByEffectiveOwnership(t *testing.T) {
	cfg := ownerScopesConfig("unused")
	// A profile restating the root ownership exactly is not its own scope.
	cfg.Clients.Profiles = append(cfg.Clients.Profiles, config.ClientProfileConfig{
		Name:      "same-as-root",
		Ownership: config.ClientProfileOwnershipConfig{Owner: strPtr("root-owner")},
	}, config.ClientProfileConfig{
		Name:      "app-a-twin",
		Ownership: config.ClientProfileOwnershipConfig{Owner: strPtr("A")},
	})
	scopes := newOwnerScopes(&cfg)
	if _, ok := scopes.byProfile["same-as-root"]; ok {
		t.Error("a profile matching the root ownership got its own scope")
	}
	if scopes.byProfile["app-a"] != scopes.byProfile["app-a-twin"] {
		t.Error("profiles with identical effective ownership did not share a key")
	}
	if got := len(scopes.distinct()); got != 4 {
		t.Errorf("distinct scopes = %d, want 4 (root, A, B, admin)", got)
	}
	if k := scopes.keyFor("", false); k != scopes.root {
		t.Error("no profile must resolve to the root key")
	}
	if k := scopes.keyFor("missing", true); k != scopes.root {
		t.Error("an unknown profile must resolve to the root key")
	}
}

// TestBuildkitSolveRefusedUnderProfileOwner pins that a profile's own owner,
// with no root owner at all, reaches the BuildKit image policy: the Solve is
// refused before it can touch buildkitd.
func TestBuildkitSolveRefusedUnderProfileOwner(t *testing.T) {
	var daemonCalls atomic.Int32
	socketPath := startBuildkitDaemonStub(t, &daemonCalls)
	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Ownership.LabelKey = "owner"
	cfg.Ownership.InsecureAllowWeakOwnerSelection = true
	solveAllowed := config.BuildkitControlRequestBodyConfig{Solve: config.BuildkitSolveRequestBodyConfig{Allow: true}}
	cfg.Clients.Profiles = []config.ClientProfileConfig{{
		Name:        "builder",
		RequestBody: config.RequestBodyConfig{Buildkit: config.BuildkitRequestBodyConfig{Control: solveAllowed}},
		Ownership:   config.ClientProfileOwnershipConfig{Owner: strPtr("team-a")},
	}}
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{{Profile: "builder", CIDRs: []string{"127.0.0.0/8"}}}

	resolver := upstream.NewSingleSocket(socketPath)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := withClientACL(&cfg, resolver, newDiscardLogger())(
		withBuildkitMediator(&cfg, resolver, newDiscardLogger(), "docker")(next),
	)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	code, message := solveOverGRPC(t, ln.Addr().String())
	if code != 7 || !strings.Contains(message, "owner isolation") {
		t.Fatalf("Grpc-Status = %d, message = %q, want 7 (PERMISSION_DENIED) naming owner isolation", code, message)
	}
	if got := daemonCalls.Load(); got != 0 {
		t.Fatalf("daemon RPCs = %d, want 0", got)
	}
}

func TestWithOwnershipLogsPrivilegedProfiles(t *testing.T) {
	cfg := ownerScopesConfig("unused")
	collector := &testhelp.CollectingHandler{}
	_ = withOwnership(&cfg, upstream.NewSingleSocket(cfg.Upstream.Socket), collector.Logger(), upstreamflavor.Capabilities{})
	seen := map[string]string{}
	for _, rec := range collector.Records() {
		if name, ok := rec.Attrs["profile"].(string); ok {
			seen[name] = rec.Level.String()
		}
	}
	if seen["admin"] != "WARN" || seen["app-a"] != "INFO" {
		t.Errorf("startup log levels by profile = %v, want admin WARN and app-a INFO", seen)
	}
}
