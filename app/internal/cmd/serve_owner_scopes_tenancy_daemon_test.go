package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

// tenantRes is one resource of tenancyDaemon, whatever its kind.
type tenantRes struct {
	kind      string
	name      string
	id        string
	labels    map[string]string
	data      string   // secret payload or volume driver data
	names     []string // image reference names
	container string   // exec session target
}

// tenancyDaemon is a fake Docker and Podman daemon holding every resource kind
// the ownership layer scopes, with the lookup rules the proxy relies on: exact
// name or ID first, then a unique ID prefix. It applies `filters` label
// selectors on lists and prunes the way the engines do, so what the proxy
// injects is what narrows them, and it records every request that is not a
// read, so a test can prove a refused request never reached it.
type tenancyDaemon struct {
	mu  sync.Mutex
	res []*tenantRes
	log []string
	seq int

	// inspectDelay stalls every inspect before it answers, outside the lock,
	// which is the gap a lookup-then-write race lives in.
	inspectDelay time.Duration
}

const tenancyLabelKey = "com.sockguard.owner"

func (d *tenancyDaemon) add(kind, name, owner string, mod func(*tenantRes)) *tenantRes {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.addLocked(kind, name, owner, mod)
}

func (d *tenancyDaemon) addLocked(kind, name, owner string, mod func(*tenantRes)) *tenantRes {
	d.seq++
	r := &tenantRes{kind: kind, name: name, labels: map[string]string{}}
	switch kind {
	case "secret":
		r.id = "sec" + strings.Repeat("0", 5) + string(rune('a'+d.seq%26)) + "0123456789abcdef"
	case "image":
		r.id = "sha256:img" + string(rune('a'+d.seq%26)) + "0123456789abcdef"
	default:
		r.id = kind[:1] + "id" + string(rune('a'+d.seq%26)) + "0123456789ab"
	}
	if owner != "" {
		r.labels[tenancyLabelKey] = owner
	}
	if kind == "image" {
		r.names = []string{name}
	}
	if mod != nil {
		mod(r)
	}
	d.res = append(d.res, r)
	return r
}

func (d *tenancyDaemon) find(kind, ident string) *tenantRes {
	ident = strings.TrimPrefix(ident, "/")
	var prefix *tenantRes
	prefixes := 0
	for _, r := range d.res {
		if r.kind != kind {
			continue
		}
		if r.name == ident || r.id == ident {
			return r
		}
		for _, n := range r.names {
			if n == ident {
				return r
			}
		}
		if kind == "image" && strings.TrimPrefix(r.id, "sha256:") == ident {
			return r
		}
		if len(ident) >= 4 && strings.HasPrefix(r.id, ident) && kind != "volume" && kind != "image" {
			prefix = r
			prefixes++
		}
	}
	if prefixes == 1 {
		return prefix
	}
	return nil
}

func (d *tenancyDaemon) remove(r *tenantRes) {
	for i, x := range d.res {
		if x == r {
			d.res = append(d.res[:i], d.res[i+1:]...)
			return
		}
	}
}

func (d *tenancyDaemon) byKind(kind string) []*tenantRes {
	var out []*tenantRes
	for _, r := range d.res {
		if r.kind == kind {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func (d *tenancyDaemon) exists(kind, name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.find(kind, name) != nil
}

// ownerOf reports the owner label and presence of a resource.
func (d *tenancyDaemon) ownerOf(kind, name string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.find(kind, name)
	if r == nil {
		return "", false
	}
	return r.labels[tenancyLabelKey], true
}

func (d *tenancyDaemon) dataOf(kind, name string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r := d.find(kind, name); r != nil {
		return r.data
	}
	return ""
}

// mutations is every request the daemon received that was not a read.
func (d *tenancyDaemon) mutations() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.log...)
}

func (d *tenancyDaemon) matchesFilters(r *tenantRes, raw string) bool {
	for _, f := range labelFilterValues(raw) {
		k, v, _ := strings.Cut(f, "=")
		if r.labels[k] != v {
			return false
		}
	}
	return true
}

func (d *tenancyDaemon) shape(r *tenantRes) map[string]any {
	switch r.kind {
	case "container":
		return map[string]any{"Id": r.id, "Name": "/" + r.name, "Names": []string{"/" + r.name}, "Labels": r.labels, "Config": map[string]any{"Labels": r.labels}}
	case "image":
		return map[string]any{"Id": r.id, "RepoTags": r.names, "Labels": r.labels, "Config": map[string]any{"Labels": r.labels}}
	case "volume":
		return map[string]any{"Name": r.name, "Labels": r.labels, "Options": map[string]string{"data": r.data}}
	case "network":
		return map[string]any{"Id": r.id, "Name": r.name, "Labels": r.labels}
	case "task":
		return map[string]any{"ID": r.id, "Labels": r.labels}
	default: // secret, service
		return map[string]any{"ID": r.id, "Spec": map[string]any{"Name": r.name, "Labels": r.labels}}
	}
}

func (d *tenancyDaemon) respond(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (d *tenancyDaemon) notFound(w http.ResponseWriter) {
	d.respond(w, http.StatusNotFound, map[string]string{"message": "no such resource"})
}

// listRoutes maps a GET collection path to its resource kind.
var tenancyListRoutes = map[string]string{
	"/containers/json": "container", "/images/json": "image", "/volumes": "volume",
	"/networks": "network", "/secrets": "secret", "/services": "service", "/tasks": "task",
}

// inspectPrefixes maps the first path segment of an inspect to its kind.
var tenancyInspectKinds = map[string]string{
	"containers": "container", "images": "image", "volumes": "volume", "networks": "network",
	"secrets": "secret", "services": "service", "tasks": "task",
}

func (d *tenancyDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	path := r.URL.Path
	if strings.HasPrefix(path, "/v1.") {
		if i := strings.Index(path[1:], "/"); i >= 0 {
			path = path[i+1:]
		}
	}
	isRead := r.Method == http.MethodGet || r.Method == http.MethodHead
	isInspect := isRead && (strings.HasSuffix(path, "/json") && !strings.HasSuffix(path, "/containers/json") && !strings.HasSuffix(path, "/images/json") ||
		strings.HasPrefix(path, "/secrets/") || strings.HasPrefix(path, "/volumes/") || strings.HasPrefix(path, "/networks/"))
	if isInspect && d.inspectDelay > 0 {
		// The lookup happens now and the answer is held back, so a racer
		// that creates the name meanwhile is invisible to this inspect.
		rec := httptest.NewRecorder()
		d.serve(rec, r, path, raw, isRead)
		time.Sleep(d.inspectDelay)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
		return
	}
	d.serve(w, r, path, raw, isRead)
}

func (d *tenancyDaemon) serve(w http.ResponseWriter, r *http.Request, path string, raw []byte, isRead bool) {
	w.Header().Set("Content-Type", "application/json")
	q := r.URL.Query()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !isRead {
		d.log = append(d.log, r.Method+" "+path)
	}

	segs := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	// Lists.
	case isRead && tenancyListRoutes[path] != "":
		kind := tenancyListRoutes[path]
		items := []any{}
		for _, res := range d.byKind(kind) {
			if d.matchesFilters(res, q.Get("filters")) {
				items = append(items, d.shape(res))
			}
		}
		if kind == "volume" {
			d.respond(w, http.StatusOK, map[string]any{"Volumes": items})
			return
		}
		d.respond(w, http.StatusOK, items)
	case isRead && path == "/system/df":
		out := map[string]any{"LayersSize": 1, "BuildCache": []any{map[string]any{"ID": "bc-B", "Description": "RUN B-DOCKERFILE-STEP"}}}
		for key, kind := range map[string]string{"Containers": "container", "Images": "image", "Volumes": "volume"} {
			items := []any{}
			for _, res := range d.byKind(kind) {
				items = append(items, d.shape(res))
			}
			out[key] = items
		}
		d.respond(w, http.StatusOK, out)
	case isRead && path == "/swarm":
		d.respond(w, http.StatusOK, map[string]any{"Spec": map[string]any{"Labels": d.find("swarm", "swarm").labels}})
	case isRead && path == "/swarm/unlockkey":
		d.respond(w, http.StatusOK, map[string]string{"UnlockKey": "B-UNLOCK-KEY"})
	case isRead && (len(segs) == 3 && segs[0] == "exec" && segs[2] == "json" || len(segs) == 4 && segs[0] == "libpod" && segs[1] == "exec" && segs[3] == "json"):
		res := d.find("exec", segs[len(segs)-2])
		if res == nil {
			d.notFound(w)
			return
		}
		d.respond(w, http.StatusOK, map[string]string{"ContainerID": res.container})
	case isRead && len(segs) >= 3 && segs[0] == "containers" && (segs[len(segs)-1] == "logs" || segs[len(segs)-1] == "archive"):
		_, _ = io.WriteString(w, "B-LOG-OR-ARCHIVE-DATA")

	// Inspects. A container name may itself contain slashes.
	case isRead && segs[0] == "containers" && len(segs) >= 3 && segs[len(segs)-1] == "json":
		d.inspect(w, "container", strings.Join(segs[1:len(segs)-1], "/"))
	case isRead && len(segs) == 3 && segs[2] == "json" && tenancyInspectKinds[segs[0]] != "":
		d.inspect(w, tenancyInspectKinds[segs[0]], segs[1])
	case isRead && len(segs) == 2 && tenancyInspectKinds[segs[0]] != "":
		d.inspect(w, tenancyInspectKinds[segs[0]], segs[1])
	case isRead && len(segs) >= 3 && segs[0] == "networks":
		d.inspect(w, "network", strings.Join(segs[1:], "/"))
	case isRead && len(segs) >= 3 && segs[0] == "libpod" && segs[1] == "networks" && segs[len(segs)-1] == "json":
		d.inspect(w, "network", strings.Join(segs[2:len(segs)-1], "/"))

	// Creates.
	case r.Method == http.MethodPost && path == "/containers/create":
		name := q.Get("name")
		var body struct{ Labels map[string]string }
		_ = json.Unmarshal(raw, &body)
		if name != "" && d.find("container", name) != nil {
			d.respond(w, http.StatusConflict, map[string]string{"message": "name in use"})
			return
		}
		res := d.addLocked("container", name, "", func(x *tenantRes) { x.labels = body.Labels })
		d.respond(w, http.StatusCreated, map[string]string{"Id": res.id})
	case r.Method == http.MethodPost && (path == "/volumes/create" || path == "/libpod/volumes/create"):
		var body struct {
			Name   string
			Labels map[string]string
		}
		_ = json.Unmarshal(raw, &body)
		if existing := d.find("volume", body.Name); existing != nil {
			d.respond(w, http.StatusCreated, d.shape(existing))
			return
		}
		res := d.addLocked("volume", body.Name, "", func(x *tenantRes) { x.labels = body.Labels; x.data = "vol-data-of-" + body.Labels[tenancyLabelKey] })
		d.respond(w, http.StatusCreated, d.shape(res))
	case r.Method == http.MethodPost && path == "/networks/create":
		var body struct {
			Name   string
			Labels map[string]string
		}
		_ = json.Unmarshal(raw, &body)
		if d.find("network", body.Name) != nil {
			d.respond(w, http.StatusConflict, map[string]string{"message": "network exists"})
			return
		}
		res := d.addLocked("network", body.Name, "", func(x *tenantRes) { x.labels = body.Labels })
		d.respond(w, http.StatusCreated, map[string]string{"Id": res.id})
	case r.Method == http.MethodPost && path == "/libpod/networks/create":
		var body struct {
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		}
		_ = json.Unmarshal(raw, &body)
		if existing := d.find("network", body.Name); existing != nil {
			if q.Get("ignoreIfExists") == "true" {
				d.respond(w, http.StatusOK, map[string]any{"name": existing.name, "id": existing.id, "labels": existing.labels})
				return
			}
			d.respond(w, http.StatusConflict, map[string]string{"message": "network exists"})
			return
		}
		res := d.addLocked("network", body.Name, "", func(x *tenantRes) { x.labels = body.Labels })
		d.respond(w, http.StatusOK, map[string]any{"name": res.name, "id": res.id, "labels": res.labels})
	case r.Method == http.MethodPost && path == "/secrets/create":
		var body struct {
			Name   string
			Labels map[string]string
			Data   string
		}
		_ = json.Unmarshal(raw, &body)
		if d.find("secret", body.Name) != nil {
			d.respond(w, http.StatusConflict, map[string]string{"message": "secret exists"})
			return
		}
		res := d.addLocked("secret", body.Name, "", func(x *tenantRes) { x.labels = body.Labels; x.data = body.Data })
		d.respond(w, http.StatusCreated, map[string]string{"ID": res.id})
	case r.Method == http.MethodPost && path == "/libpod/secrets/create":
		name := q.Get("name")
		var labels map[string]string
		_ = json.Unmarshal([]byte(q.Get("labels")), &labels)
		existing := d.find("secret", name)
		switch {
		case existing != nil && q.Get("replace") == "true":
			existing.labels, existing.data = labels, string(raw)
			d.respond(w, http.StatusOK, map[string]string{"ID": existing.id})
		case existing != nil && q.Get("ignore") == "true":
			d.respond(w, http.StatusOK, map[string]string{"ID": existing.id})
		case existing != nil:
			d.respond(w, http.StatusConflict, map[string]string{"message": "secret exists"})
		default:
			res := d.addLocked("secret", name, "", func(x *tenantRes) { x.labels = labels; x.data = string(raw) })
			d.respond(w, http.StatusOK, map[string]string{"ID": res.id})
		}
	case r.Method == http.MethodPost && path == "/services/create":
		var body struct {
			Name   string
			Labels map[string]string
		}
		_ = json.Unmarshal(raw, &body)
		res := d.addLocked("service", body.Name, "", func(x *tenantRes) { x.labels = body.Labels })
		d.respond(w, http.StatusCreated, map[string]string{"ID": res.id})
	case r.Method == http.MethodPost && len(segs) == 3 && segs[0] == "containers" && segs[2] == "exec":
		target := d.find("container", segs[1])
		if target == nil {
			d.notFound(w)
			return
		}
		res := d.addLocked("exec", "exec-"+segs[1], "", func(x *tenantRes) { x.container = target.id })
		d.respond(w, http.StatusCreated, map[string]string{"Id": res.id})
	case r.Method == http.MethodPost && len(segs) == 3 && segs[0] == "images" && segs[2] == "tag":
		img := d.find("image", segs[1])
		if img == nil {
			d.notFound(w)
			return
		}
		ref := q.Get("repo") + ":" + q.Get("tag")
		for _, other := range d.byKind("image") {
			kept := other.names[:0:0]
			for _, n := range other.names {
				if n != ref {
					kept = append(kept, n)
				}
			}
			other.names = kept
		}
		img.names = append(img.names, ref)
		w.WriteHeader(http.StatusCreated)

	case r.Method == http.MethodDelete && len(segs) == 2 && segs[0] == "secrets":
		res := d.find("secret", segs[1])
		if res == nil {
			d.notFound(w)
			return
		}
		d.remove(res)
		w.WriteHeader(http.StatusNoContent)

	// Podman 6.2 volume rename. The new name comes from the query or the body;
	// a taken name is a conflict, as it is on the daemon.
	case r.Method == http.MethodPost && len(segs) == 4 && segs[0] == "libpod" && segs[1] == "volumes" && segs[3] == "rename":
		res := d.find("volume", segs[2])
		if res == nil {
			d.notFound(w)
			return
		}
		var body struct {
			Name    string `json:"name"`
			NewName string `json:"newName"`
		}
		_ = json.Unmarshal(raw, &body)
		newName := q.Get("name")
		if newName == "" {
			newName = body.Name
		}
		if newName == "" {
			newName = body.NewName
		}
		if d.find("volume", newName) != nil {
			d.respond(w, http.StatusConflict, map[string]string{"message": "volume name in use"})
			return
		}
		res.name = newName
		d.respond(w, http.StatusOK, d.shape(res))

	// Prunes delete what the injected label filter selects.
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/prune"):
		kind := map[string]string{"containers": "container", "volumes": "volume", "networks": "network", "images": "image"}[segs[0]]
		var gone []string
		for _, res := range d.byKind(kind) {
			if d.matchesFilters(res, q.Get("filters")) {
				gone = append(gone, res.name)
				d.remove(res)
			}
		}
		d.respond(w, http.StatusOK, map[string]any{"Pruned": gone})
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (d *tenancyDaemon) inspect(w http.ResponseWriter, kind, ident string) {
	res := d.find(kind, ident)
	if res == nil {
		d.notFound(w)
		return
	}
	d.respond(w, http.StatusOK, d.shape(res))
}

// tenancyHarness runs the full serve chain over a tenancyDaemon with two
// tenant profiles, A and B, plus root. Profiles are picked by source IP; see
// ownerScopesConfig for why the selector kind is not what is under test.
type tenancyHarness struct {
	t      *testing.T
	addr   string
	daemon *tenancyDaemon
	client *http.Client
}

func newTenancyHarness(t *testing.T, podman bool, tweak func(*config.Config)) *tenancyHarness {
	t.Helper()
	socketPath := shortSocketPath(t, "tenancy")
	_ = os.Remove(socketPath)
	daemon := &tenancyDaemon{}
	daemon.add("swarm", "swarm", "B", nil)
	startUnixHTTPUpstream(t, socketPath, daemon)

	cfg := ownerScopesConfig(socketPath)
	allow := []config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "allow"},
	}
	cfg.Rules = allow
	cfg.InsecureAllowBodyBlindWrites = true
	cfg.InsecureAllowReadExfiltration = true
	// The allow-all rule reaches the BuildKit tunnel paths; BuildKit policy is not under test.
	cfg.InsecureAcceptOpaqueBuildkitTunnels = true //nolint:staticcheck // SA1019: deprecated flag is the only way to admit /session in this fixture
	for i := range cfg.Clients.Profiles {
		cfg.Clients.Profiles[i].Rules = allow
	}
	if tweak != nil {
		tweak(&cfg)
	}
	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	deps := newServeTestDeps()
	if podman {
		deps.probeUpstream = func(context.Context, *http.Client) (upstreamflavor.Capabilities, error) {
			return upstreamflavor.Capabilities{Flavor: upstreamflavor.Podman}, nil
		}
	}
	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, deps)
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("X-Test-Remote"); v != "" {
			r.RemoteAddr = v
		}
		handler.ServeHTTP(w, r)
	})
	addr, _ := startProxyChainServer(t, wrapped)
	return &tenancyHarness{t: t, addr: addr, daemon: daemon, client: &http.Client{Timeout: 15 * time.Second}}
}

// do sends one request as remote and returns the status and body.
func (h *tenancyHarness) do(remote, method, path, body string) (int, string) {
	h.t.Helper()
	status, out, err := h.try(remote, method, path, body)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	return status, out
}

// try is do for goroutines, which must not call t.Fatal.
func (h *tenancyHarness) try(remote, method, path, body string) (int, string, error) {
	req, err := http.NewRequest(method, "http://"+h.addr+path, strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Remote", remote)
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	out, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(out), readErr
}
