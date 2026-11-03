package ownership

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/logging"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

// pullMockDaemon is the upstream a pull's post-check talks to: it answers an
// image inspect from a label table and records each untag.
type pullMockDaemon struct {
	mu     sync.Mutex
	labels map[string]map[string]string // reference -> labels; absent means not found
	// ids is the image ID each reference points at; unset means the inspect
	// reports no ID. imageLabels is the label set of an image by ID, which a
	// retag puts back under a name.
	ids         map[string]string
	imageLabels map[string]map[string]string
	// written is what the pull puts in the store when the upstream handler
	// runs. Until then the names are free, which the request-side check needs.
	written     map[string]map[string]string
	writtenIDs  map[string]string
	pulled      bool
	inspectFail map[string]bool
	untagFail   bool
	retagFail   bool
	listFail    bool
	// listExtra pads the native list with that many unrelated images.
	listExtra int
	untagged  []string
	// untagQueries is the raw query of each untag, in step with untagged.
	untagQueries []string
	// retagged is "path?query" of each restore.
	retagged []string
	requests []string
	// postInspects are the inspect targets requested after the pull.
	postInspects []string
	// onPostInspect runs under the lock after a post-pull inspect of key, so a
	// test can move a name the way a concurrent pull would.
	onPostInspect func(d *pullMockDaemon, key string)
}

func (d *pullMockDaemon) idOf(ref string) string { return d.ids[ref] }

// lookup resolves a reference or an image ID to a reference the store holds.
func (d *pullMockDaemon) lookup(key string) (string, bool) {
	if _, ok := d.labels[key]; ok {
		return key, true
	}
	for ref, id := range d.ids {
		if _, held := d.labels[ref]; held && (id == key || strings.TrimPrefix(id, "sha256:") == key) {
			return ref, true
		}
	}
	return "", false
}

func (d *pullMockDaemon) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	rec := httptest.NewRecorder()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ids == nil {
		d.ids = map[string]string{}
	}
	d.requests = append(d.requests, req.Method+" "+req.URL.Path)
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/libpod/images/json":
		if d.listFail {
			rec.WriteHeader(http.StatusInternalServerError)
			break
		}
		var filters map[string][]string
		_ = json.Unmarshal([]byte(req.URL.Query().Get("filters")), &filters)
		want := filters["reference"][0]
		wantRepo, wantTag, _ := splitNameTag(want)
		byID := map[string][]string{}
		for ref, id := range d.ids {
			repo, tag, ok := splitNameTag(ref)
			if _, held := d.labels[ref]; held && ok && tag == wantTag && (repo == wantRepo || strings.HasSuffix(repo, "/"+wantRepo)) {
				byID[id] = append(byID[id], ref)
			}
		}
		var entries []map[string]any
		for id, names := range byID {
			sort.Strings(names)
			entries = append(entries, map[string]any{"Id": strings.TrimPrefix(id, "sha256:"), "Names": names})
		}
		for i := 0; i < d.listExtra; i++ {
			entries = append(entries, map[string]any{"Id": fmt.Sprintf("%064d", i), "Names": []string{fmt.Sprintf("other/img%d:v2", i)}})
		}
		out, _ := json.Marshal(entries)
		_, _ = rec.Write(out)
	case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/json"):
		key := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(req.URL.Path, "/libpod"), "/images/"), "/json")
		if d.pulled {
			d.postInspects = append(d.postInspects, key)
		}
		ref, ok := d.lookup(key)
		if d.pulled && d.onPostInspect != nil {
			defer d.onPostInspect(d, key)
		}
		switch {
		case d.pulled && d.inspectFail[key]:
			rec.WriteHeader(http.StatusInternalServerError)
		case !ok:
			rec.WriteHeader(http.StatusNotFound)
		default:
			var pairs []string
			for k, v := range d.labels[ref] {
				pairs = append(pairs, `"`+k+`":"`+v+`"`)
			}
			var tags []string
			for other, id := range d.ids {
				if _, held := d.labels[other]; held && id == d.ids[ref] && id != "" {
					tags = append(tags, `"`+other+`"`)
				}
			}
			sort.Strings(tags)
			idField := ""
			if id := d.idOf(ref); id != "" {
				idField = `"Id":"` + id + `","RepoTags":[` + strings.Join(tags, ",") + `],`
			}
			_, _ = rec.WriteString(`{` + idField + `"Config":{"Labels":{` + strings.Join(pairs, ",") + `}}}`)
		}
	case req.Method == http.MethodDelete:
		ref := strings.TrimPrefix(strings.TrimPrefix(req.URL.Path, "/libpod"), "/images/")
		d.untagged = append(d.untagged, req.URL.Path)
		d.untagQueries = append(d.untagQueries, req.URL.RawQuery)
		if d.untagFail {
			rec.WriteHeader(http.StatusConflict)
			break
		}
		delete(d.labels, ref)
		delete(d.ids, ref)
		_, _ = rec.WriteString(`[{"Untagged":"` + ref + `"}]`)
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/tag"):
		d.retagged = append(d.retagged, req.URL.Path+"?"+req.URL.RawQuery)
		if d.retagFail {
			rec.WriteHeader(http.StatusInternalServerError)
			break
		}
		id := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(req.URL.Path, "/libpod"), "/images/"), "/tag")
		ref := req.URL.Query().Get("repo") + ":" + req.URL.Query().Get("tag")
		d.labels[ref] = d.imageLabels[id]
		d.ids[ref] = id
		rec.WriteHeader(http.StatusCreated)
	default:
		rec.WriteHeader(http.StatusNotFound)
	}
	return rec.Result(), nil
}

const pullProgress = `{"status":"Pulling from team/app"}` + "\n" + `{"status":"Status: Downloaded newer image for team/app:v2"}` + "\n"

func (d *pullMockDaemon) pull() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pulled = true
	if d.labels == nil {
		d.labels = map[string]map[string]string{}
	}
	if d.ids == nil {
		d.ids = map[string]string{}
	}
	if d.imageLabels == nil {
		d.imageLabels = map[string]map[string]string{}
	}
	for ref, labels := range d.written {
		d.labels[ref] = labels
	}
	for ref, id := range d.writtenIDs {
		d.ids[ref] = id
		d.imageLabels[strings.TrimPrefix(id, "sha256:")] = d.written[ref]
	}
}

type pullRun struct {
	target string
	status int
	stream string
	flavor upstreamflavor.Flavor
	// probedDocker is the startup probe having positively identified dockerd.
	probedDocker bool
	// cancelAtEnd cancels the request context as the pull's last line is
	// written, the way a client that hangs up as the pull ends does.
	cancelAtEnd bool
}

func servePull(t *testing.T, daemon *pullMockDaemon, run pullRun) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := MiddlewareWithRoundTripper(daemon, logger, Options{Owner: "job-123", LabelKey: "com.sockguard.owner", UpstreamFlavor: run.flavor, UpstreamProbedDocker: run.probedDocker})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			daemon.pull()
			w.WriteHeader(run.status)
			_, _ = io.WriteString(w, run.stream)
			if run.cancelAtEnd {
				cancel()
			}
		}))
	meta := &logging.RequestMeta{RolloutMode: "enforce"}
	req := httptest.NewRequest(http.MethodPost, run.target, nil)
	req = req.WithContext(logging.WithMeta(ctx, meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, logs.String()
}

func runPull(t *testing.T, daemon *pullMockDaemon, target string, upstreamStatus int) (*httptest.ResponseRecorder, string) {
	t.Helper()
	return servePull(t, daemon, pullRun{target: target, status: upstreamStatus, stream: pullProgress, flavor: upstreamflavor.Docker, probedDocker: true})
}

func TestPullUntagsAnImageWithAnotherOwnersLabel(t *testing.T) {
	t.Parallel()
	const key = "com.sockguard.owner"
	tests := []struct {
		name          string
		target        string
		ref           string
		labels        map[string]string
		inspectFail   bool
		untagFail     bool
		status        int
		wantUntagPath string
		wantErrorLine string
		wantErrorKey  string
		// wantInspect is a case that passes: the post-pull inspect has to
		// have run, or the pass proves nothing.
		wantInspect bool
		// wantQuery is the untag's raw query.
		wantQuery string
	}{
		{
			name: "compat pull of a forged image", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2",
			labels: map[string]string{key: "victim"}, status: http.StatusOK, wantUntagPath: "/images/team/app:v2", wantQuery: "force=1&noprune=1",
			wantErrorLine: `"error":"owner policy removed pulled image team/app:v2: it carries another owner's label"`, wantErrorKey: `"errorDetail":{"message":`,
		},
		{
			name: "native pull of a forged image", target: "/v5.0.0/libpod/images/pull?reference=quay.io%2Fteam%2Fapp%3Av2", ref: "quay.io/team/app:v2",
			labels: map[string]string{key: "victim"}, status: http.StatusOK, wantUntagPath: "/libpod/images/quay.io/team/app:v2", wantQuery: "",
			wantErrorLine: `{"error":"owner policy removed pulled image quay.io/team/app:v2: it carries another owner's label"}`,
		},
		{name: "own label passes", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2", labels: map[string]string{key: "job-123"}, status: http.StatusOK, wantInspect: true},
		{name: "no owner label passes", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2", labels: map[string]string{"other": "x"}, status: http.StatusOK, wantInspect: true},
		{name: "empty owner label passes", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2", labels: map[string]string{key: ""}, status: http.StatusOK, wantInspect: true},
		{
			name: "pull that reported success and wrote nothing is reported", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2", status: http.StatusOK,
			wantErrorLine: `"error":"owner policy could not verify pulled image team/app:v2"`, wantErrorKey: `"errorDetail":{"message":`,
		},
		{name: "upstream refusal is not checked", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2", labels: map[string]string{key: "victim"}, status: http.StatusNotFound},
		{
			name: "failed inspect fails closed", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2",
			inspectFail: true, status: http.StatusOK, wantUntagPath: "/images/team/app:v2", wantQuery: "force=1&noprune=1",
			wantErrorLine: `"error":"owner policy removed pulled image team/app:v2: its owner label could not be verified"`,
		},
		{
			name: "failed untag is reported", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2",
			labels: map[string]string{key: "victim"}, untagFail: true, status: http.StatusOK, wantQuery: "force=1&noprune=1",
			wantErrorLine: `"error":"owner policy could not remove pulled image team/app:v2`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			daemon := &pullMockDaemon{inspectFail: map[string]bool{tt.ref: tt.inspectFail}, untagFail: tt.untagFail}
			if tt.labels != nil {
				daemon.written = map[string]map[string]string{tt.ref: tt.labels}
			}
			rec, logs := runPull(t, daemon, tt.target, tt.status)

			body := rec.Body.String()
			if !strings.HasPrefix(body, pullProgress) {
				t.Fatalf("stream does not begin with the daemon's progress: %q", body)
			}
			tail := strings.TrimPrefix(body, pullProgress)
			if tt.wantErrorLine == "" {
				if tail != "" || len(daemon.untagged) != 0 {
					t.Fatalf("tail = %q, untagged = %v, want a stream left untouched", tail, daemon.untagged)
				}
				if tt.wantInspect && !slices.Contains(daemon.postInspects, tt.ref) {
					t.Fatalf("post-pull inspects = %v, want %s inspected after the pull", daemon.postInspects, tt.ref)
				}
				return
			}
			if !strings.HasSuffix(tail, "\n") || strings.Count(tail, "\n") != 1 || !strings.Contains(tail, tt.wantErrorLine) {
				t.Fatalf("tail = %q, want one line containing %s", tail, tt.wantErrorLine)
			}
			if tt.wantErrorKey != "" && !strings.Contains(tail, tt.wantErrorKey) {
				t.Fatalf("tail = %q, want %s", tail, tt.wantErrorKey)
			}
			if tt.wantUntagPath != "" && (len(daemon.untagged) != 1 || daemon.untagged[0] != tt.wantUntagPath) {
				t.Fatalf("untagged = %v, want [%s]", daemon.untagged, tt.wantUntagPath)
			}
			if len(daemon.untagQueries) > 0 && daemon.untagQueries[0] != tt.wantQuery {
				t.Fatalf("untag query = %q, want %q", daemon.untagQueries[0], tt.wantQuery)
			}
			if tt.untagFail && !strings.Contains(logs, "level=ERROR") {
				t.Fatalf("logs = %q, want an error record for the failed untag", logs)
			}
			if !tt.untagFail && !strings.Contains(logs, "level=WARN") {
				t.Fatalf("logs = %q, want a warn record", logs)
			}
		})
	}
}

// A short name on a Podman-shaped destination is checked under both names, and
// each one the pull wrote is dealt with.
func TestPullChecksBothNamesOfAShortNameOnPodman(t *testing.T) {
	t.Parallel()
	daemon := &pullMockDaemon{written: map[string]map[string]string{
		"localhost/team/app:v2": {"com.sockguard.owner": "victim"},
	}}
	var logs bytes.Buffer
	handler := MiddlewareWithRoundTripper(daemon, slog.New(slog.NewTextHandler(&logs, nil)), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { daemon.pull(); _, _ = io.WriteString(w, pullProgress) }))
	req := httptest.NewRequest(http.MethodPost, "/v5.0.0/libpod/images/pull?reference=team%2Fapp%3Av2", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{RolloutMode: "enforce"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if len(daemon.untagged) != 1 || daemon.untagged[0] != "/libpod/images/localhost/team/app:v2" {
		t.Fatalf("untagged = %v", daemon.untagged)
	}
	if !strings.Contains(rec.Body.String(), "owner policy removed pulled image localhost/team/app:v2") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// Warn and audit rollouts forward what enforce would refuse, so they leave the
// pulled image alone.
func TestPullCheckSkippedInWarnRollout(t *testing.T) {
	t.Parallel()
	daemon := &pullMockDaemon{written: map[string]map[string]string{"team/app:v2": {"com.sockguard.owner": "victim"}}}
	handler := MiddlewareWithRoundTripper(daemon, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { daemon.pull(); _, _ = io.WriteString(w, pullProgress) }))
	req := httptest.NewRequest(http.MethodPost, "/images/create?fromImage=team%2Fapp&tag=v2", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{RolloutMode: "warn"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Body.String() != pullProgress || len(daemon.untagged) != 0 {
		t.Fatalf("body = %q untagged = %v, want the stream untouched", rec.Body.String(), daemon.untagged)
	}
}

func TestImagePullProgressErrorShapes(t *testing.T) {
	t.Parallel()
	if got := imagePullProgressError(true, `a "b"`); got != `{"error":"a \"b\""}` {
		t.Fatalf("libpod = %s", got)
	}
	if got := imagePullProgressError(false, "m"); got != `{"errorDetail":{"message":"m"},"error":"m"}` {
		t.Fatalf("compat = %s", got)
	}
}

const (
	testOwnerKey = "com.sockguard.owner"
	oldImageID   = "sha256:" + "0ld0ld0ld0ld0ld0ld0ld0ld0ld0ld0ld0ld0ld0ld0ld0ld0ld0ld0ld0ld0ld0"
	newImageID   = "sha256:" + "new0new0new0new0new0new0new0new0new0new0new0new0new0new0new0new0"
)

func heldBefore(ref string) *pullMockDaemon {
	return &pullMockDaemon{
		labels:      map[string]map[string]string{ref: {testOwnerKey: "job-123"}},
		ids:         map[string]string{ref: oldImageID},
		imageLabels: map[string]map[string]string{strings.TrimPrefix(oldImageID, "sha256:"): {testOwnerKey: "job-123"}},
		written:     map[string]map[string]string{ref: {testOwnerKey: "victim"}},
		writtenIDs:  map[string]string{ref: newImageID},
	}
}

// A pull that moves a name the requester already held onto a foreign image
// leaves the name on what it held before.
func TestPullRestoresTheRequestersOwnTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		target     string
		ref        string
		wantUntag  string
		wantRetag  string
		wantAppend string
	}{
		{
			name: "compat", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2",
			wantUntag: "/images/team/app:v2",
			wantRetag: "/images/" + strings.TrimPrefix(oldImageID, "sha256:") + "/tag?" + url.Values{"repo": {"team/app"}, "tag": {"v2"}}.Encode(),
		},
		{
			name: "native", target: "/v5.0.0/libpod/images/pull?reference=quay.io%2Fteam%2Fapp%3Av2", ref: "quay.io/team/app:v2",
			wantUntag: "/libpod/images/quay.io/team/app:v2",
			wantRetag: "/libpod/images/" + strings.TrimPrefix(oldImageID, "sha256:") + "/tag?" + url.Values{"repo": {"quay.io/team/app"}, "tag": {"v2"}}.Encode(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			daemon := heldBefore(tt.ref)
			rec, logs := runPull(t, daemon, tt.target, http.StatusOK)

			if len(daemon.untagged) != 1 || daemon.untagged[0] != tt.wantUntag {
				t.Fatalf("untagged = %v, want [%s]", daemon.untagged, tt.wantUntag)
			}
			if len(daemon.retagged) != 1 || daemon.retagged[0] != tt.wantRetag {
				t.Fatalf("retagged = %v, want [%s]", daemon.retagged, tt.wantRetag)
			}
			if got := daemon.ids[tt.ref]; got != strings.TrimPrefix(oldImageID, "sha256:") {
				t.Fatalf("%s points at %q after the restore, want the old image", tt.ref, got)
			}
			tail := strings.TrimPrefix(rec.Body.String(), pullProgress)
			if !strings.Contains(tail, "the reference is back on the image it named before") || strings.Count(tail, "\n") != 1 {
				t.Fatalf("tail = %q, want one line saying the reference was restored", tail)
			}
			if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "restored the reference") {
				t.Fatalf("logs = %q, want a warn record of the restore", logs)
			}
		})
	}
}

// A name nobody held before the pull is only untagged.
func TestPullDoesNotRetagANameNobodyHeld(t *testing.T) {
	t.Parallel()
	daemon := &pullMockDaemon{
		written:    map[string]map[string]string{"team/app:v2": {testOwnerKey: "victim"}},
		writtenIDs: map[string]string{"team/app:v2": newImageID},
	}
	rec, _ := runPull(t, daemon, "/images/create?fromImage=team%2Fapp&tag=v2", http.StatusOK)
	if len(daemon.untagged) != 1 || len(daemon.retagged) != 0 {
		t.Fatalf("untagged = %v retagged = %v, want one untag and no retag", daemon.untagged, daemon.retagged)
	}
	if strings.Contains(rec.Body.String(), "back on the image") {
		t.Fatalf("body = %q, want no restore line", rec.Body.String())
	}
}

func TestPullReportsARestoreThatFailed(t *testing.T) {
	t.Parallel()
	daemon := heldBefore("team/app:v2")
	daemon.retagFail = true
	rec, logs := runPull(t, daemon, "/images/create?fromImage=team%2Fapp&tag=v2", http.StatusOK)
	tail := strings.TrimPrefix(rec.Body.String(), pullProgress)
	if !strings.Contains(tail, "could not restore the image the reference named before") {
		t.Fatalf("tail = %q", tail)
	}
	if !strings.Contains(logs, "level=ERROR") {
		t.Fatalf("logs = %q, want an error record", logs)
	}
}

// force on an untag removes a Podman container's image with it, so a Podman
// upstream gets a plain delete.
func TestPullUntagSendsNoForceToPodman(t *testing.T) {
	t.Parallel()
	daemon := &pullMockDaemon{written: map[string]map[string]string{"localhost/team/app:v2": {testOwnerKey: "victim"}}}
	servePull(t, daemon, pullRun{target: "/images/create?fromImage=team%2Fapp&tag=v2", status: http.StatusOK, stream: pullProgress, flavor: upstreamflavor.Podman})
	if len(daemon.untagged) != 1 || daemon.untagQueries[0] != "" {
		t.Fatalf("untagged = %v queries = %q, want one untag with no query", daemon.untagged, daemon.untagQueries)
	}
}

// An auto or unresolved flavor is not a Docker identification, so the untag
// is a plain delete there too.
func TestPullUntagSendsNoForceToAutoFlavor(t *testing.T) {
	t.Parallel()
	daemon := &pullMockDaemon{written: map[string]map[string]string{"team/app:v2": {testOwnerKey: "victim"}}}
	servePull(t, daemon, pullRun{target: "/images/create?fromImage=team%2Fapp&tag=v2", status: http.StatusOK, stream: pullProgress, flavor: upstreamflavor.Auto})
	if len(daemon.untagged) != 1 || daemon.untagQueries[0] != "" {
		t.Fatalf("untagged = %v queries = %q, want one untag with no query", daemon.untagged, daemon.untagQueries)
	}
}

// A pull that failed in its stream wrote nothing, and says so itself.
func TestPullWithAnErrorLineIsNotReportedUnverified(t *testing.T) {
	t.Parallel()
	daemon := &pullMockDaemon{}
	stream := `{"status":"Pulling from team/app"}` + "\n" + `{"errorDetail":{"message":"manifest unknown"},"error":"manifest unknown"}` + "\n"
	rec, _ := servePull(t, daemon, pullRun{target: "/images/create?fromImage=team%2Fapp&tag=v2", status: http.StatusOK, stream: stream})
	if rec.Body.String() != stream {
		t.Fatalf("body = %q, want the daemon's stream untouched", rec.Body.String())
	}
}

const pullDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// A pull by digest writes no name, but the image is addressable by
// repository@digest, so that reference is checked after the pull. It is only
// ever reported: a digest pins its content and a delete could drop an image
// other names hold.
func TestPullByDigestReportsAForeignImage(t *testing.T) {
	t.Parallel()
	const kept = "carries another owner's label; it was left in place because a digest reference pins its content"
	tests := []struct {
		name       string
		target     string
		ref        string
		flavor     upstreamflavor.Flavor
		probed     bool
		failInspec bool
		existed    bool
		wantLine   string
	}{
		{
			name: "compat pull", target: "/images/create?fromImage=" + url.QueryEscape("team/app@"+pullDigest),
			ref: "team/app@" + pullDigest, flavor: upstreamflavor.Docker, probed: true,
			wantLine: "owner policy: pulled image team/app@" + pullDigest + " " + kept,
		},
		{
			name: "compat pull with the digest in tag", target: "/images/create?fromImage=team%2Fapp%3Av1&tag=" + url.QueryEscape(pullDigest),
			ref: "team/app@" + pullDigest, flavor: upstreamflavor.Docker, probed: true,
			wantLine: "owner policy: pulled image team/app@" + pullDigest + " " + kept,
		},
		{
			name: "libpod pull", target: "/v5.0.0/libpod/images/pull?reference=" + url.QueryEscape("quay.io/team/app@"+pullDigest),
			ref: "quay.io/team/app@" + pullDigest, flavor: upstreamflavor.Podman,
			wantLine: "owner policy: pulled image quay.io/team/app@" + pullDigest + " " + kept,
		},
		{
			name: "reference that existed before the pull", target: "/images/create?fromImage=" + url.QueryEscape("team/app@"+pullDigest),
			ref: "team/app@" + pullDigest, flavor: upstreamflavor.Docker, probed: true, existed: true,
			wantLine: "owner policy: pulled image team/app@" + pullDigest + " " + kept,
		},
		{
			name: "failed inspect is reported unverified", target: "/images/create?fromImage=" + url.QueryEscape("team/app@"+pullDigest),
			ref: "team/app@" + pullDigest, flavor: upstreamflavor.Docker, probed: true, failInspec: true,
			wantLine: "owner policy could not verify pulled image team/app@" + pullDigest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			daemon := &pullMockDaemon{
				written:     map[string]map[string]string{tt.ref: {testOwnerKey: "victim"}},
				inspectFail: map[string]bool{tt.ref: tt.failInspec},
			}
			if tt.existed {
				daemon.labels = map[string]map[string]string{tt.ref: {testOwnerKey: "victim"}}
				daemon.ids = map[string]string{tt.ref: newImageID}
			}
			rec, logs := servePull(t, daemon, pullRun{target: tt.target, status: http.StatusOK, stream: pullProgress, flavor: tt.flavor, probedDocker: tt.probed})
			for _, req := range daemon.requests {
				if strings.HasPrefix(req, http.MethodDelete+" ") {
					t.Fatalf("requests = %v, want no DELETE for a pull by digest", daemon.requests)
				}
			}
			if len(daemon.untagged) != 0 {
				t.Fatalf("untagged = %v, want none", daemon.untagged)
			}
			tail := strings.TrimPrefix(rec.Body.String(), pullProgress)
			if strings.Count(tail, "\n") != 1 || !strings.Contains(tail, tt.wantLine) {
				t.Fatalf("tail = %q, want one error line containing %q", tail, tt.wantLine)
			}
			if !strings.Contains(logs, "level=WARN") {
				t.Fatalf("logs = %q, want a warning", logs)
			}
		})
	}
}

func TestPullByDigestLeavesOwnAndUnlabelledImages(t *testing.T) {
	t.Parallel()
	ref := "team/app@" + pullDigest
	for _, labels := range []map[string]string{{testOwnerKey: "job-123"}, {"other": "x"}} {
		daemon := &pullMockDaemon{written: map[string]map[string]string{ref: labels}}
		rec, _ := servePull(t, daemon, pullRun{target: "/images/create?fromImage=" + url.QueryEscape(ref), status: http.StatusOK, stream: pullProgress, flavor: upstreamflavor.Docker, probedDocker: true})
		if rec.Body.String() != pullProgress || len(daemon.untagged) != 0 || !slices.Contains(daemon.postInspects, ref) {
			t.Fatalf("labels %v: body = %q untagged = %v inspects = %v", labels, rec.Body.String(), daemon.untagged, daemon.postInspects)
		}
	}
}

// The check runs on a context detached from the client's, so a client that
// hangs up as the pull ends cannot skip it.
func TestPullCheckAndUntagRunAfterTheRequestContextIsCancelled(t *testing.T) {
	t.Parallel()
	daemon := &pullMockDaemon{
		written:    map[string]map[string]string{"team/app:v2": {testOwnerKey: "victim"}},
		writtenIDs: map[string]string{"team/app:v2": newImageID},
	}
	rec, _ := servePull(t, daemon, pullRun{target: "/images/create?fromImage=team%2Fapp&tag=v2", status: http.StatusOK, stream: pullProgress, cancelAtEnd: true})
	if len(daemon.untagged) != 1 || daemon.untagged[0] != "/images/team/app:v2" {
		t.Fatalf("untagged = %v, want the foreign image untagged after the cancel", daemon.untagged)
	}
	if !strings.Contains(rec.Body.String(), "owner policy removed pulled image team/app:v2") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// A short name Podman resolved through registries.conf lands on a name the
// computed references do not spell. The pull report names the image ID, and
// the check follows that.
func TestPullFollowsReportedImageIDsOnPodman(t *testing.T) {
	t.Parallel()
	const id = "1234567890ab1234567890ab1234567890ab1234567890ab1234567890ab1234"
	report := pullProgress + `{"images":["` + id + `"],"id":"` + id + `"}` + "\n"
	target := "/v5.0.0/libpod/images/pull?reference=team%2Fapp%3Av2"

	t.Run("pre-existing foreign image under a name outside the computed refs", func(t *testing.T) {
		t.Parallel()
		daemon := &pullMockDaemon{
			labels:     map[string]map[string]string{"quay.io/team/app:v2": {testOwnerKey: "victim"}},
			ids:        map[string]string{"quay.io/team/app:v2": id},
			written:    map[string]map[string]string{"quay.io/team/app:v2": {testOwnerKey: "victim"}},
			writtenIDs: map[string]string{"quay.io/team/app:v2": id},
		}
		rec, logs := servePull(t, daemon, pullRun{target: target, status: http.StatusOK, stream: report, flavor: upstreamflavor.Podman})
		tail := strings.TrimPrefix(rec.Body.String(), report)
		if !strings.Contains(tail, `"error":"owner policy could not remove pulled image quay.io/team/app:v2: it carries another owner's label and is named outside`) || strings.Count(tail, "\n") != 1 {
			t.Fatalf("tail = %q, want one error line naming the resolved name", tail)
		}
		if len(daemon.untagged) != 0 {
			t.Fatalf("untagged = %v, want a name this pull did not compute left alone", daemon.untagged)
		}
		if !strings.Contains(logs, "level=ERROR") {
			t.Fatalf("logs = %q, want an error record", logs)
		}
	})

	t.Run("pre-existing foreign image also under a computed name", func(t *testing.T) {
		t.Parallel()
		daemon := &pullMockDaemon{
			labels: map[string]map[string]string{"quay.io/team/app:v2": {testOwnerKey: "victim"}},
			ids:    map[string]string{"quay.io/team/app:v2": id},
			written: map[string]map[string]string{
				"quay.io/team/app:v2":   {testOwnerKey: "victim"},
				"localhost/team/app:v2": {testOwnerKey: "victim"},
			},
			writtenIDs: map[string]string{"quay.io/team/app:v2": id, "localhost/team/app:v2": id},
		}
		rec, _ := servePull(t, daemon, pullRun{target: target, status: http.StatusOK, stream: report, flavor: upstreamflavor.Podman})
		if len(daemon.untagged) != 1 || daemon.untagged[0] != "/libpod/images/localhost/team/app:v2" {
			t.Fatalf("untagged = %v, want only the computed localhost/ name", daemon.untagged)
		}
		tail := strings.TrimPrefix(rec.Body.String(), report)
		if !strings.Contains(tail, "owner policy removed pulled image localhost/team/app:v2") || !strings.Contains(tail, "could not remove pulled image quay.io/team/app:v2") {
			t.Fatalf("tail = %q, want a removal line and an error line", tail)
		}
	})

	t.Run("image of the requester's own is left alone and counts as verified", func(t *testing.T) {
		t.Parallel()
		daemon := &pullMockDaemon{
			written:    map[string]map[string]string{"quay.io/team/app:v2": {testOwnerKey: "job-123"}},
			writtenIDs: map[string]string{"quay.io/team/app:v2": id},
		}
		rec, _ := servePull(t, daemon, pullRun{target: target, status: http.StatusOK, stream: report, flavor: upstreamflavor.Podman})
		if rec.Body.String() != report || len(daemon.untagged) != 0 {
			t.Fatalf("body = %q untagged = %v, want the stream untouched", rec.Body.String(), daemon.untagged)
		}
		if !slices.Contains(daemon.postInspects, id) {
			t.Fatalf("post-pull inspects = %v, want the reported ID inspected", daemon.postInspects)
		}
	})

	t.Run("reported ID that does not resolve", func(t *testing.T) {
		t.Parallel()
		daemon := &pullMockDaemon{}
		rec, _ := servePull(t, daemon, pullRun{target: target, status: http.StatusOK, stream: report, flavor: upstreamflavor.Podman})
		if !strings.Contains(strings.TrimPrefix(rec.Body.String(), report), "owner policy could not verify pulled image team/app:v2") {
			t.Fatalf("body = %q, want the unverified line", rec.Body.String())
		}
	})
}

// A name registries.conf resolved a short name to, on an image the pull
// created, is this pull's and is removed. The same name on an image that
// existed before the pull is only reported.
func TestPullRemovesResolvedNamesOnlyFromNewImages(t *testing.T) {
	t.Parallel()
	const id = "1234567890ab1234567890ab1234567890ab1234567890ab1234567890ab1234"
	report := pullProgress + `{"images":["` + id + `"],"id":"` + id + `"}` + "\n"
	target := "/v5.0.0/libpod/images/pull?reference=team%2Fapp%3Av2"
	const resolved = "quay.io/team/app:v2"
	foreign := func() map[string]map[string]string {
		return map[string]map[string]string{resolved: {testOwnerKey: "victim"}}
	}

	t.Run("new image is untagged", func(t *testing.T) {
		t.Parallel()
		daemon := &pullMockDaemon{written: foreign(), writtenIDs: map[string]string{resolved: id}}
		rec, _ := servePull(t, daemon, pullRun{target: target, status: http.StatusOK, stream: report, flavor: upstreamflavor.Podman})
		if len(daemon.untagged) != 1 || daemon.untagged[0] != "/libpod/images/"+resolved || daemon.untagQueries[0] != "" {
			t.Fatalf("untagged = %v %v, want the resolved name untagged without force", daemon.untagged, daemon.untagQueries)
		}
		if tail := strings.TrimPrefix(rec.Body.String(), report); !strings.Contains(tail, "owner policy removed pulled image "+resolved+": it carries another owner's label") {
			t.Fatalf("tail = %q", tail)
		}
	})

	t.Run("pre-existing image is report-only", func(t *testing.T) {
		t.Parallel()
		daemon := &pullMockDaemon{labels: foreign(), ids: map[string]string{resolved: "sha256:" + id}, written: foreign(), writtenIDs: map[string]string{resolved: "sha256:" + id}}
		rec, _ := servePull(t, daemon, pullRun{target: target, status: http.StatusOK, stream: report, flavor: upstreamflavor.Podman})
		if len(daemon.untagged) != 0 {
			t.Fatalf("untagged = %v, want a pre-existing image left alone", daemon.untagged)
		}
		if tail := strings.TrimPrefix(rec.Body.String(), report); !strings.Contains(tail, "could not remove pulled image "+resolved) {
			t.Fatalf("tail = %q, want the report-only line", tail)
		}
	})

	for _, tt := range []struct {
		name   string
		daemon *pullMockDaemon
	}{
		{"list over the cap is report-only", &pullMockDaemon{listExtra: maxPrePullImages + 1}},
		{"list that fails is report-only", &pullMockDaemon{listFail: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.daemon.written, tt.daemon.writtenIDs = foreign(), map[string]string{resolved: id}
			rec, _ := servePull(t, tt.daemon, pullRun{target: target, status: http.StatusOK, stream: report, flavor: upstreamflavor.Podman})
			if len(tt.daemon.untagged) != 0 {
				t.Fatalf("untagged = %v, want report-only when the pre-pull list is not trusted", tt.daemon.untagged)
			}
			if tail := strings.TrimPrefix(rec.Body.String(), report); !strings.Contains(tail, "could not remove pulled image "+resolved) {
				t.Fatalf("tail = %q", tail)
			}
		})
	}

	t.Run("name on a new image outside the requested reference is report-only", func(t *testing.T) {
		t.Parallel()
		other := map[string]map[string]string{"quay.io/other/thing:v9": {testOwnerKey: "victim"}}
		daemon := &pullMockDaemon{written: other, writtenIDs: map[string]string{"quay.io/other/thing:v9": id}}
		_, _ = servePull(t, daemon, pullRun{target: target, status: http.StatusOK, stream: report, flavor: upstreamflavor.Podman})
		if len(daemon.untagged) != 0 {
			t.Fatalf("untagged = %v, want a name the request did not ask for left alone", daemon.untagged)
		}
	})
}

// Another pull can move a name between the first inspect and the untag. The
// name is then not this pull's, and is reported instead of untagged.
func TestPullSkipsANameThatMovedBeforeTheUntag(t *testing.T) {
	t.Parallel()
	const id = "1234567890ab1234567890ab1234567890ab1234567890ab1234567890ab1234"
	const otherID = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
	const resolved = "quay.io/team/app:v2"
	report := pullProgress + `{"images":["` + id + `"],"id":"` + id + `"}` + "\n"
	daemon := &pullMockDaemon{
		written:    map[string]map[string]string{resolved: {testOwnerKey: "victim"}},
		writtenIDs: map[string]string{resolved: id},
	}
	daemon.onPostInspect = func(d *pullMockDaemon, key string) {
		if key == id {
			d.ids[resolved] = otherID
			d.onPostInspect = nil
		}
	}
	rec, _ := servePull(t, daemon, pullRun{target: "/v5.0.0/libpod/images/pull?reference=team%2Fapp%3Av2", status: http.StatusOK, stream: report, flavor: upstreamflavor.Podman})
	if len(daemon.untagged) != 0 {
		t.Fatalf("untagged = %v, want a moved name left alone", daemon.untagged)
	}
	if tail := strings.TrimPrefix(rec.Body.String(), report); !strings.Contains(tail, "owner policy left "+resolved+" in place") || strings.Count(tail, "\n") != 1 {
		t.Fatalf("tail = %q, want one line saying the name moved", tail)
	}
}

func TestNamesRequestedReference(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		dest string
		got  string
		want bool
	}{
		{"same name", "app:v1", "app:v1", true},
		{"registry prefix", "app:v1", "quay.io/app:v1", true},
		{"app vs notapp", "app:v1", "notapp:v1", false},
		{"team/app vs xteam/app", "team/app:v1", "xteam/app:v1", false},
		{"team/app under a registry with a port", "team/app:v1", "host:5000/team/app:v1", true},
		{"other repo on a port registry", "app:v1", "host:5000/other:v1", false},
		{"tag mismatch", "app:v1", "quay.io/app:v2", false},
		{"name without a tag", "app:v1", "quay.io/app", false},
		{"empty repo", ":v1", "quay.io/app:v1", false},
		{"empty repo and name", ":v1", ":v1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			refs := &imageDestinationReferences{destinations: []imageDestination{{target: tt.dest}}}
			if got := namesRequestedReference(refs, tt.got); got != tt.want {
				t.Fatalf("namesRequestedReference(%q, %q) = %v, want %v", tt.dest, tt.got, got, tt.want)
			}
		})
	}
}
