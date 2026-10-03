package ownership

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/logging"
	"github.com/codeswhat/sockguard/v2/app/internal/upstreamflavor"
)

// TestCommitImageDestination pins the reference a commit's `repo` and `tag`
// build, on each route and engine, and every shape that is refused instead.
func TestCommitImageDestination(t *testing.T) {
	t.Parallel()
	longBare := strings.Repeat("a", imageTagBareRepoMaxLen+1)

	tests := []struct {
		name       string
		query      string
		path       string
		flavor     upstreamflavor.Flavor
		want       []imageDestination
		wantReason string
	}{
		{name: "no repo names nothing", query: "container=c", path: "/commit"},
		{name: "empty repo names nothing", query: "container=c&repo=&tag=v1", path: "/commit"},
		{name: "repo and tag", query: "container=c&repo=team%2Fapp&tag=v1", path: "/commit", want: []imageDestination{{target: "team/app:v1"}}},
		{name: "default tag", query: "container=c&repo=team%2Fapp", path: "/commit", want: []imageDestination{{target: "team/app:latest"}}},
		{name: "empty tag is the default tag", query: "container=c&repo=team%2Fapp&tag=", path: "/commit", want: []imageDestination{{target: "team/app:latest"}}},
		{name: "tag carried in repo", query: "container=c&repo=team%2Fapp%3Av1", path: "/commit", want: []imageDestination{{target: "team/app:v1"}}},
		{name: "registry port is not a tag", query: "container=c&repo=registry.example%3A5000%2Fteam%2Fapp", path: "/commit", want: []imageDestination{{target: "registry.example:5000/team/app:latest"}}},
		{
			name: "podman compat short name is checked under both names", query: "container=c&repo=team%2Fapp&tag=v1", path: "/commit", flavor: upstreamflavor.Podman,
			want: []imageDestination{{target: "team/app:v1", storedTarget: "localhost/team/app:v1"}},
		},
		{
			name: "podman compat name with a registry has one reading", query: "container=c&repo=quay.io%2Fteam%2Fapp&tag=v1", path: "/commit", flavor: upstreamflavor.Podman,
			want: []imageDestination{{target: "quay.io/team/app:v1"}},
		},
		{
			name: "native route is checked under both names whatever the flavor says", query: "container=c&repo=team%2Fapp&tag=v1", path: "/libpod/commit", flavor: upstreamflavor.Docker,
			want: []imageDestination{{target: "team/app:v1", storedTarget: "localhost/team/app:v1"}},
		},
		{name: "repeated repo", query: "container=c&repo=mine&repo=theirs", path: "/commit", wantReason: commitDenyAmbiguousName},
		{name: "repeated tag", query: "container=c&repo=mine&tag=a&tag=b", path: "/commit", wantReason: commitDenyAmbiguousName},
		{name: "case variant of repo", query: "container=c&Repo=theirs", path: "/commit", wantReason: commitDenyAmbiguousName},
		{name: "case variant of tag", query: "container=c&repo=mine&TAG=v1", path: "/commit", wantReason: commitDenyAmbiguousName},
		{name: "semicolon separator", query: "container=c&repo=mine;repo=theirs", path: "/commit", wantReason: commitDenyAmbiguousName},
		{name: "bad escape", query: "container=c&repo=%zz", path: "/commit", wantReason: commitDenyAmbiguousName},
		{name: "digest in repo", query: "container=c&repo=team%2Fapp%40sha256%3Aabc", path: "/commit", wantReason: "owner policy denied commit whose repo carries a digest"},
		{name: "tag in repo beside a tag parameter", query: "container=c&repo=team%2Fapp%3Av1&tag=v2", path: "/commit", wantReason: "owner policy denied commit whose repo already carries a tag beside a tag parameter"},
		{name: "repo outside the grammar", query: "container=c&repo=Team%2FApp", path: "/commit", wantReason: "owner policy denied commit with a repo outside the image reference grammar"},
		{name: "bare repo over the length bound", query: "container=c&repo=" + longBare, path: "/commit", wantReason: "owner policy denied commit with a repo outside the image reference grammar"},
		{name: "tag outside the grammar", query: "container=c&repo=team%2Fapp&tag=-v1", path: "/commit", wantReason: "owner policy denied commit with a tag outside the image reference grammar"},
		{name: "digest algorithm name", query: "container=c&repo=sha256&tag=v1", path: "/commit", wantReason: "owner policy denied commit whose repo is a digest algorithm name: the engines read such a reference as an image ID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			refs, reason := commitImageDestination(tt.query, tt.path, tt.flavor)
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
			var got []imageDestination
			if refs != nil {
				got = refs.destinations
			}
			if len(got) != len(tt.want) {
				t.Fatalf("destinations = %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("destinations = %+v, want %+v", got, tt.want)
				}
			}
		})
	}
}

// TestCommitAuthorizesTheNameItAssigns sends commits through the middleware on
// every spelling of the route and asserts on what reached the daemon.
func TestCommitAuthorizesTheNameItAssigns(t *testing.T) {
	t.Parallel()
	const heldByAnotherOwner = "owner policy denied commit onto a reference that already names an image outside this owner"

	tests := []struct {
		name         string
		query        string
		allowUnowned bool
		wantStatus   int
		wantReason   string
	}{
		{name: "name another owner's image holds", query: "container=owned&repo=theirs%2Fapp&tag=v1", wantStatus: http.StatusForbidden, wantReason: heldByAnotherOwner},
		{name: "default tag another owner's image holds", query: "container=owned&repo=theirs%2Fapp", wantStatus: http.StatusForbidden, wantReason: heldByAnotherOwner},
		{name: "name an unlabeled image holds", query: "container=owned&repo=shared%2Fbase", wantStatus: http.StatusForbidden, wantReason: heldByAnotherOwner},
		{name: "name an unlabeled image holds with unowned images allowed", query: "container=owned&repo=shared%2Fbase", allowUnowned: true, wantStatus: http.StatusCreated},
		{name: "name the caller's image holds", query: "container=owned&repo=mine%2Fapp&tag=v1", wantStatus: http.StatusCreated},
		{name: "name nothing holds", query: "container=owned&repo=mine%2Fnew", wantStatus: http.StatusCreated},
		{name: "no name", query: "container=owned", wantStatus: http.StatusCreated},
		{
			name: "the container is checked before the name", query: "container=foreign&repo=theirs%2Fapp&tag=v1", wantStatus: http.StatusForbidden,
			wantReason: `owner policy denied access to container "foreign" referenced by commit container parameter`,
		},
		{name: "unreadable name", query: "container=owned&repo=mine&repo=theirs%2Fapp", wantStatus: http.StatusForbidden, wantReason: commitDenyAmbiguousName},
	}
	for _, spelling := range commitSpellings {
		for _, tt := range tests {
			t.Run(spelling.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				fi := fakeInspector{resources: map[string]map[string]inspectResult{
					"containers": {
						"owned":   {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
						"foreign": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
					},
					"images": {
						"theirs/app:v1":      {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
						"theirs/app:latest":  {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
						"mine/app:v1":        {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
						"shared/base:latest": {found: true},
					},
				}}
				forwarded := false
				handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: tt.allowUnowned}, fi.inspectResource, fi.inspectExec)(
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						forwarded = true
						w.WriteHeader(http.StatusCreated)
					}))

				meta := &logging.RequestMeta{RolloutMode: "enforce"}
				req := httptest.NewRequest(http.MethodPost, spelling.path+"?"+tt.query, nil)
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != tt.wantStatus {
					t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
				}
				if wantForwarded := tt.wantStatus == http.StatusCreated; forwarded != wantForwarded {
					t.Fatalf("forwarded = %v, want %v", forwarded, wantForwarded)
				}
				if tt.wantReason == "" {
					return
				}
				wantReason := tt.wantReason
				if spelling.libpodPrefix {
					wantReason = "libpod " + wantReason
				}
				if meta.Reason != wantReason {
					t.Fatalf("reason = %q, want %q", meta.Reason, wantReason)
				}
				if meta.ReasonCode != reasonCodeOwnerPolicyDeniedAccess {
					t.Fatalf("reason code = %q, want %q", meta.ReasonCode, reasonCodeOwnerPolicyDeniedAccess)
				}
			})
		}
	}
}

// TestCommitNameLookupFailureIsNotAVerdict keeps a failed lookup of the name
// apart from a denial: the daemon did not answer, so the client gets a 502 and
// nothing is forwarded.
func TestCommitNameLookupFailureIsNotAVerdict(t *testing.T) {
	t.Parallel()
	fi := fakeInspector{resources: map[string]map[string]inspectResult{
		"containers": {"owned": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
		"images":     {"mine/app:latest": {err: errors.New("daemon unavailable")}},
	}}
	forwarded := false
	handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fi.inspectResource, fi.inspectExec)(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded = true }))

	meta := &logging.RequestMeta{RolloutMode: "enforce"}
	req := httptest.NewRequest(http.MethodPost, "/commit?container=owned&repo=mine%2Fapp", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway || forwarded {
		t.Fatalf("status = %d, forwarded = %v, want 502 and nothing forwarded", rec.Code, forwarded)
	}
	if meta.ReasonCode != reasonCodeOwnerPolicyLookupFailed {
		t.Fatalf("reason code = %q, want %q", meta.ReasonCode, reasonCodeOwnerPolicyLookupFailed)
	}
}

// TestCommitNameDenialFollowsRolloutModes checks that the refusal is an
// ordinary policy denial, which warn and audit forward and record, and that
// the commit they forward is still stamped: a name this layer would refuse
// must not cost the image its owner label in a rollout that only watches.
func TestCommitNameDenialFollowsRolloutModes(t *testing.T) {
	t.Parallel()
	queries := map[string]string{
		"name another owner's image holds": "container=owned&repo=theirs%2Fapp",
		"unreadable name":                  "container=owned&repo=mine&repo=theirs%2Fapp",
	}
	for _, mode := range []string{"warn", "audit"} {
		for name, query := range queries {
			t.Run(mode+"/"+name, func(t *testing.T) {
				t.Parallel()
				fi := fakeInspector{resources: map[string]map[string]inspectResult{
					"containers": {"owned": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
					"images":     {"theirs/app:latest": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true}},
				}}
				var forwardedBody string
				forwarded := false
				handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fi.inspectResource, fi.inspectExec)(
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						forwarded = true
						body, _ := io.ReadAll(r.Body)
						forwardedBody = string(body)
						w.WriteHeader(http.StatusCreated)
					}))

				meta := &logging.RequestMeta{RolloutMode: mode}
				req := httptest.NewRequest(http.MethodPost, "/commit?"+query, nil)
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != http.StatusCreated || !forwarded {
					t.Fatalf("status = %d, forwarded = %v, want the request forwarded", rec.Code, forwarded)
				}
				if meta.Decision != logging.DecisionWouldDeny {
					t.Fatalf("decision = %q, want %q", meta.Decision, logging.DecisionWouldDeny)
				}
				if forwardedBody != `{"Labels":{"com.sockguard.owner":"job-123"}}` {
					t.Fatalf("forwarded body = %q, want the owner label stamped", forwardedBody)
				}
			})
		}
	}
}
