package ownership

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

// TestBuildImageDestinations pins the references a build's `t` values build,
// on each route and engine, and every shape that is refused instead.
func TestBuildImageDestinations(t *testing.T) {
	t.Parallel()
	outputs := func(value string) string { return "outputs=" + url.QueryEscape(value) }
	tooMany := strings.Repeat("t=a&", buildMaxTags+1)

	tests := []struct {
		name       string
		query      string
		path       string
		flavor     upstreamflavor.Flavor
		want       []imageDestination
		wantReason string
	}{
		{name: "no tag names nothing", query: "dockerfile=Dockerfile", path: "/build"},
		{name: "empty tag names nothing", query: "t=", path: "/build"},
		{name: "one tag", query: "t=team%2Fapp%3Av1", path: "/build", want: []imageDestination{{target: "team/app:v1"}}},
		{name: "default tag", query: "t=team%2Fapp", path: "/build", want: []imageDestination{{target: "team/app:latest"}}},
		{
			name: "every value is a name", query: "t=team%2Fapp%3Av1&q=1&t=team%2Fapp%3Av2", path: "/build",
			want: []imageDestination{{target: "team/app:v1"}, {target: "team/app:v2"}},
		},
		{name: "a repeated name is checked once", query: "t=team%2Fapp&t=team%2Fapp%3Alatest", path: "/build", want: []imageDestination{{target: "team/app:latest"}}},
		{name: "registry port is not a tag", query: "t=registry.example%3A5000%2Fteam%2Fapp", path: "/build", want: []imageDestination{{target: "registry.example:5000/team/app:latest"}}},
		{name: "an image named docker on dockerd", query: "t=docker%3Adind", path: "/build", want: []imageDestination{{target: "docker:dind"}}},
		{
			name: "an image named docker on podman", query: "t=docker%3Adind", path: "/build", flavor: upstreamflavor.Podman,
			want: []imageDestination{{target: "docker:dind", storedTarget: "localhost/docker:dind"}},
		},
		{name: "a transport name is an image name on dockerd", query: "t=dir%3Aout", path: "/build", flavor: upstreamflavor.Docker, want: []imageDestination{{target: "dir:out"}}},
		{
			name: "podman compat short name is checked under both names", query: "t=team%2Fapp%3Av1", path: "/build", flavor: upstreamflavor.Podman,
			want: []imageDestination{{target: "team/app:v1", storedTarget: "localhost/team/app:v1"}},
		},
		{name: "native route checks the stored name", query: "t=team%2Fapp%3Av1", path: "/libpod/build", want: []imageDestination{{target: "localhost/team/app:v1"}}},
		{name: "native route keeps a name with a registry", query: "t=quay.io%2Fteam%2Fapp", path: "/libpod/build", want: []imageDestination{{target: "quay.io/team/app:latest"}}},
		{name: "output that names nothing", query: outputs(`[{"Type":"local","Attrs":{"dest":"-"}}]`), path: "/build"},
		{name: "empty outputs", query: "outputs=", path: "/build"},
		{name: "empty manifest", query: "manifest=", path: "/libpod/build"},

		{name: "semicolon separator", query: "t=mine;t=theirs", path: "/build", wantReason: buildDenyUnreadableQuery},
		{name: "bad escape", query: "t=%zz", path: "/build", wantReason: buildDenyUnreadableQuery},
		{name: "case variant of t", query: "T=theirs%2Fapp", path: "/build", wantReason: buildDenyAmbiguousTag},
		{name: "case variant of t beside the exact key", query: "t=mine&T=theirs%2Fapp", path: "/libpod/build", wantReason: buildDenyAmbiguousTag},
		{name: "too many tags", query: tooMany, path: "/build", wantReason: buildDenyTooManyTags},
		{name: "digest", query: "t=team%2Fapp%40sha256%3Aabc", path: "/build", wantReason: "owner policy denied build whose t parameter carries a digest"},
		{name: "name outside the grammar", query: "t=Team%2FApp", path: "/build", wantReason: "owner policy denied build with a t parameter outside the image reference grammar"},
		{name: "tag outside the grammar", query: "t=team%2Fapp%3A-v1", path: "/build", wantReason: "owner policy denied build with a tag outside the image reference grammar"},
		{name: "digest algorithm name", query: "t=sha256%3Av1", path: "/build", wantReason: "owner policy denied build whose t parameter is a digest algorithm name: the engines read such a reference as an image ID"},
		{name: "registry transport on the native route", query: "t=docker%3A%2F%2Fregistry.example%2Fapp", path: "/libpod/build", wantReason: "owner policy denied build with a t parameter outside the image reference grammar"},
		{name: "host path transport on the native route", query: "t=dir%3A%2Ftmp%2Fout", path: "/libpod/build", wantReason: buildDenyTransport},
		{name: "storage transport on the native route", query: "t=containers-storage%3Atheirs%3Av1", path: "/libpod/build", wantReason: buildDenyTransport},
		{name: "transport read as a registry port", query: "t=dir%3A5000%2Fout", path: "/libpod/build", wantReason: buildDenyTransport},
		{name: "transport on podman's compat route", query: "t=oci-archive%3Aout", path: "/build", flavor: upstreamflavor.Podman, wantReason: buildDenyTransport},
		{name: "output that names an image", query: outputs(`[{"Type":"image","Attrs":{"name":"theirs/app:v1"}}]`), path: "/build", wantReason: buildDenyOutputName},
		{name: "output named under folded field names", query: outputs(`[{"type":"image","attrs":{"name":"theirs/app:v1"}}]`), path: "/build", wantReason: buildDenyOutputName},
		{name: "second output names an image", query: outputs(`[{"Type":"local"},{"Type":"image","Attrs":{"name":"theirs/app"}}]`), path: "/build", wantReason: buildDenyOutputName},
		{name: "outputs that do not decode", query: outputs(`{"Type":"image"}`), path: "/build", wantReason: buildDenyOutputs},
		{name: "manifest list name", query: "t=mine&manifest=theirs%2Fapp", path: "/libpod/build", wantReason: buildDenyManifest},
		{name: "manifest list name under another spelling", query: "Manifest=theirs%2Fapp", path: "/build", wantReason: buildDenyManifest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			refs, reason := buildImageDestinations(tt.query, tt.path, tt.flavor)
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

// TestBuildAuthorizesTheNamesItAssigns sends builds through the middleware on
// both routes and asserts on what reached the daemon, and on the owner label
// an allowed build carries when it gets there.
func TestBuildAuthorizesTheNamesItAssigns(t *testing.T) {
	t.Parallel()
	const heldByAnotherOwner = "owner policy denied build onto a reference that already names an image outside this owner"

	tests := []struct {
		name         string
		path         string
		query        string
		allowUnowned bool
		wantStatus   int
		wantReason   string
	}{
		{name: "name another owner's image holds", path: "/build", query: "t=theirs%2Fapp%3Av1", wantStatus: http.StatusForbidden, wantReason: heldByAnotherOwner},
		{name: "second name another owner's image holds", path: "/v1.45/build", query: "t=mine%2Fapp&t=theirs%2Fapp%3Av1", wantStatus: http.StatusForbidden, wantReason: heldByAnotherOwner},
		{name: "name an unlabeled image holds", path: "/build", query: "t=shared%2Fbase", wantStatus: http.StatusForbidden, wantReason: heldByAnotherOwner},
		{name: "name an unlabeled image holds with unowned images allowed", path: "/build", query: "t=shared%2Fbase", allowUnowned: true, wantStatus: http.StatusOK},
		{name: "name the caller's image holds", path: "/build", query: "t=mine%2Fapp", wantStatus: http.StatusOK},
		{name: "name nothing holds", path: "/build", query: "t=mine%2Fnew%3Av2", wantStatus: http.StatusOK},
		{name: "no name", path: "/build", query: "q=1", wantStatus: http.StatusOK},
		{name: "native route denial carries the libpod prefix", path: "/v5.0.0/libpod/build", query: "t=theirs%2Fapp%3Av1", wantStatus: http.StatusForbidden, wantReason: "libpod " + heldByAnotherOwner},
		{name: "unreadable name", path: "/build", query: "T=theirs%2Fapp", wantStatus: http.StatusForbidden, wantReason: buildDenyAmbiguousTag},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			theirs := inspectResult{labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true}
			fi := fakeInspector{resources: map[string]map[string]inspectResult{
				"images": {
					"theirs/app:v1":           theirs,
					"localhost/theirs/app:v1": theirs,
					"mine/app:latest":         {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
					"shared/base:latest":      {found: true},
				},
			}}
			var forwardedLabels string
			forwarded := false
			handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: tt.allowUnowned}, fi.inspectResource, fi.inspectExec)(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					forwarded = true
					forwardedLabels = r.URL.Query().Get("labels")
					w.WriteHeader(http.StatusOK)
				}))

			meta := &logging.RequestMeta{RolloutMode: "enforce"}
			req := httptest.NewRequest(http.MethodPost, tt.path+"?"+tt.query, strings.NewReader("FROM scratch\n"))
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if wantForwarded := tt.wantStatus == http.StatusOK; forwarded != wantForwarded {
				t.Fatalf("forwarded = %v, want %v", forwarded, wantForwarded)
			}
			if forwarded && forwardedLabels != `{"com.sockguard.owner":"job-123"}` {
				t.Fatalf("labels forwarded = %q, want the owner label", forwardedLabels)
			}
			if tt.wantReason == "" {
				return
			}
			if meta.Reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", meta.Reason, tt.wantReason)
			}
			if meta.ReasonCode != reasonCodeOwnerPolicyDeniedAccess {
				t.Fatalf("reason code = %q, want %q", meta.ReasonCode, reasonCodeOwnerPolicyDeniedAccess)
			}
		})
	}
}

// TestBuildNameDenialFollowsRolloutModes checks that a refused build name is an
// ordinary policy denial, which warn and audit forward and record, and that
// the build they forward is still stamped: a name this layer would refuse must
// not cost the image its owner label in a rollout that only watches.
func TestBuildNameDenialFollowsRolloutModes(t *testing.T) {
	t.Parallel()
	queries := map[string]string{
		"name another owner's image holds": "t=theirs%2Fapp%3Av1",
		"unreadable name":                  "T=theirs%2Fapp",
		"query that cannot be parsed":      "t=mine;t=theirs",
	}
	for _, mode := range []string{"warn", "audit"} {
		for name, query := range queries {
			t.Run(mode+"/"+name, func(t *testing.T) {
				t.Parallel()
				fi := fakeInspector{resources: map[string]map[string]inspectResult{
					"images": {"theirs/app:v1": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true}},
				}}
				var forwardedLabels string
				forwarded := false
				handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fi.inspectResource, fi.inspectExec)(
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						forwarded = true
						forwardedLabels = r.URL.Query().Get("labels")
						w.WriteHeader(http.StatusOK)
					}))

				meta := &logging.RequestMeta{RolloutMode: mode}
				req := httptest.NewRequest(http.MethodPost, "/build?"+query, strings.NewReader("FROM scratch\n"))
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK || !forwarded {
					t.Fatalf("status = %d, forwarded = %v, want the request forwarded", rec.Code, forwarded)
				}
				if meta.Decision != logging.DecisionWouldDeny {
					t.Fatalf("decision = %q, want %q", meta.Decision, logging.DecisionWouldDeny)
				}
				if forwardedLabels != `{"com.sockguard.owner":"job-123"}` {
					t.Fatalf("labels forwarded = %q, want the owner label stamped", forwardedLabels)
				}
			})
		}
	}
}
