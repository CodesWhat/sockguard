package ownership

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

// imageCreateDestinationsForTest runs the request-shape pass of a route that
// brings an image in from outside and returns what it captured.
func imageCreateDestinationsForTest(t *testing.T, path, rawQuery string, flavor upstreamflavor.Flavor) ([]imageDestination, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path+"?"+rawQuery, nil)
	refs := imageCreateOwnershipReferences(req, path, flavor)
	if refs.imageDestinations == nil {
		return nil, refs.denyReason
	}
	return refs.imageDestinations.destinations, refs.denyReason
}

// TestImageImportDestination pins the reference an import's parameters build,
// on each route and engine, and every shape that is refused instead.
func TestImageImportDestination(t *testing.T) {
	t.Parallel()
	longShort := strings.Repeat("a", imageTagRepoMaxLen-len("localhost/")-1) + "/b"

	tests := []struct {
		name       string
		path       string
		query      string
		flavor     upstreamflavor.Flavor
		want       []imageDestination
		wantReason string
	}{
		{name: "no repo names nothing", path: imageCreatePath, query: "fromSrc=-"},
		{name: "repo and tag", path: imageCreatePath, query: "fromSrc=-&repo=team%2Fapp&tag=v1", want: []imageDestination{{target: "team/app:v1"}}},
		{name: "default tag", path: imageCreatePath, query: "fromSrc=-&repo=team%2Fapp", want: []imageDestination{{target: "team/app:latest"}}},
		{name: "tag carried in repo", path: imageCreatePath, query: "fromSrc=-&repo=team%2Fapp%3Av1", want: []imageDestination{{target: "team/app:v1"}}},
		{name: "empty fromImage is an import", path: imageCreatePath, query: "fromImage=&fromSrc=-&repo=team%2Fapp", want: []imageDestination{{target: "team/app:latest"}}},
		{
			name: "podman compat short name is checked under both names", path: imageCreatePath, query: "fromSrc=-&repo=team%2Fapp", flavor: upstreamflavor.Podman,
			want: []imageDestination{{target: "team/app:latest", storedTarget: "localhost/team/app:latest"}},
		},
		{name: "repeated repo", path: imageCreatePath, query: "fromSrc=-&repo=mine&repo=theirs", wantReason: imageCreateDenyAmbiguous},
		{name: "case variant of repo", path: imageCreatePath, query: "fromSrc=-&Repo=theirs", wantReason: imageCreateDenyAmbiguous},
		{name: "case variant of tag", path: imageCreatePath, query: "fromSrc=-&repo=mine&Tag=v1", wantReason: imageCreateDenyAmbiguous},
		{name: "repeated fromImage", path: imageCreatePath, query: "fromImage=&fromImage=alpine&repo=theirs", wantReason: imageCreateDenyAmbiguous},
		{name: "case variant of fromImage", path: imageCreatePath, query: "fromimage=alpine&fromSrc=-&repo=theirs", wantReason: imageCreateDenyAmbiguous},
		{name: "semicolon separator", path: imageCreatePath, query: "fromSrc=-&repo=mine;repo=theirs", wantReason: imageCreateDenyAmbiguous},
		{name: "digest in repo", path: imageCreatePath, query: "fromSrc=-&repo=team%2Fapp%40sha256%3Aabc", wantReason: "owner policy denied image import whose repo carries a digest"},
		{name: "tag in repo beside a tag parameter", path: imageCreatePath, query: "fromSrc=-&repo=team%2Fapp%3Av1&tag=v2", wantReason: "owner policy denied image import whose repo already carries a tag beside a tag parameter"},
		{name: "repo outside the grammar", path: imageCreatePath, query: "fromSrc=-&repo=Team%2FApp", wantReason: "owner policy denied image import with a repo outside the image reference grammar"},
		{name: "digest as the tag", path: imageCreatePath, query: "fromSrc=-&repo=team%2Fapp&tag=sha256%3A" + strings.Repeat("a", 64), wantReason: "owner policy denied image import with a tag outside the image reference grammar"},

		{name: "native import with no reference names nothing", path: libpodImageImportPath, query: "message=hi"},
		{name: "native import stores a short name under localhost", path: libpodImageImportPath, query: "reference=team%2Fapp%3Av1", want: []imageDestination{{target: "localhost/team/app:v1"}}},
		{name: "native import default tag", path: libpodImageImportPath, query: "reference=team%2Fapp", want: []imageDestination{{target: "localhost/team/app:latest"}}},
		{name: "native import keeps a name with a registry", path: libpodImageImportPath, query: "reference=quay.io%2Fteam%2Fapp%3Av1", want: []imageDestination{{target: "quay.io/team/app:v1"}}},
		{name: "native import repeated reference", path: libpodImageImportPath, query: "reference=mine&reference=theirs", wantReason: libpodImageImportDenyAmbiguousRef},
		{name: "native import case variant of reference", path: libpodImageImportPath, query: "Reference=theirs", wantReason: libpodImageImportDenyAmbiguousRef},
		{name: "native import bad escape", path: libpodImageImportPath, query: "reference=%zz", wantReason: libpodImageImportDenyAmbiguousRef},
		{name: "native import digest", path: libpodImageImportPath, query: "reference=team%2Fapp%40sha256%3Aabc", wantReason: "owner policy denied image import whose reference carries a digest"},
		{name: "native import short name too long to store", path: libpodImageImportPath, query: "reference=" + longShort, wantReason: "owner policy denied image import with a reference outside the image reference grammar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, reason := imageCreateDestinationsForTest(t, tt.path, tt.query, tt.flavor)
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
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

// TestImageImportAuthorizesTheNameItAssigns sends imports through the
// middleware on both routes and asserts on what reached the daemon.
func TestImageImportAuthorizesTheNameItAssigns(t *testing.T) {
	t.Parallel()
	const heldByAnotherOwner = "owner policy denied image import onto a reference that already names an image outside this owner"

	tests := []struct {
		name         string
		target       string
		allowUnowned bool
		wantStatus   int
		wantReason   string
	}{
		{name: "name another owner's image holds", target: "/images/create?fromSrc=-&repo=theirs%2Fapp&tag=v1", wantStatus: http.StatusForbidden, wantReason: heldByAnotherOwner},
		{name: "name an unlabeled image holds", target: "/v1.45/images/create?fromSrc=-&repo=shared%2Fbase", wantStatus: http.StatusForbidden, wantReason: heldByAnotherOwner},
		{name: "name an unlabeled image holds with unowned images allowed", target: "/images/create?fromSrc=-&repo=shared%2Fbase", allowUnowned: true, wantStatus: http.StatusOK},
		{name: "name the caller's image holds", target: "/images/create?fromSrc=-&repo=mine%2Fapp", wantStatus: http.StatusOK},
		{name: "name nothing holds", target: "/images/create?fromSrc=-&repo=mine%2Fnew", wantStatus: http.StatusOK},
		{name: "no name", target: "/images/create?fromSrc=-", wantStatus: http.StatusOK},
		{name: "unreadable name", target: "/images/create?fromSrc=-&Repo=theirs%2Fapp", wantStatus: http.StatusForbidden, wantReason: imageCreateDenyAmbiguous},
		{name: "native name another owner's image holds", target: "/v5.0.0/libpod/images/import?reference=theirs%2Fapp%3Av1", wantStatus: http.StatusForbidden, wantReason: "libpod " + heldByAnotherOwner},
		{name: "native name nothing holds", target: "/v5.0.0/libpod/images/import?reference=mine%2Fnew", wantStatus: http.StatusOK},
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
			forwarded := false
			handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: tt.allowUnowned}, fi.inspectResource, fi.inspectExec)(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					forwarded = true
					w.WriteHeader(http.StatusOK)
				}))

			meta := &logging.RequestMeta{RolloutMode: "enforce"}
			req := httptest.NewRequest(http.MethodPost, tt.target, strings.NewReader("rootfs"))
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if wantForwarded := tt.wantStatus == http.StatusOK; forwarded != wantForwarded {
				t.Fatalf("forwarded = %v, want %v", forwarded, wantForwarded)
			}
			if tt.wantReason != "" && meta.Reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", meta.Reason, tt.wantReason)
			}
		})
	}
}

// TestImageCreateRoutePathClassification pins which requests the pass reads a
// name from: the method matters, and so does the exact path.
func TestImageCreateRoutePathClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/images/create", true},
		{http.MethodPost, "/libpod/images/import", true},
		{http.MethodGet, "/images/create", false},
		{http.MethodPost, "/images/create/tag", false},
		{http.MethodPost, "/libpod/images/create", false},
		{http.MethodPost, "/images/import", false},
	}
	for _, tt := range tests {
		if got := isImageCreateRoutePath(tt.method, tt.path); got != tt.want {
			t.Errorf("isImageCreateRoutePath(%s, %s) = %v, want %v", tt.method, tt.path, got, tt.want)
		}
	}
}
