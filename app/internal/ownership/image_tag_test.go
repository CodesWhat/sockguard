package ownership

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

const (
	imageTagTestOwner    = "job-123"
	imageTagTestLabelKey = "com.sockguard.owner"
	imageTagTestSource   = "mine:1"
)

// imageTagInspector is a store holding the caller's source image and, when
// target is non-empty, one more image under that reference.
func imageTagInspector(target string, targetState inspectResult) *recordingInspector {
	images := map[string]inspectResult{
		imageTagTestSource: {labels: map[string]string{imageTagTestLabelKey: imageTagTestOwner}, found: true},
	}
	if target != "" {
		images[target] = targetState
	}
	return &recordingInspector{resources: map[string]map[string]inspectResult{
		string(dockerresource.KindImage): images,
	}}
}

func serveImageTagRequest(t *testing.T, inspector *recordingInspector, opts Options, req *http.Request) (rec *httptest.ResponseRecorder, forwarded bool) {
	t.Helper()
	handler := middlewareWithDeps(testLogger(), opts, inspector.inspectResource, inspector.inspectExec)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			forwarded = true
			w.WriteHeader(http.StatusCreated)
		}))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, forwarded
}

func inspectedImages(inspector *recordingInspector) []string {
	ids := make([]string, 0, len(inspector.calls))
	for _, call := range inspector.calls {
		ids = append(ids, call.id)
	}
	return ids
}

// TestImageTagTargetReference pins the reference this layer reads out of
// `repo` and `tag` against the one the engines build. The dockerd column was
// confirmed against dockerd 29.5.2 for every row marked with its outcome, and
// the Podman notes were read from compat.TagImage at v5.8.6.
func TestImageTagTargetReference(t *testing.T) {
	t.Parallel()
	const digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	tests := []struct {
		name     string
		rawQuery string
		want     string
		wantDeny string
	}{
		// dockerd: 201, creates team/app:v1.
		{name: "repo and tag", rawQuery: "repo=team%2Fapp&tag=v1", want: "team/app:v1"},
		// dockerd: 201, creates team/app:latest.
		{name: "repo alone takes the default tag", rawQuery: "repo=team%2Fapp", want: "team/app:latest"},
		// dockerd: 201, creates team/app:latest.
		{name: "empty tag takes the default tag", rawQuery: "repo=team%2Fapp&tag=", want: "team/app:latest"},
		// dockerd: 201, creates team/app:v1. What docker-py sends for
		// image.tag("team/app:v1"). Podman builds team/app:v1:latest and
		// rejects it.
		{name: "repo carries its own tag", rawQuery: "repo=team%2Fapp%3Av1", want: "team/app:v1"},
		{name: "repo carries its own tag beside an empty tag", rawQuery: "repo=team%2Fapp%3Av1&tag=", want: "team/app:v1"},
		// dockerd: 201, creates team/app:v2 and drops v1. Podman builds
		// team/app:v1:v2 and rejects it.
		{name: "repo carries a tag beside a tag parameter", rawQuery: "repo=team%2Fapp%3Av1&tag=v2", wantDeny: imageTagDenyQualifiedRepo},
		// dockerd: 400 "cannot import digest reference", with or without tag.
		{name: "repo carries a digest", rawQuery: "repo=team%2Fapp%40" + digest, wantDeny: imageTagDenyDigest},
		{name: "repo carries a digest beside a tag", rawQuery: "repo=team%2Fapp%40" + digest + "&tag=v1", wantDeny: imageTagDenyDigest},
		{name: "repo carries a tag and a digest", rawQuery: "repo=team%2Fapp%3Av1%40" + digest, wantDeny: imageTagDenyDigest},

		// dockerd: 201, creates registry.example:5000/team/app:v1.
		{name: "registry port with a tag", rawQuery: "repo=registry.example%3A5000%2Fteam%2Fapp&tag=v1", want: "registry.example:5000/team/app:v1"},
		// dockerd: 201, creates registry.example:5000/team/app:latest.
		{name: "registry port is not a tag", rawQuery: "repo=registry.example%3A5000%2Fteam%2Fapp", want: "registry.example:5000/team/app:latest"},
		{name: "registry port and a tag carried in repo", rawQuery: "repo=registry.example%3A5000%2Fteam%2Fapp%3Av1", want: "registry.example:5000/team/app:v1"},
		// dockerd: 201, creates name "localhost" with tag "5000".
		{name: "single segment with a colon is name and tag", rawQuery: "repo=localhost%3A5000", want: "localhost:5000"},
		{name: "localhost registry", rawQuery: "repo=localhost%3A5000%2Fapp&tag=v1", want: "localhost:5000/app:v1"},
		{name: "ipv6 registry", rawQuery: "repo=%5B%3A%3A1%5D%3A5000%2Fapp&tag=v1", want: "[::1]:5000/app:v1"},
		// dockerd: 201. An upper-case first component is a domain to the
		// reference parser, which is the only place the grammar allows it.
		{name: "upper-case domain", rawQuery: "repo=Registry.Example%2Fteam%2Fapp&tag=v1", want: "Registry.Example/team/app:v1"},
		{name: "upper-case path", rawQuery: "repo=registry.example%2FTeam%2Fapp&tag=v1", wantDeny: imageTagDenyInvalidRepo},
		{name: "upper-case single name", rawQuery: "repo=App&tag=v1", wantDeny: imageTagDenyInvalidRepo},
		// dockerd: 201 for both, and both inspect as the same record as
		// their short spelling.
		{name: "explicit docker hub domain", rawQuery: "repo=docker.io%2Flibrary%2Fapp&tag=v1", want: "docker.io/library/app:v1"},
		{name: "path separators", rawQuery: "repo=team%2Fsub_dir%2Fmy-app.v2&tag=v1", want: "team/sub_dir/my-app.v2:v1"},
		{name: "raw slash in the query", rawQuery: "repo=team/app&tag=v1", want: "team/app:v1"},
		{name: "unrelated parameters", rawQuery: "force=1&repo=team%2Fapp&tag=v1&x=y", want: "team/app:v1"},
		{name: "percent-encoded exact key", rawQuery: "re%70o=team%2Fapp&ta%67=v1", want: "team/app:v1"},
		{name: "longest name", rawQuery: "repo=" + strings.Repeat("a", imageTagRepoMaxLen), want: strings.Repeat("a", imageTagRepoMaxLen) + ":latest"},
		{name: "longest tag", rawQuery: "repo=app&tag=" + strings.Repeat("a", imagePushTagMaxLen), want: "app:" + strings.Repeat("a", imagePushTagMaxLen)},

		// dockerd: 200 with no effect. Podman: 400.
		{name: "no query", rawQuery: "", wantDeny: imageTagDenyNoRepo},
		{name: "tag without repo", rawQuery: "tag=v1", wantDeny: imageTagDenyNoRepo},
		{name: "empty repo", rawQuery: "repo=&tag=v1", wantDeny: imageTagDenyNoRepo},

		// dockerd and Podman both read the first value of the exact key.
		{name: "repeated repo", rawQuery: "repo=team%2Fapp&repo=other%2Fapp&tag=v1", wantDeny: imageTagDenyAmbiguous},
		{name: "repeated tag", rawQuery: "repo=team%2Fapp&tag=v1&tag=v2", wantDeny: imageTagDenyAmbiguous},
		{name: "repeated tag with an empty first value", rawQuery: "repo=team%2Fapp&tag=&tag=v2", wantDeny: imageTagDenyAmbiguous},
		{name: "percent-encoded repeated repo", rawQuery: "repo=team%2Fapp&re%70o=other%2Fapp", wantDeny: imageTagDenyAmbiguous},
		// dockerd: ignores the key, so ?Repo= alone is the no-repo shape.
		{name: "capitalized repo key", rawQuery: "Repo=team%2Fapp&tag=v1", wantDeny: imageTagDenyAmbiguous},
		{name: "capitalized tag key", rawQuery: "repo=team%2Fapp&Tag=v1", wantDeny: imageTagDenyAmbiguous},
		{name: "case-variant repo beside the exact key", rawQuery: "repo=team%2Fapp&REPO=other%2Fapp", wantDeny: imageTagDenyAmbiguous},
		// dockerd: 400 for both.
		{name: "semicolon separator", rawQuery: "x;repo=other%2Fapp&repo=team%2Fapp", wantDeny: imageTagDenyAmbiguous},
		{name: "invalid escape", rawQuery: "repo=team%2Fapp&x=%zz", wantDeny: imageTagDenyAmbiguous},

		// dockerd: 400 "invalid tag format".
		{name: "tag with a path separator", rawQuery: "repo=team%2Fapp&tag=v1%2Fjson", wantDeny: imageTagDenyInvalidTag},
		{name: "tag with a leading dash", rawQuery: "repo=team%2Fapp&tag=-v1", wantDeny: imageTagDenyInvalidTag},
		{name: "tag with trailing whitespace", rawQuery: "repo=team%2Fapp&tag=v1%20", wantDeny: imageTagDenyInvalidTag},
		{name: "tag over 128 characters", rawQuery: "repo=team%2Fapp&tag=" + strings.Repeat("a", imagePushTagMaxLen+1), wantDeny: imageTagDenyInvalidTag},
		// dockerd: 400 "invalid reference format" for all of these.
		{name: "repo with a trailing colon", rawQuery: "repo=team%2Fapp%3A", wantDeny: imageTagDenyInvalidTag},
		{name: "repo with an invalid carried tag", rawQuery: "repo=team%2Fapp%3A.v1", wantDeny: imageTagDenyInvalidTag},
		{name: "repo with two colons in the last segment", rawQuery: "repo=team%2Fapp%3Av1%3Av2", wantDeny: imageTagDenyInvalidRepo},
		{name: "repo with leading whitespace", rawQuery: "repo=%20team%2Fapp", wantDeny: imageTagDenyInvalidRepo},
		{name: "repo with a plus-encoded space", rawQuery: "repo=team+app", wantDeny: imageTagDenyInvalidRepo},
		{name: "repo with a leading slash", rawQuery: "repo=%2Fteam%2Fapp", wantDeny: imageTagDenyInvalidRepo},
		{name: "repo with a trailing slash", rawQuery: "repo=team%2Fapp%2F", wantDeny: imageTagDenyInvalidRepo},
		{name: "repo with an empty path segment", rawQuery: "repo=team%2F%2Fapp", wantDeny: imageTagDenyInvalidRepo},
		{name: "repo with a dot segment", rawQuery: "repo=team%2F..%2Fapp", wantDeny: imageTagDenyInvalidRepo},
		{name: "repo with a doubled separator", rawQuery: "repo=team%2Fmy..app", wantDeny: imageTagDenyInvalidRepo},
		{name: "repo with a non-ascii letter", rawQuery: "repo=team%2Fapp%C3%A9", wantDeny: imageTagDenyInvalidRepo},
		{name: "repo with a query delimiter", rawQuery: "repo=team%2Fapp%3Fx", wantDeny: imageTagDenyInvalidRepo},
		{name: "repo that is only a registry port", rawQuery: "repo=registry.example%3A5000%2F", wantDeny: imageTagDenyInvalidRepo},
		{name: "repo over 255 characters", rawQuery: "repo=" + strings.Repeat("a", imageTagRepoMaxLen+1), wantDeny: imageTagDenyInvalidRepo},
		// dockerd: 400 "refusing to create an ambiguous tag using digest
		// algorithm as name". GET /images/sha256:<hex>/json resolves an image
		// by ID prefix, so the inspect could not answer for the name.
		{name: "digest algorithm as the name", rawQuery: "repo=sha256&tag=abcd", wantDeny: imageTagDenyDigestName},
		{name: "digest algorithm with the tag carried in repo", rawQuery: "repo=sha256%3Aabcd", wantDeny: imageTagDenyDigestName},
		{name: "longer digest algorithm as the name", rawQuery: "repo=sha512&tag=" + strings.Repeat("a", 128), wantDeny: imageTagDenyDigestName},
		{name: "digest algorithm under a namespace is an ordinary name", rawQuery: "repo=team%2Fsha256&tag=abcd", want: "team/sha256:abcd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, deny := imageTagTarget(tt.rawQuery, false)
			if got != tt.want || deny != tt.wantDeny {
				t.Fatalf("imageTagTarget(%q) = (%q, %q), want (%q, %q)", tt.rawQuery, got, deny, tt.want, tt.wantDeny)
			}
		})
	}
}

// TestImageTagTargetOnPodmansNativeRoute pins the name the libpod route is
// checked under. Podman's native tag route stores a short name under
// localhost/ without looking anything up (libimage NormalizeName, read at
// go.podman.io/common v0.67.1), so that is the reference the inspect has to
// ask for. The Docker-compatible spelling of each request keeps the name as
// the client sent it.
func TestImageTagTargetOnPodmansNativeRoute(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		rawQuery   string
		wantLibpod string
		wantCompat string
		wantDeny   string
	}{
		{name: "single component", rawQuery: "repo=app&tag=v1", wantLibpod: "localhost/app:v1", wantCompat: "app:v1"},
		{name: "namespaced short name", rawQuery: "repo=team%2Fapp", wantLibpod: "localhost/team/app:latest", wantCompat: "team/app:latest"},
		{name: "library namespace is not a registry", rawQuery: "repo=library%2Fapp", wantLibpod: "localhost/library/app:latest", wantCompat: "library/app:latest"},
		{name: "dotted single component is a path", rawQuery: "repo=my.app", wantLibpod: "localhost/my.app:latest", wantCompat: "my.app:latest"},
		{name: "first component that is not a valid domain", rawQuery: "repo=a_b.c%2Fd", wantLibpod: "localhost/a_b.c/d:latest", wantCompat: "a_b.c/d:latest"},
		{name: "tag carried in a short repo", rawQuery: "repo=team%2Fapp%3Av1", wantLibpod: "localhost/team/app:v1", wantCompat: "team/app:v1"},
		{name: "localhost registry", rawQuery: "repo=localhost%2Fapp", wantLibpod: "localhost/app:latest", wantCompat: "localhost/app:latest"},
		{name: "localhost registry with a port", rawQuery: "repo=localhost%3A5000%2Fapp", wantLibpod: "localhost:5000/app:latest", wantCompat: "localhost:5000/app:latest"},
		{name: "dotted registry", rawQuery: "repo=registry.example%2Fteam%2Fapp&tag=v1", wantLibpod: "registry.example/team/app:v1", wantCompat: "registry.example/team/app:v1"},
		{name: "registry with a port", rawQuery: "repo=registry%3A5000%2Fapp", wantLibpod: "registry:5000/app:latest", wantCompat: "registry:5000/app:latest"},
		{name: "ipv6 registry", rawQuery: "repo=%5B%3A%3A1%5D%3A5000%2Fapp", wantLibpod: "[::1]:5000/app:latest", wantCompat: "[::1]:5000/app:latest"},
		{name: "docker hub", rawQuery: "repo=docker.io%2Flibrary%2Fapp", wantLibpod: "docker.io/library/app:latest", wantCompat: "docker.io/library/app:latest"},
		{name: "upper-case dotted registry", rawQuery: "repo=Registry.Example%2Fapp", wantLibpod: "Registry.Example/app:latest", wantCompat: "Registry.Example/app:latest"},
		// Upper case is legal only in a domain. dockerd reads "Team" as one;
		// Podman stores the name under localhost/, where "Team" is a path
		// component it rejects.
		{name: "upper-case short first component", rawQuery: "repo=Team%2Fapp", wantCompat: "Team/app:latest", wantDeny: imageTagDenyInvalidRepo},
		{name: "digest algorithm as the name", rawQuery: "repo=sha256&tag=abcd", wantDeny: imageTagDenyDigestName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, deny := imageTagTarget(tt.rawQuery, true)
			if got != tt.wantLibpod || deny != tt.wantDeny {
				t.Fatalf("libpod imageTagTarget(%q) = (%q, %q), want (%q, %q)", tt.rawQuery, got, deny, tt.wantLibpod, tt.wantDeny)
			}
			if tt.wantCompat == "" {
				return
			}
			if got, deny := imageTagTarget(tt.rawQuery, false); got != tt.wantCompat || deny != "" {
				t.Fatalf("docker-compatible imageTagTarget(%q) = (%q, %q), want (%q, \"\")", tt.rawQuery, got, deny, tt.wantCompat)
			}
		})
	}
}

// TestLibpodImageTagChecksTheStoredName sends a short name through the
// middleware on Podman's native route. The reference Podman will move is the
// localhost/ one, so that is the image whose owner decides the request, and a
// same-named image under another registry is not the target.
func TestLibpodImageTagChecksTheStoredName(t *testing.T) {
	t.Parallel()
	const path = "/v5.0.0/libpod/images/" + imageTagTestSource + "/tag?repo=team%2Fapp&tag=v2"
	foreign := inspectResult{labels: map[string]string{imageTagTestLabelKey: "someone-else"}, found: true}

	tests := []struct {
		name       string
		holder     string
		wantStatus int
	}{
		{name: "another owner holds the localhost name", holder: "localhost/team/app:v2", wantStatus: http.StatusForbidden},
		{name: "another owner holds the name short-name resolution would find", holder: "team/app:v2", wantStatus: http.StatusCreated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inspector := imageTagInspector(tt.holder, foreign)
			rec, forwarded := serveImageTagRequest(t, inspector, Options{Owner: imageTagTestOwner, LabelKey: imageTagTestLabelKey}, httptest.NewRequest(http.MethodPost, path, nil))

			if rec.Code != tt.wantStatus || forwarded != (tt.wantStatus == http.StatusCreated) {
				t.Fatalf("status = %d forwarded = %v, want %d; body: %s", rec.Code, forwarded, tt.wantStatus, rec.Body.String())
			}
			if got, want := inspectedImages(inspector), []string{imageTagTestSource, "localhost/team/app:v2"}; !slices.Equal(got, want) {
				t.Fatalf("inspected images = %v, want %v", got, want)
			}
		})
	}
}

// TestImageTagAuthorizesSourceAndTarget is the ownership matrix for the
// reference a retag points at its source: an existing reference is taken away
// from the image that holds it, so that image is checked on the same terms as
// the subject of any other per-image request, and a reference nothing holds
// is free to create.
func TestImageTagAuthorizesSourceAndTarget(t *testing.T) {
	t.Parallel()
	const target = "registry.example/team/app:v2"
	const query = "?repo=registry.example%2Fteam%2Fapp&tag=v2"

	routes := []struct {
		name         string
		path         string
		reasonPrefix string
	}{
		{name: "docker-compatible", path: "/v1.45/images/" + imageTagTestSource + "/tag"},
		{name: "libpod", path: "/v5.0.0/libpod/images/" + imageTagTestSource + "/tag", reasonPrefix: "libpod "},
	}
	states := []struct {
		name         string
		present      bool
		state        inspectResult
		allowUnowned bool
		wantStatus   int
	}{
		{name: "target absent", wantStatus: http.StatusCreated},
		{name: "target absent with unowned images refused", wantStatus: http.StatusCreated},
		{name: "target is the caller's", present: true, state: inspectResult{labels: map[string]string{imageTagTestLabelKey: imageTagTestOwner}, found: true}, wantStatus: http.StatusCreated},
		{name: "target is another owner's", present: true, state: inspectResult{labels: map[string]string{imageTagTestLabelKey: "someone-else"}, found: true}, wantStatus: http.StatusForbidden},
		{name: "target is another owner's with unowned images allowed", present: true, state: inspectResult{labels: map[string]string{imageTagTestLabelKey: "someone-else"}, found: true}, allowUnowned: true, wantStatus: http.StatusForbidden},
		{name: "target has no labels and unowned images are allowed", present: true, state: inspectResult{found: true}, allowUnowned: true, wantStatus: http.StatusCreated},
		{name: "target has no labels and unowned images are refused", present: true, state: inspectResult{found: true}, wantStatus: http.StatusForbidden},
		{name: "target has an empty owner label and unowned images are allowed", present: true, state: inspectResult{labels: map[string]string{imageTagTestLabelKey: ""}, found: true}, allowUnowned: true, wantStatus: http.StatusCreated},
		{name: "target has only unrelated labels and unowned images are refused", present: true, state: inspectResult{labels: map[string]string{"maintainer": "x"}, found: true}, wantStatus: http.StatusForbidden},
	}
	for _, route := range routes {
		for _, state := range states {
			t.Run(route.name+"/"+state.name, func(t *testing.T) {
				t.Parallel()
				present := ""
				if state.present {
					present = target
				}
				inspector := imageTagInspector(present, state.state)
				opts := Options{Owner: imageTagTestOwner, LabelKey: imageTagTestLabelKey, AllowUnownedImages: state.allowUnowned}
				rec, forwarded := serveImageTagRequest(t, inspector, opts, httptest.NewRequest(http.MethodPost, route.path+query, nil))

				if rec.Code != state.wantStatus {
					t.Fatalf("status = %d, want %d; body: %s", rec.Code, state.wantStatus, rec.Body.String())
				}
				if wantForwarded := state.wantStatus == http.StatusCreated; forwarded != wantForwarded {
					t.Fatalf("forwarded = %v, want %v", forwarded, wantForwarded)
				}
				if got, want := inspectedImages(inspector), []string{imageTagTestSource, target}; !slices.Equal(got, want) {
					t.Fatalf("inspected images = %v, want the source then the target %v", got, want)
				}
				if state.wantStatus == http.StatusForbidden && !strings.Contains(rec.Body.String(), route.reasonPrefix+imageTagDenyTarget) {
					t.Fatalf("body should carry %q, got: %s", route.reasonPrefix+imageTagDenyTarget, rec.Body.String())
				}
			})
		}
	}
}

// TestImageTagChecksTheSourceFirst keeps the source's answers what they were
// before the target was checked at all: a source that fails never costs a
// second inspect, so its 403 or 404 says nothing about the target.
func TestImageTagChecksTheSourceFirst(t *testing.T) {
	t.Parallel()
	const target = "team/app:v2"
	foreign := inspectResult{labels: map[string]string{imageTagTestLabelKey: "someone-else"}, found: true}

	tests := []struct {
		name         string
		source       string
		sourceState  *inspectResult
		allowUnowned bool
		wantStatus   int
		wantReason   string
		wantInspects []string
	}{
		{name: "foreign source", source: "theirs:1", sourceState: &foreign, wantStatus: http.StatusForbidden, wantReason: "owner policy denied access to image", wantInspects: []string{"theirs:1"}},
		{name: "missing source", source: "absent:1", wantStatus: http.StatusNotFound, wantReason: "owner policy could not resolve image", wantInspects: []string{"absent:1"}},
		{name: "unlabeled source with unowned images refused", source: "base:1", sourceState: &inspectResult{found: true}, wantStatus: http.StatusForbidden, wantReason: "owner policy denied access to image", wantInspects: []string{"base:1"}},
		{name: "unlabeled source onto a foreign target", source: "base:1", sourceState: &inspectResult{found: true}, allowUnowned: true, wantStatus: http.StatusForbidden, wantReason: imageTagDenyTarget, wantInspects: []string{"base:1", target}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inspector := imageTagInspector(target, foreign)
			if tt.sourceState != nil {
				inspector.resources[string(dockerresource.KindImage)][tt.source] = *tt.sourceState
			}
			opts := Options{Owner: imageTagTestOwner, LabelKey: imageTagTestLabelKey, AllowUnownedImages: tt.allowUnowned}
			rec, forwarded := serveImageTagRequest(t, inspector, opts, httptest.NewRequest(http.MethodPost, "/images/"+tt.source+"/tag?repo=team%2Fapp&tag=v2", nil))

			if forwarded {
				t.Fatal("retag reached the upstream")
			}
			if rec.Code != tt.wantStatus || !strings.Contains(rec.Body.String(), tt.wantReason) {
				t.Fatalf("status = %d, body = %s; want %d carrying %q", rec.Code, rec.Body.String(), tt.wantStatus, tt.wantReason)
			}
			if got := inspectedImages(inspector); !slices.Equal(got, tt.wantInspects) {
				t.Fatalf("inspected images = %v, want %v", got, tt.wantInspects)
			}
		})
	}
}

// TestImageTagRefusesUnreadableTargets sends each refused request shape
// through the middleware: it is answered with a 403 before anything is
// inspected, on both spellings of the route, and never reaches the daemon.
func TestImageTagRefusesUnreadableTargets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		rawQuery string
		reason   string
	}{
		{name: "no repo", rawQuery: "", reason: imageTagDenyNoRepo},
		{name: "tag alone", rawQuery: "tag=v1", reason: imageTagDenyNoRepo},
		{name: "repeated repo", rawQuery: "repo=mine%2Fcopy&repo=theirs%2Fapp", reason: imageTagDenyAmbiguous},
		{name: "repeated tag", rawQuery: "repo=theirs%2Fapp&tag=unused&tag=latest", reason: imageTagDenyAmbiguous},
		{name: "capitalized repo key", rawQuery: "Repo=theirs%2Fapp", reason: imageTagDenyAmbiguous},
		{name: "semicolon separator", rawQuery: "x;repo=theirs%2Fapp&repo=mine%2Fcopy", reason: imageTagDenyAmbiguous},
		{name: "invalid escape", rawQuery: "repo=mine%2Fcopy&x=%zz", reason: imageTagDenyAmbiguous},
		{name: "digest in repo", rawQuery: "repo=theirs%2Fapp%40sha256:0000000000000000000000000000000000000000000000000000000000000000&tag=latest", reason: imageTagDenyDigest},
		{name: "tag in repo beside a tag parameter", rawQuery: "repo=mine%2Fcopy%3Av1&tag=latest", reason: imageTagDenyQualifiedRepo},
		{name: "repo outside the grammar", rawQuery: "repo=Theirs%2FApp", reason: imageTagDenyInvalidRepo},
		{name: "tag outside the grammar", rawQuery: "repo=theirs%2Fapp&tag=la%20test", reason: imageTagDenyInvalidTag},
		{name: "digest algorithm as the name", rawQuery: "repo=sha256&tag=abcd", reason: imageTagDenyDigestName},
	}
	routes := []struct {
		name         string
		path         string
		reasonPrefix string
	}{
		{name: "docker-compatible", path: "/v1.45/images/" + imageTagTestSource + "/tag"},
		{name: "libpod", path: "/v5.0.0/libpod/images/" + imageTagTestSource + "/tag", reasonPrefix: "libpod "},
	}
	for _, route := range routes {
		for _, tt := range tests {
			t.Run(route.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				inspector := imageTagInspector("", inspectResult{})
				req := httptest.NewRequest(http.MethodPost, "/", nil)
				req.URL.Path = route.path
				req.URL.RawQuery = tt.rawQuery
				rec, forwarded := serveImageTagRequest(t, inspector, Options{Owner: imageTagTestOwner, LabelKey: imageTagTestLabelKey, AllowUnownedImages: true}, req)

				if forwarded {
					t.Fatal("retag reached the upstream")
				}
				if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), route.reasonPrefix+tt.reason) {
					t.Fatalf("status = %d, body = %s; want %d carrying %q", rec.Code, rec.Body.String(), http.StatusForbidden, route.reasonPrefix+tt.reason)
				}
				if len(inspector.calls) != 0 {
					t.Fatalf("inspect calls = %#v, want none for a refused request shape", inspector.calls)
				}
			})
		}
	}
}

// TestImageTagRolloutModesForwardTheDenial keeps the target check on the
// rollout contract every other request-side owner verdict follows: warn and
// audit record the would-be denial and forward, for the foreign target and
// for a refused request shape alike.
func TestImageTagRolloutModesForwardTheDenial(t *testing.T) {
	t.Parallel()
	const target = "theirs/app:latest"
	foreign := inspectResult{labels: map[string]string{imageTagTestLabelKey: "someone-else"}, found: true}

	for _, mode := range []string{"warn", "audit"} {
		for name, rawQuery := range map[string]string{
			"foreign target":        "repo=theirs%2Fapp&tag=latest",
			"refused request shape": "repo=theirs%2Fapp&repo=mine%2Fcopy",
		} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				t.Parallel()
				inspector := imageTagInspector(target, foreign)
				meta := &logging.RequestMeta{RolloutMode: mode}
				req := httptest.NewRequest(http.MethodPost, "/images/"+imageTagTestSource+"/tag?"+rawQuery, nil)
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec, forwarded := serveImageTagRequest(t, inspector, Options{Owner: imageTagTestOwner, LabelKey: imageTagTestLabelKey}, req)

				if !forwarded || rec.Code != http.StatusCreated {
					t.Fatalf("forwarded = %v status = %d, want true and %d", forwarded, rec.Code, http.StatusCreated)
				}
				if meta.Decision != logging.DecisionWouldDeny || meta.ReasonCode != reasonCodeOwnerPolicyDeniedAccess {
					t.Fatalf("meta = decision %q code %q, want %q and %q", meta.Decision, meta.ReasonCode, logging.DecisionWouldDeny, reasonCodeOwnerPolicyDeniedAccess)
				}
			})
		}
	}
}

// TestImageTagTargetLookupFailureIsNotAVerdict: an inspect of the target that
// errors is a 502 like any other failed lookup, never an allow.
func TestImageTagTargetLookupFailureIsNotAVerdict(t *testing.T) {
	t.Parallel()
	inspector := imageTagInspector("team/app:v2", inspectResult{err: errors.New("upstream returned 500")})
	rec, forwarded := serveImageTagRequest(t, inspector, Options{Owner: imageTagTestOwner, LabelKey: imageTagTestLabelKey, AllowUnownedImages: true},
		httptest.NewRequest(http.MethodPost, "/images/"+imageTagTestSource+"/tag?repo=team%2Fapp&tag=v2", nil))

	if forwarded || rec.Code != http.StatusBadGateway {
		t.Fatalf("forwarded = %v status = %d, want false and %d; body: %s", forwarded, rec.Code, http.StatusBadGateway, rec.Body.String())
	}
}

// TestLibpodImageUntagChecksOnlyItsSource pins why the untag route gets no
// target check although it takes the same `repo` and `tag`. Podman resolves
// the path to one image and removes a name only when that image holds it, so
// the parameters cannot reach another image: the source is the whole effect.
// Any query is forwarded as it came.
func TestLibpodImageUntagChecksOnlyItsSource(t *testing.T) {
	t.Parallel()
	foreign := inspectResult{labels: map[string]string{imageTagTestLabelKey: "someone-else"}, found: true}

	for name, rawQuery := range map[string]string{
		"names another owner's reference":  "repo=theirs%2Fapp&tag=latest",
		"no parameters removes every name": "",
		"repeated repo":                    "repo=mine&repo=theirs%2Fapp",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			inspector := imageTagInspector("theirs/app:latest", foreign)
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.URL.Path = "/v5.0.0/libpod/images/" + imageTagTestSource + "/untag"
			req.URL.RawQuery = rawQuery
			rec, forwarded := serveImageTagRequest(t, inspector, Options{Owner: imageTagTestOwner, LabelKey: imageTagTestLabelKey}, req)

			if !forwarded || rec.Code != http.StatusCreated {
				t.Fatalf("forwarded = %v status = %d, want true and %d; body: %s", forwarded, rec.Code, http.StatusCreated, rec.Body.String())
			}
			if got, want := inspectedImages(inspector), []string{imageTagTestSource}; !slices.Equal(got, want) {
				t.Fatalf("inspected images = %v, want only the source %v", got, want)
			}
		})
	}

	t.Run("foreign source is still denied", func(t *testing.T) {
		t.Parallel()
		inspector := imageTagInspector("theirs/app:latest", foreign)
		rec, forwarded := serveImageTagRequest(t, inspector, Options{Owner: imageTagTestOwner, LabelKey: imageTagTestLabelKey},
			httptest.NewRequest(http.MethodPost, "/v5.0.0/libpod/images/theirs/app:latest/untag", nil))
		if forwarded || rec.Code != http.StatusForbidden {
			t.Fatalf("forwarded = %v status = %d, want false and %d", forwarded, rec.Code, http.StatusForbidden)
		}
	})
}

// TestImageTagRefusalDoesNotShadowImageScp covers the one path the retag
// classifier and the image-SCP route view read differently. Podman routes
// POST /libpod/images/scp/victim/tag/ to the SCP catch-all, because the
// trailing slash keeps it off the anchored tag handler, while the cleaned
// path this layer classifies from ends in /tag. The SCP reading has to win:
// the request is an SCP of a local image nothing holds, not a retag with no
// repo.
func TestImageTagRefusalDoesNotShadowImageScp(t *testing.T) {
	t.Parallel()
	inspector := imageTagInspector("", inspectResult{})
	rec, forwarded := serveImageTagRequest(t, inspector, Options{Owner: imageTagTestOwner, LabelKey: imageTagTestLabelKey},
		httptest.NewRequest(http.MethodPost, "/libpod/images/scp/victim/tag/", nil))

	if forwarded || rec.Code != http.StatusNotFound {
		t.Fatalf("forwarded = %v status = %d, want false and %d; body: %s", forwarded, rec.Code, http.StatusNotFound, rec.Body.String())
	}
	if got, want := inspectedImages(inspector), []string{"victim/tag/"}; !slices.Equal(got, want) {
		t.Fatalf("inspected images = %v, want the SCP source %v", got, want)
	}
}

// TestImageTagWithoutCapturedTargetFailsClosed pins the authorization pass on
// its own: a retag that reaches it with no captured target is refused rather
// than authorized on its source alone, which is the check the route was fixed
// to stop doing.
func TestImageTagWithoutCapturedTargetFailsClosed(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: imageTagTestOwner, LabelKey: imageTagTestLabelKey}

	for _, normPath := range []string{"/images/" + imageTagTestSource + "/tag", "/libpod/images/" + imageTagTestSource + "/tag"} {
		for name, refs := range map[string]*ownershipRequestReferences{
			"nil references":   nil,
			"empty references": {},
			"empty target":     {imageTag: &imageTagOwnershipReference{}},
		} {
			t.Run(normPath+"/"+name, func(t *testing.T) {
				t.Parallel()
				inspector := imageTagInspector("", inspectResult{})
				verdict, reason, err := allowOwnershipRequest(t.Context(), http.MethodPost, normPath, opts, inspector.inspectResource, inspector.inspectExec, refs)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if verdict != verdictDeny || !strings.HasSuffix(reason, imageTagDenyNoRepo) {
					t.Fatalf("verdict = %v, reason = %q; want a deny carrying %q", verdict, reason, imageTagDenyNoRepo)
				}
				if len(inspector.calls) != 0 {
					t.Fatalf("inspect calls = %#v, want none", inspector.calls)
				}
			})
		}
	}
}

// TestIsImageTagRoutePathClassification pins the route classifier itself.
func TestIsImageTagRoutePathClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/images/app/tag", true},
		{http.MethodPost, "/images/registry.example:5000/team/app:v1/tag", true},
		{http.MethodPost, "/libpod/images/app/tag", true},
		{http.MethodPost, "/libpod/images/scp/app/tag", true}, // an image named scp/app: Podman registers /tag ahead of the SCP catch-all
		{http.MethodPost, "/images/tag/tag", true},            // an image named "tag"
		{http.MethodPost, "/images/tag", false},               // no {name}: not a route either engine serves
		{http.MethodPost, "/libpod/images/tag", false},
		{http.MethodPost, "/libpod/images/app/untag", false},
		{http.MethodPost, "/images/app/push", false},
		{http.MethodPost, "/images/app/tag/push", false},
		{http.MethodPost, "/images/app/tags", false},
		{http.MethodPost, "/images/apptag", false},
		{http.MethodGet, "/images/app/tag", false},
		{http.MethodDelete, "/images/app/tag", false},
		{http.MethodPost, "/containers/app/tag", false},
		{http.MethodPost, "/v1.45/images/app/tag", false}, // normPath is version-stripped; the classifier never sees a prefix
	}
	for _, tt := range tests {
		if got := isImageTagRoutePath(tt.method, tt.path); got != tt.want {
			t.Errorf("isImageTagRoutePath(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
		}
	}
}
