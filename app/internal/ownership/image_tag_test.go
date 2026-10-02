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
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
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
		// The 255 bound is on the repository path, and dockerd completes a
		// name with no slash to library/<name> before it measures. A name
		// with a slash is measured as spelled. dockerd 29.5.2 answers the
		// inspect of each of these with a plain 404.
		{name: "longest single-segment name", rawQuery: "repo=" + strings.Repeat("a", imageTagBareRepoMaxLen), want: strings.Repeat("a", imageTagBareRepoMaxLen) + ":latest"},
		{name: "longest single-segment name with its tag carried in repo", rawQuery: "repo=" + strings.Repeat("a", imageTagBareRepoMaxLen) + "%3Av1", want: strings.Repeat("a", imageTagBareRepoMaxLen) + ":v1"},
		{name: "longest multi-segment name", rawQuery: "repo=team%2F" + strings.Repeat("a", imageTagRepoMaxLen-len("team/")), want: "team/" + strings.Repeat("a", imageTagRepoMaxLen-len("team/")) + ":latest"},
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
		{name: "multi-segment repo over 255 characters", rawQuery: "repo=team%2F" + strings.Repeat("a", imageTagRepoMaxLen+1-len("team/")), wantDeny: imageTagDenyInvalidRepo},
		// dockerd: 400 "repository name must not be more than 255
		// characters" on the inspect of each, which this layer would turn
		// into a 502 the client can produce at will. library/<name> is over
		// the bound although the name as spelled is not.
		{name: "single-segment repo one over what library/ leaves room for", rawQuery: "repo=" + strings.Repeat("a", imageTagBareRepoMaxLen+1), wantDeny: imageTagDenyInvalidRepo},
		{name: "single-segment repo one over with its tag carried in repo", rawQuery: "repo=" + strings.Repeat("a", imageTagBareRepoMaxLen+1) + "%3Av1", wantDeny: imageTagDenyInvalidRepo},
		{name: "single-segment repo at 255 characters", rawQuery: "repo=" + strings.Repeat("a", imageTagRepoMaxLen), wantDeny: imageTagDenyInvalidRepo},
		// dockerd: 400 "refusing to create an ambiguous tag using digest
		// algorithm as name". GET /images/sha256:<hex>/json resolves an image
		// by ID prefix, so the inspect could not answer for the name.
		{name: "digest algorithm as the name", rawQuery: "repo=sha256&tag=abcd", wantDeny: imageTagDenyDigestName},
		{name: "digest algorithm with the tag carried in repo", rawQuery: "repo=sha256%3Aabcd", wantDeny: imageTagDenyDigestName},
		// dockerd refuses only "sha256" and would create these two. They are
		// refused here because <algorithm>:<hex> of the right length parses
		// as a digest, so the inspect could not ask for the name.
		{name: "sha384 as the name", rawQuery: "repo=sha384&tag=" + strings.Repeat("a", 96), wantDeny: imageTagDenyDigestName},
		{name: "sha512 as the name", rawQuery: "repo=sha512&tag=" + strings.Repeat("a", 128), wantDeny: imageTagDenyDigestName},
		{name: "digest algorithm under a namespace is an ordinary name", rawQuery: "repo=team%2Fsha256&tag=abcd", want: "team/sha256:abcd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, stored, deny := imageTagTarget(tt.rawQuery, imageTagNamedAsSpelled)
			if got != tt.want || stored != "" || deny != tt.wantDeny {
				t.Fatalf("imageTagTarget(%q) = (%q, %q, %q), want (%q, \"\", %q)", tt.rawQuery, got, stored, deny, tt.want, tt.wantDeny)
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
//
// On a Podman upstream the Docker-compatible route can land on either, so it
// reads both out of the same request: the name as spelled is the target and
// the localhost/ one comes back beside it. A `repo` that names its registry
// has one name, and a name the native route refuses is refused there too.
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
		// Podman's reference grammar bounds the whole name, registry
		// included, so the localhost/ it adds counts toward the 255.
		{
			name:       "longest short name that fits under localhost",
			rawQuery:   "repo=team%2F" + strings.Repeat("a", imageTagRepoMaxLen-len("localhost/team/")),
			wantLibpod: "localhost/team/" + strings.Repeat("a", imageTagRepoMaxLen-len("localhost/team/")) + ":latest",
			wantCompat: "team/" + strings.Repeat("a", imageTagRepoMaxLen-len("localhost/team/")) + ":latest",
		},
		{
			name:       "short name that outgrows the bound under localhost",
			rawQuery:   "repo=team%2F" + strings.Repeat("a", imageTagRepoMaxLen+1-len("localhost/team/")),
			wantCompat: "team/" + strings.Repeat("a", imageTagRepoMaxLen+1-len("localhost/team/")) + ":latest",
			wantDeny:   imageTagDenyInvalidRepo,
		},
		{
			name:       "qualified name at the bound is not prefixed",
			rawQuery:   "repo=registry.example%2F" + strings.Repeat("a", imageTagRepoMaxLen-len("registry.example/")),
			wantLibpod: "registry.example/" + strings.Repeat("a", imageTagRepoMaxLen-len("registry.example/")) + ":latest",
			wantCompat: "registry.example/" + strings.Repeat("a", imageTagRepoMaxLen-len("registry.example/")) + ":latest",
		},
		{name: "digest algorithm as the name", rawQuery: "repo=sha256&tag=abcd", wantDeny: imageTagDenyDigestName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, stored, deny := imageTagTarget(tt.rawQuery, imageTagNamedAsStored)
			if got != tt.wantLibpod || stored != "" || deny != tt.wantDeny {
				t.Fatalf("libpod imageTagTarget(%q) = (%q, %q, %q), want (%q, \"\", %q)", tt.rawQuery, got, stored, deny, tt.wantLibpod, tt.wantDeny)
			}

			wantTarget, wantStored := tt.wantCompat, tt.wantLibpod
			switch {
			case tt.wantDeny != "":
				wantTarget, wantStored = "", ""
			case wantStored == wantTarget:
				wantStored = ""
			}
			if got, stored, deny := imageTagTarget(tt.rawQuery, imageTagNamedEitherWay); got != wantTarget || stored != wantStored || deny != tt.wantDeny {
				t.Fatalf("docker-compatible on podman imageTagTarget(%q) = (%q, %q, %q), want (%q, %q, %q)", tt.rawQuery, got, stored, deny, wantTarget, wantStored, tt.wantDeny)
			}

			if tt.wantCompat == "" {
				return
			}
			if got, stored, deny := imageTagTarget(tt.rawQuery, imageTagNamedAsSpelled); got != tt.wantCompat || stored != "" || deny != "" {
				t.Fatalf("docker-compatible imageTagTarget(%q) = (%q, %q, %q), want (%q, \"\", \"\")", tt.rawQuery, got, stored, deny, tt.wantCompat)
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

// TestCompatImageTagChecksBothNamesOnPodman covers the Docker-compatible route
// on a Podman upstream, where a `repo` that names no registry has two possible
// destinations and this layer cannot tell which one the daemon will write.
//
// With compat_api_enforce_docker_hub at its default, Podman looks the short
// name up (alias first) and tags the name the lookup found, which is the image
// the inspect of the name as spelled answers with. With the option off it
// stores the name under localhost/ and looks nothing up (NormalizeToDockerHub
// and libimage's NormalizeName, read from Podman 5.8.6). So both are
// inspected, and the request goes through only when neither takes a name from
// another owner. dockerd has one reading of a name and is asked once.
func TestCompatImageTagChecksBothNamesOnPodman(t *testing.T) {
	t.Parallel()
	const (
		compatPath = "/v1.45/images/" + imageTagTestSource + "/tag"
		libpodPath = "/v5.0.0/libpod/images/" + imageTagTestSource + "/tag"
		short      = "?repo=nginx&tag=prod"
		spelled    = "nginx:prod"
		stored     = "localhost/nginx:prod"
	)
	own := inspectResult{labels: map[string]string{imageTagTestLabelKey: imageTagTestOwner}, found: true}
	foreign := inspectResult{labels: map[string]string{imageTagTestLabelKey: "someone-else"}, found: true}
	unlabeled := inspectResult{found: true}
	failing := inspectResult{err: errors.New("upstream returned 500")}
	// One character more than fits once Podman puts localhost/ in front.
	longShort := "team/" + strings.Repeat("a", imageTagRepoMaxLen+1-len("localhost/team/"))

	tests := []struct {
		name         string
		flavor       upstreamflavor.Flavor
		path         string
		query        string
		images       map[string]inspectResult
		allowUnowned bool
		wantStatus   int
		wantReason   string
		wantInspects []string
	}{
		{
			name: "podman: caller holds both names", flavor: upstreamflavor.Podman, path: compatPath, query: short,
			images:     map[string]inspectResult{spelled: own, stored: own},
			wantStatus: http.StatusCreated, wantInspects: []string{imageTagTestSource, spelled, stored},
		},
		{
			name: "podman: neither name is held", flavor: upstreamflavor.Podman, path: compatPath, query: short,
			wantStatus: http.StatusCreated, wantInspects: []string{imageTagTestSource, spelled, stored},
		},
		{
			// The image short-name resolution finds is another owner's. The
			// first inspect settles it.
			name: "podman: another owner holds the name as spelled", flavor: upstreamflavor.Podman, path: compatPath, query: short,
			images:     map[string]inspectResult{spelled: foreign, stored: own},
			wantStatus: http.StatusForbidden, wantReason: imageTagDenyTarget, wantInspects: []string{imageTagTestSource, spelled},
		},
		{
			// The reported case: the alias resolves to the caller's image and
			// localhost/ is another owner's.
			name: "podman: another owner holds the localhost name", flavor: upstreamflavor.Podman, path: compatPath, query: short,
			images:     map[string]inspectResult{spelled: own, stored: foreign},
			wantStatus: http.StatusForbidden, wantReason: imageTagDenyTarget, wantInspects: []string{imageTagTestSource, spelled, stored},
		},
		{
			name: "podman: another owner holds the localhost name and nothing answers for the short one", flavor: upstreamflavor.Podman, path: compatPath, query: short,
			images:     map[string]inspectResult{stored: foreign},
			wantStatus: http.StatusForbidden, wantReason: imageTagDenyTarget, wantInspects: []string{imageTagTestSource, spelled, stored},
		},
		{
			name: "podman: unlabeled image holds the localhost name and unowned images are allowed", flavor: upstreamflavor.Podman, path: compatPath, query: short,
			images: map[string]inspectResult{spelled: own, stored: unlabeled}, allowUnowned: true,
			wantStatus: http.StatusCreated, wantInspects: []string{imageTagTestSource, spelled, stored},
		},
		{
			name: "podman: unlabeled image holds the localhost name and unowned images are refused", flavor: upstreamflavor.Podman, path: compatPath, query: short,
			images:     map[string]inspectResult{spelled: own, stored: unlabeled},
			wantStatus: http.StatusForbidden, wantReason: imageTagDenyTarget, wantInspects: []string{imageTagTestSource, spelled, stored},
		},
		{
			name: "podman: inspect of the localhost name fails", flavor: upstreamflavor.Podman, path: compatPath, query: short,
			images: map[string]inspectResult{spelled: own, stored: failing}, allowUnowned: true,
			wantStatus: http.StatusBadGateway, wantInspects: []string{imageTagTestSource, spelled, stored},
		},
		{
			name: "podman: default tag", flavor: upstreamflavor.Podman, path: compatPath, query: "?repo=team%2Fapp",
			wantStatus: http.StatusCreated, wantInspects: []string{imageTagTestSource, "team/app:latest", "localhost/team/app:latest"},
		},
		// A `repo` that names its registry is stored as written whatever the
		// option says, so there is one name to check.
		{
			name: "podman: registry-qualified repo", flavor: upstreamflavor.Podman, path: compatPath, query: "?repo=registry.example%2Fteam%2Fapp&tag=v2",
			images:     map[string]inspectResult{"localhost/registry.example/team/app:v2": foreign},
			wantStatus: http.StatusCreated, wantInspects: []string{imageTagTestSource, "registry.example/team/app:v2"},
		},
		{
			name: "podman: repo already under localhost", flavor: upstreamflavor.Podman, path: compatPath, query: "?repo=localhost%2Fnginx&tag=prod",
			images:     map[string]inspectResult{stored: foreign},
			wantStatus: http.StatusForbidden, wantReason: imageTagDenyTarget, wantInspects: []string{imageTagTestSource, stored},
		},
		{
			name: "podman: registry with a port", flavor: upstreamflavor.Podman, path: compatPath, query: "?repo=localhost%3A5000%2Fnginx&tag=prod",
			wantStatus: http.StatusCreated, wantInspects: []string{imageTagTestSource, "localhost:5000/nginx:prod"},
		},
		// Podman accepts neither of these under either setting: the name is
		// over the bound as localhost/<repo> and as docker.io/<repo>, and an
		// upper-case first component is a path component once it is completed.
		{
			name: "podman: short name that outgrows the bound under localhost", flavor: upstreamflavor.Podman, path: compatPath, query: "?repo=" + longShort,
			wantStatus: http.StatusForbidden, wantReason: imageTagDenyInvalidRepo,
		},
		{
			name: "podman: upper-case short first component", flavor: upstreamflavor.Podman, path: compatPath, query: "?repo=Team%2Fapp",
			wantStatus: http.StatusForbidden, wantReason: imageTagDenyInvalidRepo,
		},
		// The native route always stores under localhost/, so that is still
		// the only name it is checked under.
		{
			name: "podman: native route", flavor: upstreamflavor.Podman, path: libpodPath, query: short,
			images:     map[string]inspectResult{spelled: foreign},
			wantStatus: http.StatusCreated, wantInspects: []string{imageTagTestSource, stored},
		},

		// dockerd: unchanged. localhost/nginx:prod is an image on a registry
		// called localhost there, and not the reference the request names.
		{
			name: "docker: short repo", flavor: upstreamflavor.Docker, path: compatPath, query: short,
			images:     map[string]inspectResult{stored: foreign},
			wantStatus: http.StatusCreated, wantInspects: []string{imageTagTestSource, spelled},
		},
		{
			name: "docker: another owner holds the name", flavor: upstreamflavor.Docker, path: compatPath, query: short,
			images:     map[string]inspectResult{spelled: foreign},
			wantStatus: http.StatusForbidden, wantReason: imageTagDenyTarget, wantInspects: []string{imageTagTestSource, spelled},
		},
		{
			name: "docker: registry-qualified repo", flavor: upstreamflavor.Docker, path: compatPath, query: "?repo=registry.example%2Fteam%2Fapp&tag=v2",
			wantStatus: http.StatusCreated, wantInspects: []string{imageTagTestSource, "registry.example/team/app:v2"},
		},
		{
			name: "docker: short name over the bound Podman has", flavor: upstreamflavor.Docker, path: compatPath, query: "?repo=" + longShort,
			wantStatus: http.StatusCreated, wantInspects: []string{imageTagTestSource, longShort + ":latest"},
		},
		{
			name: "docker: upper-case first component is a domain", flavor: upstreamflavor.Docker, path: compatPath, query: "?repo=Team%2Fapp",
			wantStatus: http.StatusCreated, wantInspects: []string{imageTagTestSource, "Team/app:latest"},
		},
		// The zero Flavor is Docker everywhere in this package. See
		// Options.UpstreamFlavor.
		{
			name: "zero flavor is docker", path: compatPath, query: short,
			images:     map[string]inspectResult{stored: foreign},
			wantStatus: http.StatusCreated, wantInspects: []string{imageTagTestSource, spelled},
		},
		// Startup never hands the chain an unresolved flavor. If one arrived
		// anyway there would be no telling which engine reads the request, so
		// it gets the check that holds on both.
		{
			name: "unresolved flavor gets the podman check", flavor: upstreamflavor.Auto, path: compatPath, query: short,
			images:     map[string]inspectResult{spelled: own, stored: foreign},
			wantStatus: http.StatusForbidden, wantReason: imageTagDenyTarget, wantInspects: []string{imageTagTestSource, spelled, stored},
		},
		{
			name: "unrecognized flavor gets the podman check", flavor: "containerd", path: compatPath, query: short,
			images:     map[string]inspectResult{spelled: own, stored: foreign},
			wantStatus: http.StatusForbidden, wantReason: imageTagDenyTarget, wantInspects: []string{imageTagTestSource, spelled, stored},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inspector := imageTagInspector("", inspectResult{})
			for name, state := range tt.images {
				inspector.resources[string(dockerresource.KindImage)][name] = state
			}
			opts := Options{Owner: imageTagTestOwner, LabelKey: imageTagTestLabelKey, AllowUnownedImages: tt.allowUnowned, UpstreamFlavor: tt.flavor}
			rec, forwarded := serveImageTagRequest(t, inspector, opts, httptest.NewRequest(http.MethodPost, tt.path+tt.query, nil))

			if rec.Code != tt.wantStatus || forwarded != (tt.wantStatus == http.StatusCreated) {
				t.Fatalf("status = %d forwarded = %v, want %d; body: %s", rec.Code, forwarded, tt.wantStatus, rec.Body.String())
			}
			if tt.wantReason != "" && !strings.Contains(rec.Body.String(), tt.wantReason) {
				t.Fatalf("body should carry %q, got: %s", tt.wantReason, rec.Body.String())
			}
			if got := inspectedImages(inspector); !slices.Equal(got, tt.wantInspects) {
				t.Fatalf("inspected images = %v, want %v", got, tt.wantInspects)
			}
		})
	}
}

// TestCompatImageTagOnPodmanFollowsRolloutModes: the second name is an owner
// verdict like the first, so warn and audit record it and forward.
func TestCompatImageTagOnPodmanFollowsRolloutModes(t *testing.T) {
	t.Parallel()
	own := inspectResult{labels: map[string]string{imageTagTestLabelKey: imageTagTestOwner}, found: true}
	foreign := inspectResult{labels: map[string]string{imageTagTestLabelKey: "someone-else"}, found: true}

	for _, mode := range []string{"warn", "audit"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			inspector := imageTagInspector("localhost/nginx:prod", foreign)
			inspector.resources[string(dockerresource.KindImage)]["nginx:prod"] = own
			meta := &logging.RequestMeta{RolloutMode: mode}
			req := httptest.NewRequest(http.MethodPost, "/v1.45/images/"+imageTagTestSource+"/tag?repo=nginx&tag=prod", nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			opts := Options{Owner: imageTagTestOwner, LabelKey: imageTagTestLabelKey, UpstreamFlavor: upstreamflavor.Podman}
			rec, forwarded := serveImageTagRequest(t, inspector, opts, req)

			if !forwarded || rec.Code != http.StatusCreated {
				t.Fatalf("forwarded = %v status = %d, want true and %d", forwarded, rec.Code, http.StatusCreated)
			}
			if meta.Decision != logging.DecisionWouldDeny || meta.ReasonCode != reasonCodeOwnerPolicyDeniedAccess || meta.Reason != imageTagDenyTarget {
				t.Fatalf("meta = decision %q code %q reason %q, want %q, %q and %q", meta.Decision, meta.ReasonCode, meta.Reason, logging.DecisionWouldDeny, reasonCodeOwnerPolicyDeniedAccess, imageTagDenyTarget)
			}
		})
	}
}

// TestImageTagRefusesTheCompatPathPodmanReadsAsNative covers the one
// Docker-compatible path Podman does not read as a compat request. Podman
// tells the two APIs apart by the third "/"-separated piece of the request URL
// (IsLibpodRequest, read at v5.8.6), not by the route it matched. On an
// unversioned POST /images/libpod/tag that piece is the image name, so Podman
// stores a `repo` that names no registry under localhost/ without looking
// anything up, while this layer inspects the name as the client spelled it and
// Podman answers that inspect through short-name resolution. The two can name
// different images, so the path is refused. The versioned spelling every
// Docker client sends has "images" in that position and is left alone.
func TestImageTagRefusesTheCompatPathPodmanReadsAsNative(t *testing.T) {
	t.Parallel()
	const query = "?repo=nginx&tag=prod"
	own := inspectResult{labels: map[string]string{imageTagTestLabelKey: imageTagTestOwner}, found: true}

	tests := []struct {
		name string
		path string
		// wantInspects is empty for a refused path: the refusal comes before
		// any inspect.
		wantInspects []string
	}{
		{name: "unversioned path to an image named libpod", path: "/images/libpod/tag"},
		{name: "unversioned path to an image under libpod/", path: "/images/libpod/app/tag"},
		{name: "unversioned path to a tagged image under libpod/", path: "/images/libpod/app:1/tag"},

		{name: "versioned path to an image named libpod", path: "/v1.45/images/libpod/tag", wantInspects: []string{"libpod", "nginx:prod"}},
		{name: "versioned path to an image under libpod/", path: "/v1.45/images/libpod/app/tag", wantInspects: []string{"libpod/app", "nginx:prod"}},
		// Podman compares the piece as it arrived, and the proxy forwards the
		// path unchanged, so an escape keeps the request a compat one.
		{name: "escaped letter in the segment", path: "/images/%6Cibpod/tag", wantInspects: []string{"libpod", "nginx:prod"}},
		{name: "escaped slash keeps the name in one segment", path: "/images/libpod%2Fapp/tag", wantInspects: []string{"libpod/app", "nginx:prod"}},
		{name: "tag in the first segment", path: "/images/libpod:1/tag", wantInspects: []string{"libpod:1", "nginx:prod"}},
		{name: "longer first segment", path: "/images/libpods/app/tag", wantInspects: []string{"libpods/app", "nginx:prod"}},
		{name: "libpod further into the name", path: "/images/team/libpod/tag", wantInspects: []string{"team/libpod", "nginx:prod"}},
		// The native route is the one both sides read the same way, and its
		// target is checked under the name Podman stores.
		{name: "native route to an image named libpod", path: "/v5.0.0/libpod/images/libpod/tag", wantInspects: []string{"libpod", "localhost/nginx:prod"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Every image the caller could name here is its own, including
			// the one the short target resolves to, so the only thing that
			// can refuse a request is the shape of its path.
			inspector := imageTagInspector("nginx:prod", own)
			for _, source := range []string{"libpod", "libpod/app", "libpod/app:1", "libpod:1", "libpods/app", "team/libpod"} {
				inspector.resources[string(dockerresource.KindImage)][source] = own
			}
			rec, forwarded := serveImageTagRequest(t, inspector, Options{Owner: imageTagTestOwner, LabelKey: imageTagTestLabelKey}, httptest.NewRequest(http.MethodPost, tt.path+query, nil))

			if len(tt.wantInspects) > 0 {
				if !forwarded || rec.Code != http.StatusCreated {
					t.Fatalf("forwarded = %v status = %d, want true and %d; body: %s", forwarded, rec.Code, http.StatusCreated, rec.Body.String())
				}
				if got := inspectedImages(inspector); !slices.Equal(got, tt.wantInspects) {
					t.Fatalf("inspected images = %v, want %v", got, tt.wantInspects)
				}
				return
			}
			if forwarded {
				t.Fatal("retag reached the upstream")
			}
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), imageTagDenyLibpodSegment) {
				t.Fatalf("status = %d, body = %s; want %d carrying %q", rec.Code, rec.Body.String(), http.StatusForbidden, imageTagDenyLibpodSegment)
			}
			if len(inspector.calls) != 0 {
				t.Fatalf("inspect calls = %#v, want none for a refused path", inspector.calls)
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
