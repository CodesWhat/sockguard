package ownership

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

const (
	testDigestSHA256 = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testDigestQuery  = "sha256%3A0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// TestImagePullDestination pins the local name a pull's parameters build, on
// each route and engine, and every shape that is refused instead.
func TestImagePullDestination(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		path       string
		query      string
		flavor     upstreamflavor.Flavor
		want       []imageDestination
		wantReason string
	}{
		{name: "fromImage and tag", path: imageCreatePath, query: "fromImage=team%2Fapp&tag=v1", want: []imageDestination{{target: "team/app:v1"}}},
		{name: "tag carried in fromImage", path: imageCreatePath, query: "fromImage=team%2Fapp%3Av1", want: []imageDestination{{target: "team/app:v1"}}},
		{name: "registry with a port", path: imageCreatePath, query: "fromImage=registry.example%3A5000%2Fteam%2Fapp&tag=v1", want: []imageDestination{{target: "registry.example:5000/team/app:v1"}}},
		{name: "what the Docker SDK sends", path: imageCreatePath, query: "fromImage=docker.io%2Flibrary%2Falpine&tag=latest", want: []imageDestination{{target: "docker.io/library/alpine:latest"}}},
		{name: "repo is not a pull parameter", path: imageCreatePath, query: "fromImage=team%2Fapp&tag=v1&repo=theirs%2Fapp", want: []imageDestination{{target: "team/app:v1"}}},
		{name: "platform on dockerd", path: imageCreatePath, query: "fromImage=team%2Fapp&tag=v1&platform=linux%2Farm64", want: []imageDestination{{target: "team/app:v1"}}},
		{
			name: "podman compat short name is checked under both names", path: imageCreatePath, query: "fromImage=team%2Fapp&tag=v1", flavor: upstreamflavor.Podman,
			want: []imageDestination{{target: "team/app:v1", storedTarget: "localhost/team/app:v1"}},
		},
		{
			name: "podman compat platform with the registry spelled", path: imageCreatePath, query: "fromImage=quay.io%2Fteam%2Fapp&tag=v1&platform=linux%2Farm64", flavor: upstreamflavor.Podman,
			want: []imageDestination{{target: "quay.io/team/app:v1"}},
		},
		{name: "pull by digest in tag", path: imageCreatePath, query: "fromImage=team%2Fapp&tag=" + testDigestQuery},
		{name: "pull by digest in fromImage", path: imageCreatePath, query: "fromImage=team%2Fapp%40" + testDigestQuery},
		// A tag beside the digest is dropped by both engines, which pull by
		// the digest and write no tag. Confirmed against dockerd 28.5.1 on
		// both image stores. The first shape is the reference passed through
		// whole, and the second is how docker-py and dockerode split it.
		{name: "pull by tag and digest in fromImage", path: imageCreatePath, query: "fromImage=team%2Fapp%3Av1%40" + testDigestQuery},
		{name: "pull by a tag in fromImage and a digest in tag", path: imageCreatePath, query: "fromImage=team%2Fapp%3Av1&tag=" + testDigestQuery},
		{name: "pull by tag and digest on podman", path: imageCreatePath, query: "fromImage=team%2Fapp%3Av1%40" + testDigestQuery, flavor: upstreamflavor.Podman},
		{name: "pull by tag and digest of a short name for a platform on podman", path: imageCreatePath, query: "fromImage=team%2Fapp%3Av1%40" + testDigestQuery + "&platform=linux%2Farm64", flavor: upstreamflavor.Podman},
		{name: "pull by digest of a short name for a platform on podman", path: imageCreatePath, query: "fromImage=team%2Fapp%40" + testDigestQuery + "&platform=linux%2Farm64", flavor: upstreamflavor.Podman},

		{name: "no tag", path: imageCreatePath, query: "fromImage=team%2Fapp", wantReason: imagePullDenyNoTag},
		{name: "no tag on podman", path: imageCreatePath, query: "fromImage=team%2Fapp", flavor: upstreamflavor.Podman, wantReason: imagePullDenyNoTag},
		{name: "empty tag", path: imageCreatePath, query: "fromImage=team%2Fapp&tag=", wantReason: imagePullDenyNoTag},
		{name: "trailing colon", path: imageCreatePath, query: "fromImage=team%2Fapp%3A", wantReason: "owner policy denied image pull with a tag outside the image reference grammar"},
		{name: "tag in fromImage beside a tag parameter", path: imageCreatePath, query: "fromImage=team%2Fapp%3Av1&tag=v2", wantReason: "owner policy denied image pull whose fromImage already carries a tag beside a tag parameter"},
		{name: "digest in fromImage beside a tag parameter", path: imageCreatePath, query: "fromImage=team%2Fapp%40" + testDigestQuery + "&tag=v1", wantReason: "owner policy denied image pull that names both a tag and a digest"},
		{name: "tag outside the grammar beside a digest in fromImage", path: imageCreatePath, query: "fromImage=team%2Fapp%3A-v1%40" + testDigestQuery, wantReason: "owner policy denied image pull with a tag outside the image reference grammar"},
		{name: "tag and a digest of the wrong length in fromImage", path: imageCreatePath, query: "fromImage=team%2Fapp%3Av1%40sha256%3Aabc", wantReason: "owner policy denied image pull with a digest outside the digest grammar"},
		{name: "name outside the grammar pulled by tag and digest", path: imageCreatePath, query: "fromImage=Team%2FApp%3Av1%40" + testDigestQuery, wantReason: "owner policy denied image pull with a fromImage outside the image reference grammar"},
		{name: "tag and digest in fromImage beside a tag parameter", path: imageCreatePath, query: "fromImage=team%2Fapp%3Av1%40" + testDigestQuery + "&tag=v2", wantReason: "owner policy denied image pull that names both a tag and a digest"},
		{name: "digest of the wrong length", path: imageCreatePath, query: "fromImage=team%2Fapp%40sha256%3Aabc", wantReason: "owner policy denied image pull with a digest outside the digest grammar"},
		{name: "digest in upper case", path: imageCreatePath, query: "fromImage=team%2Fapp%40sha256%3A" + strings.Repeat("A", 64), wantReason: "owner policy denied image pull with a digest outside the digest grammar"},
		{name: "digest of an unknown algorithm as the tag", path: imageCreatePath, query: "fromImage=team%2Fapp&tag=md5%3Aabc", wantReason: "owner policy denied image pull with a tag outside the image reference grammar"},
		{name: "name outside the grammar", path: imageCreatePath, query: "fromImage=Team%2FApp&tag=v1", wantReason: "owner policy denied image pull with a fromImage outside the image reference grammar"},
		{name: "name outside the grammar pulled by digest", path: imageCreatePath, query: "fromImage=Team%2FApp%40" + testDigestQuery, wantReason: "owner policy denied image pull with a fromImage outside the image reference grammar"},
		{name: "digest algorithm name", path: imageCreatePath, query: "fromImage=sha256&tag=v1", wantReason: "owner policy denied image pull whose fromImage is a digest algorithm name: the engines read such a reference as an image ID"},
		{name: "repeated fromImage", path: imageCreatePath, query: "fromImage=mine&fromImage=theirs&tag=v1", wantReason: imageCreateDenyAmbiguous},
		{name: "repeated tag", path: imageCreatePath, query: "fromImage=mine&tag=v1&tag=v2", wantReason: imageCreateDenyAmbiguous},
		{name: "case variant of tag", path: imageCreatePath, query: "fromImage=mine&Tag=v1", wantReason: imageCreateDenyAmbiguous},
		{name: "podman compat short name for a named platform", path: imageCreatePath, query: "fromImage=team%2Fapp&tag=v1&platform=linux%2Farm64", flavor: upstreamflavor.Podman, wantReason: imagePullDenyPlatform},
		{name: "podman compat short name for a platform under another spelling", path: imageCreatePath, query: "fromImage=team%2Fapp&tag=v1&Platform=linux%2Farm64", flavor: upstreamflavor.Podman, wantReason: imagePullDenyPlatform},

		{name: "native pull", path: libpodImagePullPath, query: "reference=quay.io%2Fteam%2Fapp%3Av1", want: []imageDestination{{target: "quay.io/team/app:v1"}}},
		{name: "native pull of a short name", path: libpodImagePullPath, query: "reference=team%2Fapp%3Av1", want: []imageDestination{{target: "team/app:v1", storedTarget: "localhost/team/app:v1"}}},
		{name: "native pull behind the docker transport", path: libpodImagePullPath, query: "reference=docker%3A%2F%2Fquay.io%2Fteam%2Fapp%3Av1", want: []imageDestination{{target: "quay.io/team/app:v1"}}},
		{name: "native pull with allTags off", path: libpodImagePullPath, query: "reference=quay.io%2Fteam%2Fapp%3Av1&allTags=false", want: []imageDestination{{target: "quay.io/team/app:v1"}}},
		{name: "native pull by digest", path: libpodImagePullPath, query: "reference=quay.io%2Fteam%2Fapp%40" + testDigestQuery},
		{name: "native pull by tag and digest", path: libpodImagePullPath, query: "reference=quay.io%2Fteam%2Fapp%3Av1%40" + testDigestQuery},
		{name: "native pull with no reference", path: libpodImagePullPath, query: "policy=always"},
		{name: "native pull of a bare name", path: libpodImagePullPath, query: "reference=quay.io%2Fteam%2Fapp", wantReason: imagePullDenyNoTag},
		{name: "native pull of every tag", path: libpodImagePullPath, query: "reference=quay.io%2Fteam%2Fapp%3Av1&allTags=true", wantReason: imagePullDenyAllTags},
		{name: "native pull of every tag under another spelling", path: libpodImagePullPath, query: "reference=quay.io%2Fteam%2Fapp%3Av1&alltags=1", wantReason: imagePullDenyAllTags},
		{name: "native pull with an allTags that does not parse", path: libpodImagePullPath, query: "reference=quay.io%2Fteam%2Fapp%3Av1&allTags=yes", wantReason: imagePullDenyAllTags},
		{name: "native pull repeated reference", path: libpodImagePullPath, query: "reference=mine%3A1&reference=theirs%3A1", wantReason: libpodImagePullDenyAmbiguousRef},
		{name: "native pull case variant of reference", path: libpodImagePullPath, query: "Reference=theirs%3A1", wantReason: libpodImagePullDenyAmbiguousRef},
		{name: "native pull semicolon separator", path: libpodImagePullPath, query: "reference=mine%3A1;reference=theirs%3A1", wantReason: libpodImagePullDenyAmbiguousRef},
		{name: "native pull of another transport", path: libpodImagePullPath, query: "reference=oci-archive%3A%2Ftmp%2Fimage.tar%3Av1", wantReason: "owner policy denied image pull with a reference outside the image reference grammar"},
		{name: "native pull of a short name for a named architecture", path: libpodImagePullPath, query: "reference=team%2Fapp%3Av1&Arch=arm64", wantReason: imagePullDenyPlatform},
		{name: "native pull of a short name for a named os under another spelling", path: libpodImagePullPath, query: "reference=team%2Fapp%3Av1&os=linux", wantReason: imagePullDenyPlatform},
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

// TestIsImageDigest pins the digests a pull treats as one. Anything else in a
// tag parameter is a tag, and has to match the tag grammar.
func TestIsImageDigest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value string
		want  bool
	}{
		{testDigestSHA256, true},
		{"sha384:" + strings.Repeat("a", 96), true},
		{"sha512:" + strings.Repeat("0", 128), true},
		{"sha256:" + strings.Repeat("a", 63), false},
		{"sha256:" + strings.Repeat("a", 65), false},
		{"sha256:" + strings.Repeat("A", 64), false},
		{"sha256:" + strings.Repeat("g", 64), false},
		{"sha1:" + strings.Repeat("a", 40), false},
		{"sha256", false},
		{"latest", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isImageDigest(tt.value); got != tt.want {
			t.Errorf("isImageDigest(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

// TestImagePullAuthorizesTheNameItOverwrites sends pulls through the
// middleware on both routes and asserts on what reached the daemon.
func TestImagePullAuthorizesTheNameItOverwrites(t *testing.T) {
	t.Parallel()
	const heldByAnotherOwner = "owner policy denied image pull onto a reference that already names an image outside this owner"

	tests := []struct {
		name         string
		target       string
		allowUnowned bool
		wantStatus   int
		wantReason   string
	}{
		{name: "name another owner's image holds", target: "/images/create?fromImage=theirs%2Fapp&tag=v1", wantStatus: http.StatusForbidden, wantReason: heldByAnotherOwner},
		{name: "name an unlabeled image holds", target: "/v1.45/images/create?fromImage=shared%2Fbase&tag=latest", wantStatus: http.StatusForbidden, wantReason: heldByAnotherOwner},
		{name: "name an unlabeled image holds with unowned images allowed", target: "/images/create?fromImage=shared%2Fbase&tag=latest", allowUnowned: true, wantStatus: http.StatusOK},
		{name: "name the caller's image holds", target: "/images/create?fromImage=mine%2Fapp&tag=latest", wantStatus: http.StatusOK},
		{name: "name nothing holds", target: "/images/create?fromImage=fresh%2Fapp&tag=1", wantStatus: http.StatusOK},
		{name: "another owner's name by digest", target: "/images/create?fromImage=theirs%2Fapp%40" + testDigestQuery, wantStatus: http.StatusOK},
		{name: "another owner's name by tag and digest", target: "/images/create?fromImage=theirs%2Fapp%3Av1%40" + testDigestQuery, wantStatus: http.StatusOK},
		{name: "every tag of a repository", target: "/images/create?fromImage=theirs%2Fapp", wantStatus: http.StatusForbidden, wantReason: imagePullDenyNoTag},
		{name: "native name another owner's image holds", target: "/v5.0.0/libpod/images/pull?reference=theirs%2Fapp%3Av1", wantStatus: http.StatusForbidden, wantReason: "libpod " + heldByAnotherOwner},
		{name: "native name only the stored spelling of which is held", target: "/v5.0.0/libpod/images/pull?reference=theirs%2Ftool%3Av1", wantStatus: http.StatusForbidden, wantReason: "libpod " + heldByAnotherOwner},
		{name: "native name nothing holds", target: "/v5.0.0/libpod/images/pull?reference=fresh%2Fapp%3A1", wantStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			theirs := inspectResult{labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true}
			fi := fakeInspector{resources: map[string]map[string]inspectResult{
				"images": {
					"theirs/app:v1":            theirs,
					"localhost/theirs/tool:v1": theirs,
					"mine/app:latest":          {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
					"shared/base:latest":       {found: true},
				},
			}}
			forwarded := false
			handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: tt.allowUnowned}, fi.inspectResource, fi.inspectExec)(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					forwarded = true
					w.WriteHeader(http.StatusOK)
				}))

			meta := &logging.RequestMeta{RolloutMode: "enforce"}
			req := httptest.NewRequest(http.MethodPost, tt.target, nil)
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
