package ownership

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

// TestImageLoadDestinations pins the references a load's archive names build,
// on each route and engine, and every record that is refused instead.
func TestImageLoadDestinations(t *testing.T) {
	t.Parallel()
	tooMany := make([]string, 0, imageLoadMaxNames+1)
	for i := range imageLoadMaxNames + 1 {
		tooMany = append(tooMany, fmt.Sprintf("team/app:v%d", i))
	}

	tests := []struct {
		name       string
		record     *logging.ImageLoadRecord
		path       string
		flavor     upstreamflavor.Flavor
		want       []imageDestination
		wantReason string
	}{
		{name: "archive that names nothing", record: &logging.ImageLoadRecord{}, path: imageLoadPath},
		{name: "unnamed entries name nothing", record: &logging.ImageLoadRecord{References: []string{"", imageLoadUntaggedName}}, path: imageLoadPath},
		{name: "repo tag", record: &logging.ImageLoadRecord{References: []string{"team/app:v1"}}, path: imageLoadPath, want: []imageDestination{{target: "team/app:v1"}}},
		{
			name: "both spellings a containerd-store save writes", record: &logging.ImageLoadRecord{References: []string{"app:v1", "docker.io/library/app:v1"}}, path: imageLoadPath,
			want: []imageDestination{{target: "app:v1"}, {target: "docker.io/library/app:v1"}},
		},
		{name: "a repeated name is checked once", record: &logging.ImageLoadRecord{References: []string{"team/app:v1", "team/app:v1"}}, path: imageLoadPath, want: []imageDestination{{target: "team/app:v1"}}},
		{name: "name with no tag", record: &logging.ImageLoadRecord{References: []string{"team/app"}}, path: imageLoadPath, want: []imageDestination{{target: "team/app:latest"}}},
		{name: "name saved by digest writes no tag", record: &logging.ImageLoadRecord{References: []string{"docker.io/library/app@" + testDigestSHA256}}, path: imageLoadPath},
		{
			name: "podman compat short name is checked under both names", record: &logging.ImageLoadRecord{References: []string{"team/app:v1"}}, path: imageLoadPath, flavor: upstreamflavor.Podman,
			want: []imageDestination{{target: "team/app:v1", storedTarget: "localhost/team/app:v1"}},
		},
		{name: "native route checks the stored name", record: &logging.ImageLoadRecord{References: []string{"team/app:v1"}}, path: libpodImageLoadPath, want: []imageDestination{{target: "localhost/team/app:v1"}}},
		{name: "native route keeps a name with a registry", record: &logging.ImageLoadRecord{References: []string{"quay.io/team/app:v1"}}, path: libpodImageLoadPath, want: []imageDestination{{target: "quay.io/team/app:v1"}}},

		{name: "archive nobody inspected", path: imageLoadPath, wantReason: imageLoadDenyUninspected},
		{name: "archive in neither format", record: &logging.ImageLoadRecord{Unreadable: true}, path: imageLoadPath, wantReason: imageLoadDenyUnreadable},
		{name: "too many names", record: &logging.ImageLoadRecord{References: tooMany}, path: imageLoadPath, wantReason: imageLoadDenyTooManyNames},
		{name: "name outside the grammar", record: &logging.ImageLoadRecord{References: []string{"Team/App:v1"}}, path: imageLoadPath, wantReason: "owner policy denied image load with a name outside the image reference grammar"},
		{name: "name with surrounding space", record: &logging.ImageLoadRecord{References: []string{" team/app:v1"}}, path: imageLoadPath, wantReason: "owner policy denied image load with a name outside the image reference grammar"},
		{name: "tag outside the grammar", record: &logging.ImageLoadRecord{References: []string{"team/app:-v1"}}, path: imageLoadPath, wantReason: "owner policy denied image load with a tag outside the image reference grammar"},
		{name: "tag and digest", record: &logging.ImageLoadRecord{References: []string{"team/app:v1@" + testDigestSHA256}}, path: imageLoadPath, wantReason: "owner policy denied image load that names both a tag and a digest"},
		{name: "digest outside the grammar", record: &logging.ImageLoadRecord{References: []string{"team/app@sha256:abc"}}, path: imageLoadPath, wantReason: "owner policy denied image load with a digest outside the digest grammar"},
		{name: "digest algorithm name", record: &logging.ImageLoadRecord{References: []string{"sha256:v1"}}, path: imageLoadPath, wantReason: "owner policy denied image load whose name is a digest algorithm name: the engines read such a reference as an image ID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			refs, reason := imageLoadDestinations(tt.record, tt.path, tt.flavor)
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

// TestImageLoadAuthorizesTheNamesItAssigns sends loads through the middleware
// with the record the filter leaves for it, and asserts on what reached the
// daemon.
func TestImageLoadAuthorizesTheNamesItAssigns(t *testing.T) {
	t.Parallel()
	const heldByAnotherOwner = "owner policy denied image load onto a reference that already names an image outside this owner"

	tests := []struct {
		name         string
		path         string
		record       *logging.ImageLoadRecord
		allowUnowned bool
		wantStatus   int
		wantReason   string
	}{
		{name: "name another owner's image holds", path: "/images/load", record: &logging.ImageLoadRecord{References: []string{"theirs/app:v1"}}, wantStatus: http.StatusForbidden, wantReason: heldByAnotherOwner},
		{name: "second name another owner's image holds", path: "/v1.45/images/load", record: &logging.ImageLoadRecord{References: []string{"mine/app:latest", "theirs/app:v1"}}, wantStatus: http.StatusForbidden, wantReason: heldByAnotherOwner},
		{name: "name an unlabeled image holds", path: "/images/load", record: &logging.ImageLoadRecord{References: []string{"shared/base:latest"}}, wantStatus: http.StatusForbidden, wantReason: heldByAnotherOwner},
		{name: "name an unlabeled image holds with unowned images allowed", path: "/images/load", record: &logging.ImageLoadRecord{References: []string{"shared/base:latest"}}, allowUnowned: true, wantStatus: http.StatusOK},
		{name: "name the caller's image holds", path: "/images/load", record: &logging.ImageLoadRecord{References: []string{"mine/app:latest"}}, wantStatus: http.StatusOK},
		{name: "name nothing holds", path: "/images/load", record: &logging.ImageLoadRecord{References: []string{"mine/new:v2"}}, wantStatus: http.StatusOK},
		{name: "no names", path: "/images/load", record: &logging.ImageLoadRecord{}, wantStatus: http.StatusOK},
		{name: "archive nobody inspected", path: "/images/load", wantStatus: http.StatusForbidden, wantReason: imageLoadDenyUninspected},
		{name: "native name another owner's image holds", path: "/v5.0.0/libpod/images/load", record: &logging.ImageLoadRecord{References: []string{"theirs/app:v1"}}, wantStatus: http.StatusForbidden, wantReason: "libpod " + heldByAnotherOwner},
		{name: "native archive nobody inspected", path: "/v5.0.0/libpod/images/load", wantStatus: http.StatusForbidden, wantReason: "libpod " + imageLoadDenyUninspected},
		{name: "host path load is left to the blind-write acknowledgment", path: "/v5.0.0/libpod/local/images/load", wantStatus: http.StatusOK},
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

			meta := &logging.RequestMeta{RolloutMode: "enforce", ImageLoad: tt.record}
			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader("archive"))
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
