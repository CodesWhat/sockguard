package ownership

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

func TestContainerImageMountSourcesAreCollected(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"HostConfig":{"Mounts":[{"Type":"image","Source":"theirs/app:latest","Target":"/x"},{"Type":"image","Source":"theirs/app:latest"},{"Type":"volume","Source":"vol"}]}}`,
		`{"hostconfig":{"mounts":[{"TYPE":"IMAGE","source":"theirs/app:latest"},{"type":"volume","source":"vol"}]}}`,
	} {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatal(err)
		}
		got, overflow, hasImage := collectContainerCreateEmbeddedReferencesWithImageMounts(decoded)
		if overflow || !hasImage {
			t.Fatalf("overflow = %v hasImage = %v", overflow, hasImage)
		}
		want := []embeddedOwnershipReference{
			{dockerresource.KindImage, "theirs/app:latest", "container HostConfig.Mounts image source"},
			{dockerresource.KindVolume, "vol", "container HostConfig.Mounts"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("refs = %#v, want %#v", got, want)
		}
	}
}

func TestMiddlewareChecksContainerImageMounts(t *testing.T) {
	t.Parallel()
	const body = `{"Image":"mine/app","HostConfig":{"Mounts":[{"Type":"image","Source":"%s","Target":"/mnt"}]}}`
	images := func(source string, result inspectResult) map[string]map[string]inspectResult {
		return map[string]map[string]inspectResult{
			"images": {"mine/app": ownerLabel("job-123"), source: result},
		}
	}
	tests := []struct {
		name      string
		flavor    upstreamflavor.Flavor
		source    string
		resources map[string]map[string]inspectResult
		wantCode  int
		forwarded bool
	}{
		{name: "foreign tag", flavor: upstreamflavor.Docker, source: "theirs/app:latest", resources: images("theirs/app:latest", ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "foreign id", flavor: upstreamflavor.Docker, source: "sha256:abc", resources: images("sha256:abc", ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "unlabeled", flavor: upstreamflavor.Docker, source: "shared", resources: images("shared", inspectResult{labels: map[string]string{}, found: true}), wantCode: http.StatusForbidden},
		{name: "missing", flavor: upstreamflavor.Docker, source: "ghost", resources: map[string]map[string]inspectResult{"images": {"mine/app": ownerLabel("job-123")}}, wantCode: http.StatusNotFound},
		{name: "lookup failure", flavor: upstreamflavor.Docker, source: "broken", resources: images("broken", inspectResult{err: errors.New("boom")}), wantCode: http.StatusBadGateway},
		{name: "same owner", flavor: upstreamflavor.Docker, source: "mine/data", resources: images("mine/data", ownerLabel("job-123")), wantCode: http.StatusOK, forwarded: true},
		{name: "podman refuses", flavor: upstreamflavor.Podman, source: "mine/data", resources: images("mine/data", ownerLabel("job-123")), wantCode: http.StatusForbidden},
		{name: "unresolved flavor refuses", flavor: "", source: "mine/data", resources: images("mine/data", ownerLabel("job-123")), wantCode: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, forwarded, _ := embeddedTestRun(t, Options{UpstreamFlavor: tt.flavor}, tt.resources, http.MethodPost, "/containers/create", fmt.Sprintf(body, tt.source))
			if code != tt.wantCode || forwarded != tt.forwarded {
				t.Fatalf("status = %d forwarded = %v, want %d / %v", code, forwarded, tt.wantCode, tt.forwarded)
			}
		})
	}
}
