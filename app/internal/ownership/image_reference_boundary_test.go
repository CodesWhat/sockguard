package ownership

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRetagImageAcceptsOnlySuccessfulStatus(t *testing.T) {
	t.Parallel()
	for _, native := range []bool{false, true} {
		for _, status := range []int{199, http.StatusOK, 299, http.StatusMultipleChoices} {
			t.Run(fmt.Sprintf("native=%v/status=%d", native, status), func(t *testing.T) {
				inspector := upstreamInspector{client: &http.Client{Transport: buildImageTransport(func(req *http.Request) (*http.Response, error) {
					prefix := "/images/"
					if native {
						prefix = "/libpod/images/"
					}
					if req.Method != http.MethodPost || req.URL.Path != prefix+"image-id/tag" || req.URL.Query().Get("repo") != "team/app" || req.URL.Query().Get("tag") != "v2" {
						t.Errorf("retag request=%s %s", req.Method, req.URL)
					}
					return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(""))}, nil
				})}}
				err := inspector.retagImage(t.Context(), "sha256:image-id", "team/app:v2", native)
				if wantError := status < http.StatusOK || status >= http.StatusMultipleChoices; (err != nil) != wantError {
					t.Fatalf("status %d returned error=%v, want error=%v", status, err, wantError)
				}
			})
		}
	}
}

func TestSplitImageNameTagBoundaries(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name, reference, repo, tag string
		ok                         bool
	}{
		{name: "empty", reference: ""},
		{name: "short untagged", reference: "app"},
		{name: "qualified untagged", reference: "registry.example/team/app"},
		{name: "registry port without tag", reference: "localhost:5000/app"},
		{name: "short tagged", reference: "app:v1", repo: "app", tag: "v1", ok: true},
		{name: "registry port with tag", reference: "localhost:5000/app:v1", repo: "localhost:5000/app", tag: "v1", ok: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo, tag, ok := splitNameTag(tt.reference)
			if repo != tt.repo || tag != tt.tag || ok != tt.ok {
				t.Fatalf("splitNameTag(%q)=(%q,%q,%v), want (%q,%q,%v)", tt.reference, repo, tag, ok, tt.repo, tt.tag, tt.ok)
			}
		})
	}
}

func TestRetagImageRejectsUntaggedReferenceBeforeUpstream(t *testing.T) {
	t.Parallel()
	for _, native := range []bool{false, true} {
		for _, reference := range []string{"", "app", "registry.example/team/app", "localhost:5000/app"} {
			inspector := upstreamInspector{client: &http.Client{Transport: buildImageTransport(func(*http.Request) (*http.Response, error) {
				t.Errorf("untagged reference %q reached upstream", reference)
				return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(""))}, nil
			})}}
			if err := inspector.retagImage(t.Context(), "sha256:image-id", reference, native); err == nil || !strings.Contains(err.Error(), "carries no tag") {
				t.Fatalf("retag(%q,native=%v) error=%v, want missing-tag refusal", reference, native, err)
			}
		}
	}
}
