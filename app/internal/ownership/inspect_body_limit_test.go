package ownership

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// This test runs serially because the response buffer setting is process-wide.
func TestOwnershipInspectBodyLimit(t *testing.T) {
	const limit = 512
	filter.SetResponseBodyLimit(limit)
	t.Cleanup(func() { filter.SetResponseBodyLimit(0) })

	imageID := strings.Repeat("a", 64)
	for _, tt := range []struct {
		name       string
		kind       dockerresource.Kind
		id         string
		context    func(context.Context) context.Context
		body       string
		status     int
		wantFound  bool
		ignoreBody bool
	}{
		{name: "labels", kind: dockerresource.KindContainer, id: "web", body: `{"Config":{"Labels":{"team":"a"}}}`, status: http.StatusOK, wantFound: true},
		{name: "libpod network", kind: dockerresource.KindLibpodNetwork, id: "web", body: `[{"labels":{"team":"a"}}]`, status: http.StatusOK, wantFound: true},
		{name: "exact secret", kind: dockerresource.KindSecret, id: "web", context: withExactSecretLookup, body: `{"ID":"web","Spec":{"Labels":{"team":"a"}}}`, status: http.StatusOK, wantFound: true},
		{name: "canonical network", kind: dockerresource.KindNetwork, id: "web", context: withNetworkDeleteName, body: `{"Name":"web","Labels":{"team":"a"}}`, status: http.StatusOK, wantFound: true},
		{name: "exact volume image", kind: dockerresource.KindImage, id: imageID, context: withImageVolumeID, body: `{"Id":"` + imageID + `","Config":{"Labels":{"team":"a"}}}`, status: http.StatusOK, wantFound: true},
		{name: "exact secret lookup reports ambiguity", kind: dockerresource.KindSecret, id: "web", context: withExactSecretLookup, body: `{"message":"more than one result secret with prefix web"}`, status: http.StatusInternalServerError},
		{name: "exec", id: "exec", body: `{"ContainerID":"web"}`, status: http.StatusOK, wantFound: true},
		{name: "not found", kind: dockerresource.KindContainer, id: "gone", body: `{"message":"container not found"}`, status: http.StatusNotFound, ignoreBody: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.context != nil {
				ctx = tt.context(ctx)
			}
			for _, size := range []int{limit, limit + 2} {
				body := &inspectLimitBody{Reader: strings.NewReader(tt.body + strings.Repeat(" ", size-len(tt.body)))}
				inspector := upstreamInspector{client: &http.Client{Transport: buildImageTransport(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: tt.status, Body: body, ContentLength: -1}, nil
				})}}

				var found bool
				var err error
				if tt.kind == "" {
					_, found, err = inspector.inspectExec(ctx, tt.id)
				} else {
					_, found, err = inspector.inspectResource(ctx, tt.kind, tt.id)
				}
				oversized := size > limit && !tt.ignoreBody
				if found != (tt.wantFound && !oversized) || (err != nil) != oversized {
					t.Errorf("size %d: found=%v err=%v, want found=%v error=%v", size, found, err, tt.wantFound && !oversized, oversized)
				}
				wantRead := min(size, limit+1)
				if tt.ignoreBody {
					wantRead = 0
				}
				if n := size - body.Len(); n != wantRead || !body.closed {
					t.Errorf("size %d: read %d bytes and closed=%v, want %d bytes and close", size, n, body.closed, wantRead)
				}
			}
		})
	}
}

type inspectLimitBody struct {
	*strings.Reader
	closed bool
}

func (b *inspectLimitBody) Close() error {
	b.closed = true
	return nil
}
