package visibility

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// This test runs serially because the response buffer setting is process-wide.
func TestVisibilityInspectBodyLimit(t *testing.T) {
	const limit = 512
	filter.SetResponseBodyLimit(limit)
	t.Cleanup(func() { filter.SetResponseBodyLimit(0) })

	const container = `{"Name":"/web","Config":{"Labels":{"team":"a"}}}`
	ctx := context.Background()
	for _, tt := range []struct {
		name   string
		body   string
		lookup func(upstreamInspector) (bool, error)
	}{
		{name: "labels", body: container, lookup: func(ins upstreamInspector) (bool, error) {
			_, found, err := ins.inspectResource(ctx, dockerresource.KindContainer, "web")
			return found, err
		}},
		{name: "libpod network", body: `[{"labels":{"team":"a"}}]`, lookup: func(ins upstreamInspector) (bool, error) {
			_, found, err := ins.inspectResource(ctx, dockerresource.KindLibpodNetwork, "web")
			return found, err
		}},
		{name: "metadata", body: container, lookup: func(ins upstreamInspector) (bool, error) {
			_, found, err := ins.inspectResourceMeta(ctx, dockerresource.KindContainer, "web")
			return found, err
		}},
		{name: "combined details", body: container, lookup: func(ins upstreamInspector) (bool, error) {
			_, found, err := ins.inspectResourceDetails(ctx, dockerresource.KindContainer, "web")
			return found, err
		}},
		{name: "exec", body: `{"ContainerID":"web"}`, lookup: func(ins upstreamInspector) (bool, error) {
			_, found, err := ins.inspectExec(ctx, "exec")
			return found, err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, size := range []int{limit, limit + 2} {
				body := &inspectLimitBody{Reader: strings.NewReader(tt.body + strings.Repeat(" ", size-len(tt.body)))}
				inspector := upstreamInspector{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Body: body, ContentLength: -1}, nil
				})}}

				found, err := tt.lookup(inspector)
				if oversized := size > limit; found == oversized || (err != nil) != oversized {
					t.Errorf("size %d: found=%v err=%v, want found=%v error=%v", size, found, err, !oversized, oversized)
				}
				wantRead := min(size, limit+1)
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
