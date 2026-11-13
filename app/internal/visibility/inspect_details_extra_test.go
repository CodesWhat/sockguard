package visibility

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
)

func TestInspectResourceDetailsOutcomes(t *testing.T) {
	t.Parallel()

	t.Run("container decodes labels and names", func(t *testing.T) {
		t.Parallel()
		ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"Name":"/web","Image":"img:1","Config":{"Image":"img:1","Labels":{"tier":"prod"}}}`)
		}))
		details, found, err := ins.inspectResourceDetails(context.Background(), dockerresource.KindContainer, "abc")
		if err != nil || !found || details.labels["tier"] != "prod" || len(details.meta.names) != 1 {
			t.Fatalf("details=%+v found=%v err=%v", details, found, err)
		}
	})

	t.Run("image decodes tags", func(t *testing.T) {
		t.Parallel()
		ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"RepoTags":["a:1"],"Config":{"Labels":{"k":"v"}}}`)
		}))
		details, found, err := ins.inspectResourceDetails(context.Background(), dockerresource.KindImage, "sha256:abc")
		if err != nil || !found || details.labels["k"] != "v" || len(details.meta.repoTags) != 1 {
			t.Fatalf("details=%+v found=%v err=%v", details, found, err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
		details, found, err := ins.inspectResourceDetails(context.Background(), dockerresource.KindContainer, "gone")
		if err != nil || found || details != nil {
			t.Fatalf("details=%v found=%v err=%v, want nil/false/nil", details, found, err)
		}
	})

	t.Run("non-200 status", func(t *testing.T) {
		t.Parallel()
		ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
		if _, _, err := ins.inspectResourceDetails(context.Background(), dockerresource.KindContainer, "abc"); err == nil || !strings.Contains(err.Error(), "returned status") {
			t.Fatalf("err = %v, want returned status", err)
		}
	})

	t.Run("undecodable body", func(t *testing.T) {
		t.Parallel()
		for _, kind := range []dockerresource.Kind{dockerresource.KindContainer, dockerresource.KindImage} {
			ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{`) }))
			if _, _, err := ins.inspectResourceDetails(context.Background(), kind, "abc"); err == nil {
				t.Fatalf("%s: malformed body must error", kind)
			}
		}
	})

	t.Run("unsupported kind", func(t *testing.T) {
		t.Parallel()
		ins := upstreamInspector{client: &http.Client{}}
		if _, _, err := ins.inspectResourceDetails(context.Background(), dockerresource.KindNetwork, "n"); err == nil || !strings.Contains(err.Error(), "unsupported resource kind") {
			t.Fatalf("err = %v, want unsupported kind", err)
		}
	})

	t.Run("transport failure", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("transport down")
		ins := upstreamInspector{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, boom })}}
		if _, _, err := ins.inspectResourceDetails(context.Background(), dockerresource.KindContainer, "abc"); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want transport error", err)
		}
		if _, _, err := ins.inspectResourceMeta(context.Background(), dockerresource.KindImage, "abc"); !errors.Is(err, boom) {
			t.Fatalf("meta err = %v, want transport error", err)
		}
	})
}

func TestInspectResourceMetaUndecodableBody(t *testing.T) {
	t.Parallel()
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{`) }))
	if _, _, err := ins.inspectResourceMeta(context.Background(), dockerresource.KindContainer, "abc"); err == nil {
		t.Fatal("malformed meta body must error")
	}
}
