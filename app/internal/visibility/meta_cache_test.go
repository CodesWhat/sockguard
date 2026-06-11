package visibility

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/dockerresource"
	"github.com/codeswhat/sockguard/internal/inspectcache"
)

// Docker's legacy filter encoding must survive the visibility selector merge:
// legacy maps are flattened to sorted arrays and the selectors are appended
// without disturbing other filter keys.
func TestAddVisibilityLabelFiltersAcceptsLegacyEncoding(t *testing.T) {
	t.Parallel()
	legacy := `{"label":{"env=prod":true},"status":{"running":true}}`
	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json?filters="+url.QueryEscape(legacy), nil)

	err := addVisibilityLabelFilters(req, "/containers/json", []compiledSelector{
		{key: "com.sockguard.visible", value: "true", hasValue: true},
	})
	if err != nil {
		t.Fatalf("addVisibilityLabelFilters() error = %v, want nil", err)
	}

	var filters map[string][]string
	if err := json.Unmarshal([]byte(req.URL.Query().Get("filters")), &filters); err != nil {
		t.Fatalf("rewritten filters are not modern array form: %v", err)
	}
	if got := filters["label"]; len(got) != 2 || got[0] != "env=prod" || got[1] != "com.sockguard.visible=true" {
		t.Fatalf("label filters = %#v, want [env=prod com.sockguard.visible=true]", got)
	}
	if got := filters["status"]; len(got) != 1 || got[0] != "running" {
		t.Fatalf("status filters = %#v, want [running] flattened from legacy map", got)
	}
}

// The meta cache wired by newVisibilityDeps must flatten repeated
// single-resource pattern checks to one upstream inspect per TTL window, and
// re-inspect after the TTL expires. This drives the same
// cache→inspectResourceMeta→pattern-match shape production uses, with a fake
// clock and a counting resolver in place of the daemon.
func TestResourceVisibleWithPolicyUsesMetaCache(t *testing.T) {
	t.Parallel()

	calls := 0
	current := time.Unix(1000, 0)
	cache := inspectcache.New(
		inspectcache.DefaultTTL,
		inspectcache.DefaultMaxSize,
		func() time.Time { return current },
		func(_ context.Context, _, _ string) (*resourceMeta, bool, error) {
			calls++
			return &resourceMeta{names: []string{"/web-1"}, image: "nginx:latest"}, true, nil
		},
	)
	deps := visibilityDeps{
		inspectResourceMeta: func(ctx context.Context, kind dockerresource.Kind, identifier string) (*resourceMeta, bool, error) {
			return cache.Lookup(ctx, string(kind), identifier)
		},
	}
	patterns, err := compilePatterns([]string{"web-*"})
	if err != nil {
		t.Fatalf("compilePatterns: %v", err)
	}
	policy := compiledPolicy{namePatterns: patterns}

	for i := 0; i < 3; i++ {
		visible, err := resourceVisibleWithPolicy(context.Background(), deps, dockerresource.KindContainer, "abc123", &policy)
		if err != nil {
			t.Fatalf("poll %d: resourceVisibleWithPolicy error = %v", i, err)
		}
		if !visible {
			t.Fatalf("poll %d: visible = false, want true (name web-1 matches web-*)", i)
		}
	}
	if calls != 1 {
		t.Fatalf("upstream inspects after 3 polls within TTL = %d, want 1 (cache must absorb repeats)", calls)
	}

	current = current.Add(inspectcache.DefaultTTL + time.Second)
	visible, err := resourceVisibleWithPolicy(context.Background(), deps, dockerresource.KindContainer, "abc123", &policy)
	if err != nil || !visible {
		t.Fatalf("post-TTL poll = visible %v, err %v; want true, nil", visible, err)
	}
	if calls != 2 {
		t.Fatalf("upstream inspects after TTL expiry = %d, want 2 (stale entry must re-resolve)", calls)
	}
}

// Pattern-mismatch results flow through the same cached path: a resource
// whose name fails the pattern axes is hidden without extra inspects.
func TestResourceVisibleWithPolicyHidesNonMatchingViaCache(t *testing.T) {
	t.Parallel()

	calls := 0
	cache := inspectcache.New(
		inspectcache.DefaultTTL,
		inspectcache.DefaultMaxSize,
		time.Now,
		func(_ context.Context, _, _ string) (*resourceMeta, bool, error) {
			calls++
			return &resourceMeta{names: []string{"/db-1"}, image: "postgres:16"}, true, nil
		},
	)
	deps := visibilityDeps{
		inspectResourceMeta: func(ctx context.Context, kind dockerresource.Kind, identifier string) (*resourceMeta, bool, error) {
			return cache.Lookup(ctx, string(kind), identifier)
		},
	}
	patterns, err := compilePatterns([]string{"web-*"})
	if err != nil {
		t.Fatalf("compilePatterns: %v", err)
	}
	policy := compiledPolicy{namePatterns: patterns}

	for i := 0; i < 2; i++ {
		visible, err := resourceVisibleWithPolicy(context.Background(), deps, dockerresource.KindContainer, "db1", &policy)
		if err != nil {
			t.Fatalf("poll %d: error = %v", i, err)
		}
		if visible {
			t.Fatalf("poll %d: visible = true, want false (db-1 does not match web-*)", i)
		}
	}
	if calls != 1 {
		t.Fatalf("upstream inspects = %d, want 1", calls)
	}
}
