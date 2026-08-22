package visibility

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/inspectcache"
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

// A standalone inspectcache.Cache (as used directly below) flattens repeated
// single-resource pattern checks to one upstream inspect per TTL window, and
// re-inspects after the TTL expires. Production's own cache→
// inspectResourceMeta→pattern-match wiring (newVisibilityDepsClient) uses a
// non-positive TTL instead — see TestNewVisibilityDepsClientResolvesFreshAfterNameReuse
// — so a positive-verdict cache hit is never served across a name/tag reuse.
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

// TestNewVisibilityDepsClientResolvesFreshAfterNameReuse is the regression
// test for the stale-cache-content-leak finding: production's cache wiring
// (newVisibilityDepsClient) must not memoize a positive inspect verdict
// across a name reuse. Docker frees a container's name the instant it's
// deleted and lets a differently-labeled container claim it immediately, so
// a memoized "team=alice" verdict for "shared-name" could otherwise still be
// served after the real "shared-name" now belongs to team=bob.
func TestNewVisibilityDepsClientResolvesFreshAfterNameReuse(t *testing.T) {
	t.Parallel()

	calls := 0
	currentTeam := "alice"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Config": map[string]any{"Labels": map[string]string{"team": currentTeam}},
		})
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			r2 := r.Clone(r.Context())
			r2.URL.Scheme = "http"
			r2.URL.Host = srv.Listener.Addr().String()
			return srv.Client().Transport.RoundTrip(r2)
		}),
	}
	deps := newVisibilityDepsClient(client)

	labels, found, err := deps.inspectResource(context.Background(), dockerresource.KindContainer, "shared-name")
	if err != nil || !found {
		t.Fatalf("first inspect = (%v, found=%v), want (nil, found=true)", err, found)
	}
	if labels["team"] != "alice" {
		t.Fatalf("first inspect labels = %v, want team=alice", labels)
	}

	// Simulate delete + recreate under the same name with a different owner,
	// all within what would have been the cache's TTL window.
	currentTeam = "bob"

	labels, found, err = deps.inspectResource(context.Background(), dockerresource.KindContainer, "shared-name")
	if err != nil || !found {
		t.Fatalf("second inspect = (%v, found=%v), want (nil, found=true)", err, found)
	}
	if labels["team"] != "bob" {
		t.Fatalf("second inspect labels = %v, want team=bob (stale team=alice verdict served instead)", labels)
	}
	if calls != 2 {
		t.Fatalf("upstream inspect calls = %d, want 2 (a memoized positive verdict would show 1)", calls)
	}
}
