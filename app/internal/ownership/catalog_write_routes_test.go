package ownership

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
)

// This file holds the ownership half of the write-route classification. The
// catalog is the proxy's embedded known_api_routes.json, read from its source
// file because cmd embeds it and this package cannot import cmd.
//
// Every catalog write route whose path names an existing resource ({name},
// {id}, ...) is sent through the real middleware as owner job-123 into a world
// where every resource and exec session belongs to someone else. A route the
// middleware lets through in that world names a resource nothing checks, so a
// client could act on another owner's resource through it. A new such route
// fails here until ownership handles it or it is added to
// ownerUnscopedWriteRoutes with a reason.

const catalogPathForOwnershipTest = "../cmd/known_api_routes.json"

var catalogRouteParameter = regexp.MustCompile(`\{[^{}]+\}`)

type catalogWriteRoute struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

func loadCatalogWriteRoutes(t *testing.T) []catalogWriteRoute {
	t.Helper()
	raw, err := os.ReadFile(catalogPathForOwnershipTest)
	if err != nil {
		t.Fatalf("read route catalog: %v", err)
	}
	var catalog struct {
		Routes []catalogWriteRoute `json:"routes"`
	}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatalf("decode route catalog: %v", err)
	}
	var writes []catalogWriteRoute
	for _, route := range catalog.Routes {
		if route.Method != http.MethodGet && route.Method != http.MethodHead {
			writes = append(writes, route)
		}
	}
	if len(writes) == 0 {
		t.Fatal("catalog holds no write routes")
	}
	return writes
}

// ownerUnscopedWriteRoutes are catalog writes that name something in the path
// and still pass the owner middleware untouched in a world of foreign
// resources. Each is a resource kind owner isolation does not scope, so the
// gate is the rule set, not an owner label.
var ownerUnscopedWriteRoutes = map[string]string{
	"POST /plugins/{name:.*}/disable": "plugins are daemon-global and carry no owner label; plugin rules gate the endpoint",
	"POST /plugins/{name:.*}/enable":  "plugins are daemon-global and carry no owner label; plugin rules gate the endpoint",
	"POST /plugins/{name:.*}/push":    "plugins are daemon-global and carry no owner label; plugin rules and the read-exfiltration acknowledgment gate the endpoint",
	"POST /plugins/{name:.*}/set":     "plugins are daemon-global and carry no owner label; request_body.plugin gates the endpoint",
	"POST /plugins/{name:.*}/upgrade": "plugins are daemon-global and carry no owner label; request_body.plugin gates the endpoint",
	"DELETE /plugins/{name:.*}":       "plugins are daemon-global and carry no owner label; plugin rules gate the endpoint",
}

// foreignWorldReached reports whether a write to concretePath, sent as owner
// job-123 into a world where everything belongs to another owner, reached the
// upstream. denied is the status when it did not.
func foreignWorldReached(method, concretePath string) (reached bool, status int) {
	const labelKey = "com.sockguard.owner"
	foreign := map[string]string{labelKey: "someone-else"}
	inspectResource := func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
		return foreign, true, nil
	}
	inspectExec := func(context.Context, string) (string, bool, error) {
		return "foreign-container", true, nil
	}
	handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: labelKey}, inspectResource, inspectExec)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusNoContent)
		}))
	req := httptest.NewRequest(method, "/v5.8.1"+concretePath, strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return reached, rec.Code
}

// ownerUnhandledWriteRoutes lists the parameterized write routes in routes the
// owner middleware does not stop in a world of foreign resources.
func ownerUnhandledWriteRoutes(routes []catalogWriteRoute) []string {
	var unhandled []string
	for _, route := range routes {
		if !catalogRouteParameter.MatchString(route.Path) {
			continue
		}
		key := route.Method + " " + route.Path
		if _, reviewed := ownerUnscopedWriteRoutes[key]; reviewed {
			continue
		}
		concrete := catalogRouteParameter.ReplaceAllString(route.Path, "sockguard-test")
		if reached, _ := foreignWorldReached(route.Method, concrete); reached {
			unhandled = append(unhandled, key)
		}
	}
	sort.Strings(unhandled)
	return unhandled
}

func TestCatalogWriteRoutesNamingAResourceAreOwnerHandled(t *testing.T) {
	t.Parallel()
	routes := loadCatalogWriteRoutes(t)
	if unhandled := ownerUnhandledWriteRoutes(routes); len(unhandled) > 0 {
		t.Fatalf("write routes that name a resource and pass owner isolation unchecked (add an owner check or a refusal, or a reviewed reason in ownerUnscopedWriteRoutes):\n  %s", strings.Join(unhandled, "\n  "))
	}
}

// TestOwnerUnscopedWriteRoutesAreCurrent keeps the allowlist honest, the same
// way the cmd allowlist test does.
func TestOwnerUnscopedWriteRoutesAreCurrent(t *testing.T) {
	t.Parallel()
	inCatalog := map[string]catalogWriteRoute{}
	for _, route := range loadCatalogWriteRoutes(t) {
		inCatalog[route.Method+" "+route.Path] = route
	}
	for key, reason := range ownerUnscopedWriteRoutes {
		route, ok := inCatalog[key]
		if !ok {
			t.Errorf("ownerUnscopedWriteRoutes[%q] is not a catalog write route", key)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("ownerUnscopedWriteRoutes[%q] has no reason", key)
		}
		concrete := catalogRouteParameter.ReplaceAllString(route.Path, "sockguard-test")
		if reached, _ := foreignWorldReached(route.Method, concrete); !reached {
			t.Errorf("ownerUnscopedWriteRoutes[%q] is now stopped by the middleware; drop the entry", key)
		}
	}
}

// TestOwnerUnhandledWriteRouteFailsTheCatalogCheck is the mutation check: a
// synthetic write route on a resource family the middleware has never heard of
// must be reported, and a route it does handle must not be.
func TestOwnerUnhandledWriteRouteFailsTheCatalogCheck(t *testing.T) {
	t.Parallel()
	routes := loadCatalogWriteRoutes(t)
	synthetic := catalogWriteRoute{Method: http.MethodPost, Path: "/libpod/widgets/{name}/frobnicate"}
	if got := ownerUnhandledWriteRoutes(append(slices.Clone(routes), synthetic)); !slices.Contains(got, "POST /libpod/widgets/{name}/frobnicate") {
		t.Fatalf("an unhandled write route on a resource was not reported; got %v", got)
	}
	handled := catalogWriteRoute{Method: http.MethodPost, Path: "/libpod/pods/{name}/frobnicate"}
	if got := ownerUnhandledWriteRoutes([]catalogWriteRoute{handled}); len(got) != 0 {
		t.Fatalf("a pod route is owner-checked by prefix and must not be reported; got %v", got)
	}
}
