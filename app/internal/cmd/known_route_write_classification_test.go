package cmd

import (
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproxy"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// This file keeps a new upstream write route from landing unclassified. Every
// catalog route whose method is not GET or HEAD has to be classified in a
// place the proxy enforces, or sit in reviewedWriteRoutes below with a reason.
// A route in neither fails TestKnownWriteRoutesAreClassified, which is the cue
// to decide what guards the new route before the catalog change merges.

// reviewedWriteRoutes are catalog writes no startup acknowledgment or body
// inspector covers, reviewed as safe to forward without one. Each names the
// layer that does decide the request. Ownership coverage of the routes that
// name an owned resource is asserted separately, in the ownership package's
// catalog test.
var reviewedWriteRoutes = map[string]string{
	// Lifecycle verbs on a named container: no request body to inspect, and the
	// owner check on the named container is the control.
	"POST /containers/{id}/kill":             "lifecycle verb, signal in the query; owner check on the container",
	"POST /containers/{name}/kill":           "lifecycle verb, signal in the query; owner check on the container",
	"POST /containers/{id}/pause":            "lifecycle verb, no body; owner check on the container",
	"POST /containers/{name}/pause":          "lifecycle verb, no body; owner check on the container",
	"POST /containers/{id}/rename":           "new name is a query parameter; owner check on the container",
	"POST /containers/{name}/rename":         "new name is a query parameter; owner check on the container",
	"POST /containers/{id}/resize":           "terminal size query only; owner check on the container",
	"POST /containers/{name}/resize":         "terminal size query only; owner check on the container",
	"POST /containers/{id}/restart":          "lifecycle verb, no body; owner check on the container",
	"POST /containers/{name}/restart":        "lifecycle verb, no body; owner check on the container",
	"POST /containers/{id}/start":            "lifecycle verb, no body; owner check on the container",
	"POST /containers/{name}/start":          "lifecycle verb, no body; owner check on the container",
	"POST /containers/{id}/stop":             "lifecycle verb, no body; owner check on the container",
	"POST /containers/{name}/stop":           "lifecycle verb, no body; owner check on the container",
	"POST /containers/{id}/unpause":          "lifecycle verb, no body; owner check on the container",
	"POST /containers/{name}/unpause":        "lifecycle verb, no body; owner check on the container",
	"POST /containers/{id}/wait":             "blocks until the container exits, no body; owner check on the container",
	"POST /containers/{name}/wait":           "blocks until the container exits, no body; owner check on the container",
	"DELETE /containers/{id}":                "removal by name, no body; container_remove inspector and owner check",
	"DELETE /containers/{name}":              "removal by name, no body; container_remove inspector and owner check",
	"POST /containers/prune":                 "no body; owner label injected into the filters query",
	"POST /libpod/containers/{name}/init":    "lifecycle verb, no body; owner check on the container",
	"POST /libpod/containers/{name}/kill":    "lifecycle verb, signal in the query; owner check on the container",
	"POST /libpod/containers/{name}/pause":   "lifecycle verb, no body; owner check on the container",
	"POST /libpod/containers/{name}/rename":  "new name is a query parameter; owner check on the container",
	"POST /libpod/containers/{name}/resize":  "terminal size query only; owner check on the container",
	"POST /libpod/containers/{name}/restart": "lifecycle verb, no body; owner check on the container",
	"POST /libpod/containers/{name}/start":   "lifecycle verb, no body; owner check on the container",
	"POST /libpod/containers/{name}/stop":    "lifecycle verb, no body; owner check on the container",
	"POST /libpod/containers/{name}/unmount": "lifecycle verb, no body; owner check on the container",
	"POST /libpod/containers/{name}/unpause": "lifecycle verb, no body; owner check on the container",
	"POST /libpod/containers/{name}/wait":    "blocks until the container exits, no body; owner check on the container",
	"DELETE /libpod/containers/{name}":       "removal by name, no body; container_remove inspector and owner check",
	"POST /libpod/containers/prune":          "no body; owner label injected into the filters query",
	"POST /commit":                           "container and repo come from the query; owner references checked from the query",
	"POST /libpod/commit":                    "container and repo come from the query; owner references checked from the query",
	"POST /containers/create":                "container_create inspector always runs with fail-closed defaults, so no acknowledgment is needed; owner references checked",
	"POST /debug/pprof/symbol":               "POST form of pprof symbol lookup; the GET debug routes are read-exfiltration gated and a rule has to admit the path",
	"POST /auth":                             "validates registry credentials, changes no daemon state",
	"POST /exec/{id}/resize":                 "terminal size query only; owner check resolves the exec session's container",
	"POST /libpod/exec/{id}/kill":            "signal in the query; owner check resolves the exec session's container",
	"POST /libpod/exec/{id}/remove":          "no body; owner check resolves the exec session's container",
	"POST /libpod/exec/{id}/resize":          "terminal size query only; owner check resolves the exec session's container",
	"POST /build/prune":                      "build cache prune, no body; the cache carries no owner label and owner isolation forwards it, so rules decide",
	"POST /images/prune":                     "no body; owner label injected into the filters query",
	"POST /libpod/images/prune":              "no body; owner label injected into the filters query",
	"DELETE /images/{name:.*}":               "removal by reference, no body; owner check on the image",
	"DELETE /libpod/images/{name:.*}":        "removal by reference, no body; owner check on the image",
	"DELETE /libpod/images/remove":           "batch references in the query; image_batch owner check",
	"POST /images/{name:.*}/tag":             "target in the query; owner check on source and destination",
	"POST /libpod/images/{name:.*}/tag":      "target in the query; owner check on source and destination",
	"POST /libpod/images/{name:.*}/untag":    "target in the query; owner check on source and destination",
	"DELETE /networks/{id}":                  "removal by name, no body; owner check on the network",
	"DELETE /networks/{name}":                "removal by name, no body; owner check on the network",
	"DELETE /libpod/networks/{name}":         "removal by name, no body; owner check on the network",
	"POST /networks/prune":                   "no body; owner label injected into the filters query",
	"POST /libpod/networks/prune":            "no body; owner label injected into the filters query",
	"DELETE /volumes/{name}":                 "removal by name, no body; owner check on the volume",
	"DELETE /libpod/volumes/{name}":          "removal by name, no body; owner check on the volume",
	"POST /volumes/prune":                    "no body; owner label injected into the filters query",
	"POST /libpod/volumes/prune":             "no body; owner label injected into the filters query",
	"POST /libpod/volumes/{name}/import":     "tar body is written into an owned volume; owner check on the volume",
	"DELETE /libpod/pods/{name}":             "removal by name, no body; owner check on the pod",
	"POST /libpod/pods/{name}/kill":          "lifecycle verb, signal in the query; owner check on the pod",
	"POST /libpod/pods/{name}/pause":         "lifecycle verb, no body; owner check on the pod",
	"POST /libpod/pods/{name}/restart":       "lifecycle verb, no body; owner check on the pod",
	"POST /libpod/pods/{name}/start":         "lifecycle verb, no body; owner check on the pod",
	"POST /libpod/pods/{name}/stop":          "lifecycle verb, no body; owner check on the pod",
	"POST /libpod/pods/{name}/unpause":       "lifecycle verb, no body; owner check on the pod",
	"DELETE /secrets/{id}":                   "removal by name, no body; owner check on the secret",
	"DELETE /secrets/{name}":                 "removal by name, no body; owner check on the secret",
	"DELETE /libpod/secrets/{name}":          "removal by name, no body; owner check on the secret",
	"POST /secrets/{id}/update":              "labels-only update; owner check on the secret",
	"POST /secrets/{name}/update":            "labels-only update; owner check on the secret",
	"DELETE /configs/{id}":                   "removal by name, no body; owner check on the config",
	"POST /configs/{id}/update":              "labels-only update; owner check on the config",
	"DELETE /services/{id}":                  "removal by name, no body; owner check on the service",
	"DELETE /nodes/{id}":                     "Swarm node removal, no body; owner check on the node",
	"POST /swarm/leave":                      "no body; owner check on the swarm state",
	"DELETE /plugins/{name:.*}":              "plugin removal, no body; plugin rules gate the endpoint",
	"POST /plugins/{name:.*}/disable":        "no body; plugin rules gate the endpoint",
	"POST /plugins/{name:.*}/enable":         "no body; plugin rules gate the endpoint",
}

// fullRequestBody configures every request_body block whose inspector is only
// active once the operator sets something, so bodyInspectionConfiguredForEndpoint
// reports whether an endpoint HAS an inspector at all.
func fullRequestBody() config.RequestBodyConfig {
	var body config.RequestBodyConfig
	body.Exec.AllowedCommands = [][]string{{"/bin/true"}}
	body.Swarm.AllowedJoinRemoteAddrs = []string{"manager.internal:2377"}
	body.Plugin.AllowedSetEnvPrefixes = []string{"DEBUG="}
	return body
}

// concreteCatalogPath turns a catalog path into the spelling the endpoint
// catalogs use: every parameter, slash-bearing or not, becomes sockguard-test.
func concreteCatalogPath(path string) string {
	return knownRouteParameter.ReplaceAllString(path, "sockguard-test")
}

func isReadMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

// classifyWriteRoute reports how the proxy enforces a write route, or "" when
// nothing does. Every layer is asked through the production catalog or lookup.
func classifyWriteRoute(route knownAPIRoute) string {
	concrete := concreteCatalogPath(route.Path)
	for _, endpoint := range bodySensitiveWriteEndpoints {
		if endpoint.method != route.Method || endpoint.path != concrete {
			continue
		}
		if bodyInspectionConfiguredForEndpoint(fullRequestBody(), endpoint) {
			return "body-inspected"
		}
		return "body-blind, insecure_allow_body_blind_writes"
	}
	for _, endpoint := range buildkitTunnelEndpoints {
		if endpoint.method == route.Method && endpoint.path == concrete {
			return "opaque buildkit tunnel"
		}
	}
	if service, rpc, ok := buildkitproxy.ParseGRPCPath(concrete); ok && strings.Contains(service, ".") {
		_ = rpc
		return "buildkit gRPC method, default-deny registry"
	}
	for _, endpoint := range sensitiveExfilEndpoints {
		if endpoint.method == route.Method && endpoint.path == concrete {
			return "read-exfiltration acknowledgment"
		}
	}
	if _, ok := filter.LookupLibpodUnscopeableWrite(route.Method, concrete); ok {
		return "refused under owner isolation (unscopeable write)"
	}
	if _, ok := reviewedWriteRoutes[route.Method+" "+route.Path]; ok {
		return "reviewed allowlist"
	}
	return ""
}

// unclassifiedWriteRoutes lists the write routes in routes nothing classifies.
// It takes the routes as a parameter so the mutation check can inject one.
func unclassifiedWriteRoutes(routes []knownAPIRoute) []string {
	var missing []string
	for _, route := range routes {
		if isReadMethod(route.Method) {
			continue
		}
		if classifyWriteRoute(route) == "" {
			missing = append(missing, route.Method+" "+route.Path)
		}
	}
	sort.Strings(missing)
	return missing
}

func TestKnownWriteRoutesAreClassified(t *testing.T) {
	routes, err := loadKnownAPIRoutes()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	if missing := unclassifiedWriteRoutes(routes); len(missing) > 0 {
		t.Fatalf("write routes with no classification (add a body inspector, an acknowledgment gate, an ownership refusal, or a reviewed reason in reviewedWriteRoutes):\n  %s", strings.Join(missing, "\n  "))
	}
}

// TestReviewedWriteRoutesAreCurrent keeps the allowlist honest: an entry for a
// route the catalog no longer has, or one a real layer now classifies, is dead
// weight that would hide the next gap.
func TestReviewedWriteRoutesAreCurrent(t *testing.T) {
	routes, err := loadKnownAPIRoutes()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	inCatalog := map[string]knownAPIRoute{}
	for _, route := range routes {
		inCatalog[route.Method+" "+route.Path] = route
	}
	for key, reason := range reviewedWriteRoutes {
		route, ok := inCatalog[key]
		if !ok {
			t.Errorf("reviewedWriteRoutes[%q] is not in the catalog", key)
			continue
		}
		if isReadMethod(route.Method) {
			t.Errorf("reviewedWriteRoutes[%q] is a read", key)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("reviewedWriteRoutes[%q] has no reason", key)
		}
		delete(reviewedWriteRoutes, key)
		if layer := classifyWriteRoute(route); layer != "" {
			t.Errorf("reviewedWriteRoutes[%q] is already classified by %q; drop the entry", key, layer)
		}
		reviewedWriteRoutes[key] = reason
	}
}

// TestUnclassifiedWriteRouteFailsTheClassification is the mutation check: a
// synthetic write route nothing covers has to be reported, and the same route
// reported as read has to be left alone.
func TestUnclassifiedWriteRouteFailsTheClassification(t *testing.T) {
	routes, err := loadKnownAPIRoutes()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	synthetic := knownAPIRoute{Method: http.MethodPost, Path: "/libpod/widgets/{name}/frobnicate"}
	mutated := append(slices.Clone(routes), synthetic)
	missing := unclassifiedWriteRoutes(mutated)
	if !slices.Contains(missing, "POST /libpod/widgets/{name}/frobnicate") {
		t.Fatalf("an unclassified write route was not reported; got %v", missing)
	}
	read := knownAPIRoute{Method: http.MethodGet, Path: "/libpod/widgets/{name}/frobnicate"}
	if missing := unclassifiedWriteRoutes(append(slices.Clone(routes), read)); slices.Contains(missing, "GET /libpod/widgets/{name}/frobnicate") {
		t.Fatalf("a read route was reported as an unclassified write: %v", missing)
	}
}
