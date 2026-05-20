//go:build integration

package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/differential"
)

// TestDockerdRouteClassifierOracle is the real-dockerd tier of the
// proxy-vs-daemon differential. The in-process harness in app/differential/
// judges policy bypasses with differential.ClassifyDockerRoute, a hand-written
// model of how a Docker daemon routes a method+path to an endpoint. That model
// is only as trustworthy as its agreement with a live daemon — this test is
// the agreement check.
//
// For each crafted path it compares two views:
//
//   - predicted — differential.ClassifyDockerRoute(method, path), the oracle;
//   - observed  — the endpoint a live dockerd actually reaches, inferred from
//     the response it returns (see observeDockerRoute).
//
// The corpus mirrors the path-normalization cases the in-process harness
// pins — API version prefixes, dot-segment and slash collapsing, case
// sensitivity, separator tricks, single- and double-layer percent-encoding,
// and the double-encoded-dot over-decode that motivated the NormalizePath fix.
// It is GET-only on purpose: every path is anchored on the read-only
// /containers/json so replaying it against a live daemon executes nothing and
// mutates nothing. POST routing shares the same daemon router and is exercised
// by the in-process harness.
//
// A divergence here means the oracle's model of daemon routing is wrong, which
// would make every bypass verdict built on it unsound — so any mismatch fails.
func TestDockerdRouteClassifierOracle(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)

	// A running sentinel container makes GET /containers/json a non-empty,
	// positively identifiable array, so observeDockerRoute can confirm a 200
	// response really is the container list and not some other list endpoint.
	sentinelID := createDockerContainer(t, socketPath, dockerContainerCreateRequest{
		Image: "busybox:1.37",
		Cmd:   []string{"sh", "-c", "sleep 300"},
	})
	startDockerContainer(t, socketPath, sentinelID)
	waitForDockerContainerRunning(t, socketPath, sentinelID)

	version := fetchDockerVersion(t, socketPath)

	cases := []struct {
		name   string
		target string
	}{
		// Baselines and the daemon's own API-version prefix.
		{"baseline container list", "/containers/json"},
		{"query string ignored by routing", "/containers/json?all=1"},
		{"real API version prefix", "/v" + version.APIVersion + "/containers/json"},

		// Dot-segment and slash normalization: the daemon's router cleans the
		// path (collapsing "//", ".", "..") before matching, so each of these
		// must resolve to the same container list the oracle predicts.
		{"leading doubled slash", "//containers/json"},
		{"interior doubled slash", "/containers//json"},
		{"single-dot segment", "/containers/./json"},
		{"dot-dot resolving back to json", "/containers/json/../json"},
		{"dot-dot from create to json", "/containers/create/../json"},
		{"excess dot-dot cannot climb past root", "/containers/json/../../../containers/json"},
		{"dot-dot into create is GET-unrouted", "/containers/json/../create"},

		// Case sensitivity: the daemon routes path segments case-sensitively.
		{"capitalized first segment", "/Containers/json"},
		{"capitalized last segment", "/containers/JSON"},

		// Separator tricks: a matrix-param ';' and an injected ';' are literal
		// path characters — they do not collapse to /containers/json.
		{"matrix parameter suffix", "/containers/json;ignore=1"},
		{"semicolon in first segment", "/containers;x/json"},

		// Percent-encoding. A single-encoded path is decoded once by the
		// daemon's HTTP layer and converges on the same endpoint; a
		// double-encoded path keeps a literal %XX segment after that single
		// decode — the daemon never resolves the escape sockguard leaves
		// literal.
		{"single-encoded last segment", "/containers/%6a%73%6f%6e"},
		{"single-encoded dot collapses", "/containers/%2e/json"},
		{"double-encoded last segment stays literal", "/containers/%256a%2573%256f%256e"},
		// The regression case: %252e decodes once to a literal "%2e" segment,
		// which the daemon routes as a container name to container.inspect —
		// not the container list. sockguard must not decode it a second time.
		{"double-encoded dot routes to inspect", "/containers/%252e/json"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://docker"+tc.target, nil)
			if err != nil {
				t.Fatalf("build request for %q: %v", tc.target, err)
			}

			// The oracle judges the path the daemon's HTTP server parses —
			// req.URL.Path, decoded exactly once — the same input the
			// in-process harness feeds it.
			predicted := differential.ClassifyDockerRoute(http.MethodGet, req.URL.Path)
			observed := observeDockerRoute(t, socketPath, req, sentinelID)

			if predicted != observed {
				t.Fatalf("oracle divergence for GET %q: ClassifyDockerRoute predicted %q, "+
					"live dockerd routed to %q", tc.target, predicted, observed)
			}
		})
	}
}

// observeDockerRoute sends req straight to a live dockerd and infers which
// endpoint the daemon routed it to from the response. The redirect-following
// http.Client mirrors the daemon router's path-clean redirect, so a path the
// router cleans is observed on its cleaned route.
//
// The inference is deliberately conservative — it recognizes only the route
// categories this GET-only corpus can produce and fails loudly on anything
// else, so an unmodeled response can never be silently misclassified:
//
//   - 200 + a JSON array carrying the sentinel container → container.list;
//   - 404 + a JSON daemon error naming a container       → container.inspect;
//   - 404 + the router NotFound body ("page not found",
//     served as JSON on modern dockerd, plain text on older
//     builds)                                              → unknown.
func observeDockerRoute(t *testing.T, socketPath string, req *http.Request, sentinelID string) differential.RouteCategory {
	t.Helper()

	client, closeIdle := dockerHTTPClient(socketPath)
	defer closeIdle()

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send GET %q to docker: %v", req.URL.RequestURI(), err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read docker response for %q: %v", req.URL.RequestURI(), err)
	}
	contentType := resp.Header.Get("Content-Type")
	isJSON := strings.HasPrefix(contentType, "application/json")

	switch {
	case resp.StatusCode == http.StatusOK && isJSON:
		var list []struct {
			ID string `json:"Id"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatalf("200 response for %q is not a JSON array: %v; body: %s",
				req.URL.RequestURI(), err, clipBody(body))
		}
		for _, c := range list {
			if c.ID == sentinelID {
				return differential.RouteContainerList
			}
		}
		t.Fatalf("200 JSON array for %q did not contain the sentinel container — "+
			"cannot confirm it is the container list; body: %s",
			req.URL.RequestURI(), clipBody(body))

	case resp.StatusCode == http.StatusNotFound && isJSON:
		var apiErr struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(body, &apiErr); err != nil {
			t.Fatalf("404 JSON response for %q is not a docker API error: %v; body: %s",
				req.URL.RequestURI(), err, clipBody(body))
		}
		msg := strings.ToLower(apiErr.Message)
		// "page not found" is the mux router's NotFound handler when no
		// route matches — modern dockerd serves it as JSON, older builds
		// as plain text (handled in the next case). Either way, no route
		// was reached, so the daemon executed nothing.
		if strings.Contains(msg, "page not found") {
			return differential.RouteUnknown
		}
		if strings.Contains(msg, "container") {
			return differential.RouteContainerInspect
		}
		t.Fatalf("404 docker API error for %q is neither a NotFound nor a container error: %q",
			req.URL.RequestURI(), apiErr.Message)

	case resp.StatusCode == http.StatusNotFound:
		// Plain-text 404 on older dockerd builds — same NotFound handler,
		// no JSON envelope. No route matched.
		return differential.RouteUnknown
	}

	t.Fatalf("unclassifiable docker response for %q: status=%d content-type=%q body: %s",
		req.URL.RequestURI(), resp.StatusCode, contentType, clipBody(body))
	return differential.RouteUnknown // unreachable: the t.Fatalf above stops the test
}

// clipBody bounds a response body for inclusion in a failure message.
func clipBody(body []byte) string {
	const max = 256
	if len(body) > max {
		return string(body[:max]) + "…"
	}
	return string(body)
}
