package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/responsefilter"
)

// redactableBody is shaped like a container inspect response: every field the
// response filter knows how to redact is present, so if a path reaches the
// filter at all the body comes back changed.
const redactableBody = `{"Id":"c1","Config":{"Env":["SECRET=hunter2"]},` +
	`"Mounts":[{"Source":"/host/secrets","Destination":"/run/secrets","Type":"bind"}],` +
	`"NetworkSettings":{"IPAddress":"172.17.0.2","Networks":{"bridge":{"IPAddress":"172.17.0.2","Gateway":"172.17.0.1"}}}}`

func allRedactionsEnabled() *responsefilter.Filter {
	return responsefilter.New(responsefilter.Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
		RedactSensitiveData:   true,
		RedactHostTopology:    true,
	})
}

func jsonResponse(t *testing.T, path, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

func responseBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.Body == nil {
		return ""
	}
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	_ = resp.Body.Close()
	return string(out)
}

// TestHijackCandidatePathsAreNotRedactableShapes pins the invariant that makes
// the hijack path's lack of response redaction safe.
//
// responsefilter.ModifyResponse documents that hijacked streams bypass it
// entirely, because attach and exec-start are raw bidirectional byte tunnels
// and there is no JSON body to rewrite. That is correct for the four endpoints
// currently in the hijack candidate set, and the non-upgrade branch
// (writeNonUpgradeHijackResponse) copies the upstream body straight to the
// client without consulting the filter.
//
// The risk is not today's behavior, it is drift: adding a redactable endpoint
// to filter.IsHijackCandidatePath would silently route it around every
// response-side redaction the operator configured, with no failing test. So
// assert the two sets are disjoint — every hijack candidate must be a no-op
// for a filter with every redaction switched on, even when handed a body the
// filter would otherwise rewrite.
func TestHijackCandidatePathsAreNotRedactableShapes(t *testing.T) {
	hijackPaths := []string{
		"/containers/c1/attach",
		"/exec/e1/start",
		"/libpod/containers/c1/attach",
		"/libpod/exec/e1/start",
	}

	for _, path := range hijackPaths {
		t.Run(path, func(t *testing.T) {
			if !filter.IsHijackCandidatePath(http.MethodPost, filter.NormalizePath(path)) {
				t.Fatalf("IsHijackCandidatePath(POST, %q) = false; the hijack candidate set changed and this test's fixture list is stale", path)
			}

			resp := jsonResponse(t, path, redactableBody)
			if err := allRedactionsEnabled().ModifyResponse(resp); err != nil {
				t.Fatalf("ModifyResponse(%q) = %v, want nil", path, err)
			}
			if got := responseBody(t, resp); got != redactableBody {
				t.Fatalf("ModifyResponse rewrote the body for hijack candidate %q.\n"+
					"This endpoint is proxied as a raw tunnel by writeNonUpgradeHijackResponse, which never calls the "+
					"response filter, so a redactable shape here would be served to clients unredacted. Either drop the "+
					"path from filter.IsHijackCandidatePath or route the non-upgrade hijack response through "+
					"responsefilter.ModifyResponse.\ngot:  %s\nwant: %s", path, got, redactableBody)
			}
		})
	}
}

// TestRedactableBodyFixtureIsActuallyRedacted stops the test above from passing
// vacuously: if the fixture stopped being a shape the filter rewrites, every
// subtest would trivially compare equal and the invariant would go unguarded.
func TestRedactableBodyFixtureIsActuallyRedacted(t *testing.T) {
	resp := jsonResponse(t, "/containers/c1/json", redactableBody)
	resp.Request.Method = http.MethodGet

	if err := allRedactionsEnabled().ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse(inspect) = %v, want nil", err)
	}

	got := responseBody(t, resp)
	if got == redactableBody {
		t.Fatal("the fixture body survived an inspect-path filter unchanged; it is no longer a redactable shape, so TestHijackCandidatePathsAreNotRedactableShapes proves nothing")
	}
	if bytes.Contains([]byte(got), []byte("hunter2")) {
		t.Fatalf("inspect response still carries the container env secret: %s", got)
	}
}
