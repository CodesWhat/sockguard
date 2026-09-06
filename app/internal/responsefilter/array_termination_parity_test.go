package responsefilter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/testhelp"
)

// arrayTerminationRoutes are the routes in this package that walk a top-level
// JSON array, one per distinct decoder rather than one per endpoint.
//
// The first three reach streamArrayResponse: the bespoke container-list
// handler, a responseTable list entry, and the libpod list handlers. The last
// reaches decodeJSONObjectArray, which is a different decoder on the same
// shape and so has to be held to the same verdicts. Every other array route in
// the package resolves to one of these two functions, so adding an endpoint
// does not add a parser.
var arrayTerminationRoutes = []struct {
	name string
	path string
}{
	{name: "compat container list", path: "/v1.53/containers/json"},
	{name: "compat secret list", path: "/v1.53/secrets"},
	{name: "libpod volume list", path: "/v5.8.1/libpod/volumes/json"},
	{name: "libpod network list", path: "/v5.8.1/libpod/networks/json"},
	{name: "libpod secret list", path: "/v5.8.1/libpod/secrets/json"},
	{name: "libpod network inspect array envelope", path: "/v5.8.1/libpod/networks/net-a/json"},
}

// TestArrayTerminationParityWithVisibility holds this package's array decoders
// to the verdicts in testhelp.JSONArrayTerminationCases, the same table
// internal/visibility asserts against in
// TestPatternListRejectsUnterminatedArrayAndTrailingBytes. Two packages
// stream the same Docker list bodies through decoders of their own, and the
// point of one shared table is that a case added for either is answered by
// both.
//
// The refusal here is ErrResponseRejected, which is exactly what
// internal/proxy's ErrorHandler turns into the 502 that visibility's
// middleware writes directly, so both packages refuse the same bodies with
// the same status.
func TestArrayTerminationParityWithVisibility(t *testing.T) {
	t.Parallel()

	opts := Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
		RedactSensitiveData:   true,
	}

	for _, route := range arrayTerminationRoutes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()
			for _, tc := range testhelp.JSONArrayTerminationCases() {
				t.Run(tc.Name, func(t *testing.T) {
					t.Parallel()

					resp := newResponseForTest(t, http.MethodGet, route.path, tc.Body)
					err := New(opts).ModifyResponse(resp)

					if !tc.Accept {
						if err == nil {
							body, _ := io.ReadAll(resp.Body)
							t.Fatalf("ModifyResponse(%q) error = nil, want a rejection; body relayed: %s", tc.Body, body)
						}
						if !errors.Is(err, ErrResponseRejected) {
							t.Fatalf("ModifyResponse(%q) error = %v, want it to wrap ErrResponseRejected so the proxy answers 502", tc.Body, err)
						}
						return
					}

					if err != nil {
						t.Fatalf("ModifyResponse(%q) error = %v, want nil", tc.Body, err)
					}
					body, readErr := io.ReadAll(resp.Body)
					if readErr != nil {
						t.Fatalf("ReadAll: %v", readErr)
					}
					// The oracle is encoding/json's whole-body parse, not the
					// streaming decoder under test: an accepted body must come
					// back out as exactly one JSON array, so a disagreement
					// between the two shows up here rather than as a rewritten
					// 200 the client reads as the complete list.
					var items []json.RawMessage
					if uerr := json.Unmarshal(body, &items); uerr != nil {
						t.Fatalf("rewritten body is not a single JSON array: %v (out=%q, in=%q)", uerr, body, tc.Body)
					}
				})
			}
		})
	}
}
