package ownership

// FuzzOwnershipMutateBody exercises the JSON body mutation pipeline with
// arbitrary client-supplied bytes. These functions parse and rewrite
// untrusted request bodies; any panic is a real finding.
//
// Run with:
//
//	go test -fuzz=FuzzOwnershipMutateBody -fuzztime=60s ./internal/ownership/

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

// makeBodyRequest builds a minimal *http.Request whose body is set to the
// provided bytes. It is the caller's responsibility that body is non-nil.
func makeBodyRequest(body []byte) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "http://docker/containers/create", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Body = io.NopCloser(bytes.NewReader(body))
	return req
}

// FuzzOwnershipMutateBody targets addOwnerLabelToBody, which is the widest
// JSON mutation path: it parses the full body as map[string]any (via
// mutateJSONBody) and then writes into the "Labels" sub-object.  The service
// variant (addOwnerLabelToServiceBody) traverses deeper paths; it is covered
// by FuzzOwnershipMutateServiceBody below.
func FuzzOwnershipMutateBody(f *testing.F) {
	// Valid Docker create bodies — mutation should succeed.
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"Labels":{}}`))
	f.Add([]byte(`{"Labels":null}`))
	f.Add([]byte(`{"Labels":{"existing":"value"}}`))
	f.Add([]byte(`{"Labels":{"a":"1","b":"2"},"Image":"alpine"}`))

	// Structurally invalid / wrong-type seeds — mutation should return an
	// error (not panic).
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[true]`))
	f.Add([]byte(`"string"`))
	f.Add([]byte(`42`))
	f.Add([]byte(`{"Labels":["bad","type"]}`))
	f.Add([]byte(``)) // empty body — mutateJSONBody returns an error

	// Deeply nested to exercise stack depth.
	f.Add([]byte(`{"a":{"b":{"c":{"d":{"e":{"Labels":{}}}}}}}`))

	// Large numbers that must round-trip without float64 truncation.
	f.Add([]byte(`{"Memory":9223372036854775807,"Labels":{}}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		// We only care that no panic occurs; errors are acceptable.
		req := makeBodyRequest(body)
		//nolint:errcheck
		_ = addOwnerLabelToBody(req, "com.sockguard.owner", "fuzz-owner")
	})
}

// FuzzOwnershipMutateServiceBody targets addOwnerLabelToServiceBody, which
// drills through TaskTemplate.ContainerSpec.Labels in addition to the
// top-level Labels key — a deeper traversal that could hit distinct panic
// sites compared to FuzzOwnershipMutateBody.
func FuzzOwnershipMutateServiceBody(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"Labels":{},"TaskTemplate":{"ContainerSpec":{"Labels":{}}}}`))
	f.Add([]byte(`{"Labels":null,"TaskTemplate":null}`))
	f.Add([]byte(`{"TaskTemplate":{"ContainerSpec":{"Labels":{"existing":"v"}}}}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"Labels":42}`))
	f.Add([]byte(`{"TaskTemplate":{"ContainerSpec":{"Labels":"not-an-object"}}}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		req := makeBodyRequest(body)
		//nolint:errcheck
		_ = addOwnerLabelToServiceBody(req, "com.sockguard.owner", "fuzz-owner")
	})
}
