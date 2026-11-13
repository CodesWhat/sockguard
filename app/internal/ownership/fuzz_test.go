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
	"encoding/json"
	"io"
	"net/http"
	"strings"
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

// assertOwnerStamped fails unless the JSON object at path inside raw carries
// exactly one key folding to "Labels" and that object holds labelKey=owner.
func assertOwnerStamped(t *testing.T, raw []byte, labelKey, owner string, path []string) {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("stamped body is not a JSON object: %v: %s", err, raw)
	}
	cur := decoded
	for _, k := range path {
		next, ok := cur[k].(map[string]any)
		if !ok {
			t.Fatalf("missing object at %q in %s", k, raw)
		}
		cur = next
	}
	variants := 0
	for k := range cur {
		if strings.EqualFold(k, "Labels") {
			variants++
		}
	}
	if variants != 1 {
		t.Fatalf("%d keys fold to Labels, want 1: %s", variants, raw)
	}
	labels, ok := cur["Labels"].(map[string]any)
	if !ok || labels[labelKey] != owner {
		t.Fatalf("owner label not stamped: %s", raw)
	}
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
		req := makeBodyRequest(body)
		if err := addOwnerLabelToBody(req, "com.sockguard.owner", "fuzz-owner"); err != nil {
			return // errors are acceptable; the middleware denies on them
		}
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read stamped body: %v", err)
		}
		assertOwnerStamped(t, raw, "com.sockguard.owner", "fuzz-owner", nil)
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
		if err := addOwnerLabelToServiceBody(req, "com.sockguard.owner", "fuzz-owner"); err != nil {
			return // errors are acceptable; the middleware denies on them
		}
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read stamped body: %v", err)
		}
		assertOwnerStamped(t, raw, "com.sockguard.owner", "fuzz-owner", nil)
		assertOwnerStamped(t, raw, "com.sockguard.owner", "fuzz-owner", []string{"TaskTemplate", "ContainerSpec"})
	})
}
