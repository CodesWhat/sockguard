package filter

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseMutationDocumentRejectsJSONAmbiguityCorpus(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "exact duplicate at root", body: `{"Image":"alpine","Image":"busybox"}`, want: "duplicate JSON object key"},
		{name: "exact duplicate nested", body: `{"HostConfig":{"Privileged":false,"Privileged":true}}`, want: "duplicate JSON object key"},
		{name: "exact duplicate in array", body: `{"Items":[{"Name":"a","Name":"b"}]}`, want: "duplicate JSON object key"},
		{name: "folded duplicate at root", body: `{"Image":"alpine","image":"busybox"}`, want: "duplicate case-variant JSON keys"},
		{name: "folded duplicate nested", body: `{"HostConfig":{"Privileged":false,"privileged":true}}`, want: "duplicate case-variant JSON keys"},
		{name: "folded duplicate in array", body: `{"Items":[{"TaskTemplate":{},"tasktemplate":{}}]}`, want: "duplicate case-variant JSON keys"},
		{name: "exact duplicate case-sensitive label", body: `{"Labels":{"Foo":"one","Foo":"two"}}`, want: "duplicate JSON object key"},
		{name: "trailing object", body: `{"Image":"alpine"} {"Image":"busybox"}`, want: "trailing data"},
		{name: "trailing scalar", body: `{"Image":"alpine"} true`, want: "trailing data"},
		{name: "null root", body: `null`, want: "single non-null JSON object"},
		{name: "array root", body: `[{"Image":"alpine"}]`, want: "single non-null JSON object"},
		{name: "scalar root", body: `"object"`, want: "single non-null JSON object"},
		{name: "empty body", body: ``, want: "decode json"},
		{name: "truncated after key", body: `{"Image":`, want: "decode json"},
		{name: "truncated mid-object", body: `{"Image":"alpine",`, want: "decode json"},
		{name: "unterminated object", body: `{"Image":"alpine"`, want: "decode json"},
		{name: "unterminated array", body: `{"Items":["a"`, want: "decode json"},
		{name: "garbage after value", body: `{"Image":"alpine"} #not-json`, want: "decode json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseMutationDocument([]byte(tt.body), mutationMaxNodes(len(tt.body)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("parseMutationDocument() error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestParseMutationDocumentAllowsCaseSensitiveDataMapKeys(t *testing.T) {
	body := []byte(`{
		"Labels":{"Foo":"one","foo":"two"},
		"HostConfig":{"Sysctls":{"Net.Core.Somaxconn":"1","net.core.somaxconn":"2"}},
		"TaskTemplate":{"ContainerSpec":{"Labels":{"Team":"platform","team":"runtime"}}}
	}`)
	doc, err := parseMutationDocument(body, mutationMaxNodes(len(body)))
	if err != nil {
		t.Fatalf("parseMutationDocument() error = %v, want case-sensitive map keys allowed", err)
	}
	labels, _ := doc["Labels"].(map[string]any)
	if labels["Foo"] != "one" || labels["foo"] != "two" {
		t.Fatalf("Labels = %#v, want both Foo and foo preserved", labels)
	}
}

func TestParseMutationDocumentDepthAndNodeCaps(t *testing.T) {
	t.Run("depth at cap accepted", func(t *testing.T) {
		body := nestedMutationArrayBody(mutationMaxDepth - 1)
		if _, err := parseMutationDocument(body, mutationMaxNodes(len(body))); err != nil {
			t.Fatalf("parseMutationDocument() at depth cap error = %v", err)
		}
	})

	t.Run("depth overflow rejected", func(t *testing.T) {
		body := nestedMutationArrayBody(mutationMaxDepth)
		_, err := parseMutationDocument(body, mutationMaxNodes(len(body)))
		if err == nil || !strings.Contains(err.Error(), "max depth") {
			t.Fatalf("parseMutationDocument() error = %v, want max-depth rejection", err)
		}
	})

	t.Run("node overflow rejected", func(t *testing.T) {
		body := []byte(`{"a":1,"b":2,"c":3}`)
		_, err := parseMutationDocument(body, 2)
		if err == nil || !strings.Contains(err.Error(), "node count cap") {
			t.Fatalf("parseMutationDocument() error = %v, want node-cap rejection", err)
		}
	})

	t.Run("object depth overflow rejected", func(t *testing.T) {
		// Same cap as the array-depth case above, but nesting through
		// object members (scanJSONObjectMembers's own depth check) rather
		// than array elements (scanJSONArrayElements's), since the two are
		// separate recursive functions each with their own guard.
		body := nestedMutationObjectBody(mutationMaxDepth + 1)
		_, err := parseMutationDocument(body, mutationMaxNodes(len(body)))
		if err == nil || !strings.Contains(err.Error(), "max depth") {
			t.Fatalf("parseMutationDocument() error = %v, want max-depth rejection", err)
		}
	})

	t.Run("array element node overflow rejected", func(t *testing.T) {
		// Distinct from "node overflow rejected" above: this trips the node
		// cap while scanning array elements (scanJSONArrayElements), not
		// object members (scanJSONObjectMembers).
		body := []byte(`{"a":[1,2,3]}`)
		_, err := parseMutationDocument(body, 3)
		if err == nil || !strings.Contains(err.Error(), "node count cap") {
			t.Fatalf("parseMutationDocument() error = %v, want node-cap rejection", err)
		}
	})

	t.Run("object depth exactly at cap accepted", func(t *testing.T) {
		// Mirrors "depth at cap accepted" above but nests through object
		// members (scanJSONObjectMembers's own depth guard at json_mutate.go
		// line 121) rather than array elements, since the two are separate
		// recursive functions each with their own > mutationMaxDepth check.
		// A boundary mutant (> -> >=) would reject this exact-cap body one
		// level too early.
		body := nestedMutationObjectBody(mutationMaxDepth)
		if _, err := parseMutationDocument(body, mutationMaxNodes(len(body))); err != nil {
			t.Fatalf("parseMutationDocument() at object depth cap error = %v", err)
		}
	})

	t.Run("node count exactly at cap accepted", func(t *testing.T) {
		// incrementJSONNodeCount's cap check (json_mutate.go line 192) must
		// accept a node count exactly equal to maxNodes and only reject once
		// it goes strictly over. A boundary mutant (> -> >=) would reject
		// the second (cap-reaching) key instead of only a third.
		body := []byte(`{"a":1,"b":2}`)
		if _, err := parseMutationDocument(body, 2); err != nil {
			t.Fatalf("parseMutationDocument() at node cap error = %v", err)
		}
	})
}

// TestMutationMaxNodes pins mutationMaxNodes' exact arithmetic (bodyLen+1).
// An ARITHMETIC_BASE mutant (+ -> -) would return bodyLen-1 instead, which
// this direct value assertion catches immediately.
func TestMutationMaxNodes(t *testing.T) {
	tests := []struct {
		bodyLen int
		want    int64
	}{
		{bodyLen: 0, want: 1},
		{bodyLen: 5, want: 6},
		{bodyLen: 100, want: 101},
	}
	for _, tt := range tests {
		if got := mutationMaxNodes(tt.bodyLen); got != tt.want {
			t.Errorf("mutationMaxNodes(%d) = %d, want %d", tt.bodyLen, got, tt.want)
		}
	}
}

func nestedMutationArrayBody(arrayDepth int) []byte {
	return []byte(`{"value":` + strings.Repeat("[", arrayDepth) + `0` + strings.Repeat("]", arrayDepth) + `}`)
}

func nestedMutationObjectBody(objectDepth int) []byte {
	return []byte(strings.Repeat(`{"a":`, objectDepth) + `0` + strings.Repeat(`}`, objectDepth))
}

func TestMutationSerializationPreservesNumericLexemesAndStringValues(t *testing.T) {
	original := []byte(`{
		"Image":"alpine:3.21",
		"HostConfig":{"Memory":9223372036854775807,"NanoCpus":9.007199254740993e+20,"CpuQuota":1e+09},
		"Labels":{"payload":"{\"Privileged\":true}","array":"[1,2,3]"}
	}`)
	doc, err := parseMutationDocument(original, mutationMaxNodes(len(original)))
	if err != nil {
		t.Fatalf("parseMutationDocument() error = %v", err)
	}
	if outcome, err := applyInjectLabels(doc, mutationSurfaceContainerCreate, map[string]string{"mandatory": `"Privileged":true`}); err != nil || outcome != mutationOutcomeApplied {
		t.Fatalf("applyInjectLabels() = (%q, %v), want applied", outcome, err)
	}

	final, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, lexeme := range []string{"9223372036854775807", "9.007199254740993e+20", "1e+09"} {
		if !bytes.Contains(final, []byte(lexeme)) {
			t.Errorf("mutated body %s does not preserve numeric lexeme %q", final, lexeme)
		}
	}

	reparsed, err := parseMutationDocument(final, mutationMaxNodes(len(final)))
	if err != nil {
		t.Fatalf("reparse mutated body: %v", err)
	}
	labels := reparsed["Labels"].(map[string]any)
	if got := labels["payload"]; got != `{"Privileged":true}` {
		t.Fatalf("Labels.payload = %#v, want JSON-looking content to remain a string", got)
	}
	if got := labels["mandatory"]; got != `"Privileged":true` {
		t.Fatalf("Labels.mandatory = %#v, want injected JSON-looking content to remain a string", got)
	}
	hostConfig := reparsed["HostConfig"].(map[string]any)
	if _, exists := hostConfig["Privileged"]; exists {
		t.Fatalf("HostConfig = %#v, label value must never create a Privileged field", hostConfig)
	}
}

func TestReplaceRequestBodyResetsTransportState(t *testing.T) {
	oldBody := &mutationTrackingReadCloser{Reader: strings.NewReader("old")}
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	req.Body = oldBody
	req.ContentLength = 999
	req.TransferEncoding = []string{"chunked", "identity"}
	req.Header.Set("Content-Length", "999")
	req.Header.Set("Transfer-Encoding", "chunked")
	final := []byte(`{"Image":"mirror.example/alpine:3.21"}`)

	replaceRequestBody(req, final)

	if !oldBody.closed {
		t.Fatal("replaceRequestBody() did not close the old body")
	}
	if req.ContentLength != int64(len(final)) {
		t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(final))
	}
	if req.TransferEncoding != nil {
		t.Fatalf("TransferEncoding = %#v, want nil", req.TransferEncoding)
	}
	if got := req.Header.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length header = %q, want cleared", got)
	}
	if got := req.Header.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("Transfer-Encoding header = %q, want cleared", got)
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read replacement body: %v", err)
	}
	if !bytes.Equal(got, final) {
		t.Fatalf("forwarded body = %q, want %q", got, final)
	}
	if req.GetBody == nil {
		t.Fatal("GetBody = nil, want replay function")
	}
	replay, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody() error = %v", err)
	}
	replayed, err := io.ReadAll(replay)
	if err != nil {
		t.Fatalf("read GetBody: %v", err)
	}
	_ = replay.Close()
	if !bytes.Equal(replayed, final) {
		t.Fatalf("GetBody bytes = %q, want %q", replayed, final)
	}

	final[0] = '['
	replay, err = req.GetBody()
	if err != nil {
		t.Fatalf("GetBody() after caller mutation error = %v", err)
	}
	replayed, _ = io.ReadAll(replay)
	_ = replay.Close()
	if replayed[0] != '{' {
		t.Fatalf("GetBody aliased caller buffer: got %q", replayed)
	}
}

func TestDeepCloneJSONValueProducesIndependentCopy(t *testing.T) {
	original := map[string]any{
		"scalarString": "value",
		"scalarBool":   true,
		"scalarNil":    nil,
		"nested": map[string]any{
			"list": []any{"a", "b", map[string]any{"deep": "leaf"}},
		},
	}

	clone := deepCloneJSONValue(original).(map[string]any)

	nestedOriginal := original["nested"].(map[string]any)
	nestedClone := clone["nested"].(map[string]any)
	listOriginal := nestedOriginal["list"].([]any)
	listClone := nestedClone["list"].([]any)

	// Mutate the clone's nested map and array in place; the original must be
	// unaffected, proving both the map and []any recursive-copy branches ran
	// rather than aliasing the source.
	nestedClone["list"].([]any)[0] = "mutated"
	listClone[2].(map[string]any)["deep"] = "mutated"

	if listOriginal[0] != "a" {
		t.Fatalf("original array element = %#v, want untouched by clone mutation", listOriginal[0])
	}
	if listOriginal[2].(map[string]any)["deep"] != "leaf" {
		t.Fatalf("original nested map = %#v, want untouched by clone mutation", listOriginal[2])
	}
	if clone["scalarString"] != "value" || clone["scalarBool"] != true || clone["scalarNil"] != nil {
		t.Fatalf("clone scalars = %#v, want scalar leaves preserved as-is", clone)
	}
}

func TestFoldedHelpersMatchCaseInsensitivelyAndSkipWrongType(t *testing.T) {
	m := map[string]any{
		"Image":      "alpine:3.21",
		"image":      42, // wrong type: must be skipped, not panic
		"HostConfig": map[string]any{"Privileged": true},
		"hostconfig": "not-an-object",
		"Binds":      []any{"/host:/container"},
		"binds":      "not-an-array",
	}

	strs := FoldedStrings(m, "image")
	if len(strs) != 1 || strs[0] != "alpine:3.21" {
		t.Fatalf("FoldedStrings() = %#v, want exactly the one string-typed variant", strs)
	}

	objs := FoldedObjects(m, "hostconfig")
	if len(objs) != 1 || objs[0]["Privileged"] != true {
		t.Fatalf("FoldedObjects() = %#v, want exactly the one object-typed variant", objs)
	}

	arrs := FoldedArrays(m, "binds")
	if len(arrs) != 1 || len(arrs[0]) != 1 || arrs[0][0] != "/host:/container" {
		t.Fatalf("FoldedArrays() = %#v, want exactly the one array-typed variant", arrs)
	}

	if !FoldedStringEquals(m, "IMAGE", "alpine:3.21") {
		t.Fatal("FoldedStringEquals() = false, want true for a case-folded exact match")
	}
	if FoldedStringEquals(m, "IMAGE", "  alpine:3.21  ") {
		// want must already be trimmed by the caller: only the found value is trimmed.
		t.Fatal("FoldedStringEquals() = true, want false: want itself is not trimmed")
	}
	if FoldedStringEquals(m, "missing", "anything") {
		t.Fatal("FoldedStringEquals() = true, want false for an absent key")
	}
}

func TestSoleFoldedObjectMissingKeyReturnsNotOK(t *testing.T) {
	obj, ok := soleFoldedObject(map[string]any{"Other": map[string]any{}}, "TaskTemplate")
	if ok || obj != nil {
		t.Fatalf("soleFoldedObject(missing key) = (%#v, %v), want (nil, false)", obj, ok)
	}
}

func TestNavigateFoldedObjectPathStopsAtFirstAbsentLevel(t *testing.T) {
	doc := map[string]any{"TaskTemplate": map[string]any{}}
	got, ok := navigateFoldedObjectPath(doc, "TaskTemplate", "ContainerSpec")
	if ok || got != nil {
		t.Fatalf("navigateFoldedObjectPath() = (%#v, %v), want (nil, false) for an absent inner level", got, ok)
	}
}

func TestNestedObjectSkipsNilVariantAndMergesRemainingVariants(t *testing.T) {
	decoded := map[string]any{
		"Labels": nil,
		"labels": map[string]any{"team": "platform"},
	}
	merged, err := NestedObject(decoded, "Labels")
	if err != nil {
		t.Fatalf("NestedObject() error = %v", err)
	}
	if merged["team"] != "platform" {
		t.Fatalf("merged = %#v, want the non-nil variant's contents", merged)
	}
	if _, exists := decoded["labels"]; exists {
		t.Fatalf("decoded = %#v, want case-variant key removed", decoded)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded = %#v, want exactly one canonical key remaining", decoded)
	}
}

type mutationTrackingReadCloser struct {
	io.Reader
	closed bool
}

func (r *mutationTrackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func FuzzMutationRoundTrip(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"Image":"alpine:3.21","HostConfig":{"Memory":9223372036854775807}}`),
		[]byte(`{"Labels":{"Foo":"one","foo":"two"}}`),
		[]byte(`{"Image":"alpine:3.21","Labels":{"payload":"{\"Privileged\":true}"}}`),
		[]byte(`{"Image":"alpine:3.21","Image":"busybox"}`),
		[]byte(`{"Items":[{"Name":"a","Name":"b"}]}`),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, 64<<10)
		doc, err := parseMutationDocument(body, mutationMaxNodes(len(body)))
		if err != nil {
			return
		}
		if _, err := applyInjectLabels(doc, mutationSurfaceContainerCreate, map[string]string{"com.sockguard.fuzz": "fixed"}); err != nil {
			return
		}
		_, err = applyRemapImage(doc, mutationSurfaceContainerCreate, compiledMutationRule{
			kind:       mutationRuleRemapImage,
			remapMatch: "exact",
			remapFrom:  "alpine:3.21",
			remapTo:    "mirror.example/alpine:3.21",
		})
		if err != nil {
			return
		}
		final, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("forwardable document failed to marshal: %v", err)
		}
		if _, err := parseMutationDocument(final, mutationMaxNodes(len(final))); err != nil {
			t.Fatalf("forwardable document failed strict reparse: %v\ninput: %q\nfinal: %q", err, body, final)
		}
		if err := RejectDuplicateCaseVariantJSONKeys(final); err != nil {
			t.Fatalf("forwardable document retained folded ambiguity: %v\ninput: %q\nfinal: %q", err, body, final)
		}
	})
}
