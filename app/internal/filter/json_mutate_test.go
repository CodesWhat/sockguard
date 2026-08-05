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
}

func nestedMutationArrayBody(arrayDepth int) []byte {
	return []byte(`{"value":` + strings.Repeat("[", arrayDepth) + `0` + strings.Repeat("]", arrayDepth) + `}`)
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
