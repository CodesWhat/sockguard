package responsefilter

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func allRedactOptions() Options {
	return Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
		RedactSensitiveData:   true,
	}
}

// Table-driven redaction is a read-side feature. A write on a path the table
// matches (DELETE /services/{id}, POST /services/create) carries an empty or
// non-resource body, and decoding it as the resource would reject or rewrite
// a response the daemon got right.
func TestTableRedactionSkipsNonGetMethods(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"delete service empty body", http.MethodDelete, "/services/svc-1", ""},
		{"delete node empty body", http.MethodDelete, "/nodes/node-1", ""},
		{"delete secret empty body", http.MethodDelete, "/secrets/sec-1", ""},
		{"delete config empty body", http.MethodDelete, "/configs/cfg-1", ""},
		{"post service create", http.MethodPost, "/services/create", `{"ID":"svc-1","Warnings":["w"]}`},
		{"post secret create", http.MethodPost, "/secrets/create", `{"ID":"sec-1"}`},
		{"post config create", http.MethodPost, "/configs/create", `{"ID":"cfg-1"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := New(allRedactOptions())
			resp := newResponseForTest(t, tc.method, tc.path, tc.body)
			if err := f.ModifyResponse(resp); err != nil {
				t.Fatalf("ModifyResponse() = %v, want nil", err)
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if string(got) != tc.body {
				t.Fatalf("body = %q, want untouched %q", got, tc.body)
			}
		})
	}
}

func TestTableRedactionRejectsEmptyBodyOnGet(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/services/svc-1", "/services", "/swarm"} {
		f := New(allRedactOptions())
		resp := newResponseForTest(t, http.MethodGet, path, "")
		if err := f.ModifyResponse(resp); err == nil {
			t.Fatalf("GET %s empty body: want rejection (fail closed), got nil", path)
		}
	}
}

func TestTableRedactionStillRedactsGet(t *testing.T) {
	t.Parallel()
	f := New(allRedactOptions())
	body := `{"ID":"svc-1","Spec":{"TaskTemplate":{"ContainerSpec":{"Env":["DB_PASS=secret"]}}}}`
	resp := newResponseForTest(t, http.MethodGet, "/services/svc-1", body)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(got), "DB_PASS=secret") {
		t.Fatalf("GET service env not redacted: %s", got)
	}
}
