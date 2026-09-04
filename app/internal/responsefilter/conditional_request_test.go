package responsefilter

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestStripConditionalRequestHeadersRemovesEveryPrecondition pins the whole
// RFC 9110 §13.1 set, not just the two that produce a 304, and pins that
// nothing else on the request is touched.
func TestStripConditionalRequestHeadersRemovesEveryPrecondition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		field string
		value string
	}{
		{name: "if-none-match", field: "If-None-Match", value: `"upstream-etag"`},
		{name: "if-modified-since", field: "If-Modified-Since", value: "Wed, 03 Sep 2026 10:00:00 GMT"},
		{name: "if-match", field: "If-Match", value: `"upstream-etag"`},
		{name: "if-unmodified-since", field: "If-Unmodified-Since", value: "Wed, 03 Sep 2026 10:00:00 GMT"},
		{name: "if-range", field: "If-Range", value: `"upstream-etag"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			header := http.Header{}
			header.Set(tt.field, tt.value)
			header.Set("Accept", "application/json")
			header.Set("X-Registry-Auth", "keep-me")

			StripConditionalRequestHeaders(header)

			if got := header.Get(tt.field); got != "" {
				t.Fatalf("%s = %q after strip, want it removed", tt.field, got)
			}
			if got := header.Get("Accept"); got != "application/json" {
				t.Fatalf("Accept = %q, want the unrelated header untouched", got)
			}
			if got := header.Get("X-Registry-Auth"); got != "keep-me" {
				t.Fatalf("X-Registry-Auth = %q, want the unrelated header untouched", got)
			}
		})
	}
}

// TestStripConditionalRequestHeadersClearsAllAtOnce covers the real shape: a
// client that sends several preconditions in one request must not keep any of
// them, and a repeated header must lose every value rather than one.
func TestStripConditionalRequestHeadersClearsAllAtOnce(t *testing.T) {
	t.Parallel()

	header := http.Header{}
	header.Add("If-None-Match", `"a"`)
	header.Add("If-None-Match", `"b"`)
	header.Set("If-Modified-Since", "Wed, 03 Sep 2026 10:00:00 GMT")
	header.Set("If-Match", `"c"`)
	header.Set("If-Unmodified-Since", "Wed, 03 Sep 2026 10:00:00 GMT")
	header.Set("If-Range", `"d"`)

	StripConditionalRequestHeaders(header)

	if len(header) != 0 {
		t.Fatalf("header = %v, want every conditional header removed", header)
	}
}

// TestModifyResponseRefusesNotModified pins the second half of the fix: the
// strip means a daemon cannot answer 304, so one arriving anyway is an
// upstream this build does not recognize and the response is refused rather
// than relayed. It holds with redaction disabled too, because a client whose
// cached copy predates the current config is exactly the case the refusal
// exists for.
func TestModifyResponseRefusesNotModified(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		path   string
		opts   Options
	}{
		{name: "get container inspect", method: http.MethodGet, path: "/v1.53/containers/abc/json", opts: Options{RedactContainerEnv: true}},
		{name: "get container list", method: http.MethodGet, path: "/v1.53/containers/json", opts: Options{RedactMountPaths: true}},
		{name: "head container list", method: http.MethodHead, path: "/v1.53/containers/json", opts: Options{RedactMountPaths: true}},
		{name: "no redaction configured", method: http.MethodGet, path: "/v1.53/info", opts: Options{}},
		{name: "attestation statement", method: http.MethodGet, path: "/v1.53/images/app/attestations?statement=true", opts: Options{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := newNotModifiedResponseForTest(t, tt.method, tt.path)

			err := New(tt.opts).ModifyResponse(resp)
			if !errors.Is(err, ErrResponseRejected) {
				t.Fatalf("ModifyResponse() error = %v, want one wrapping ErrResponseRejected", err)
			}
			if !strings.Contains(err.Error(), "304") {
				t.Fatalf("ModifyResponse() error = %q, want it to name the 304", err)
			}
		})
	}
}

// TestModifyResponseStillPassesOtherBodilessStatuses is the control: only the
// revalidation status is refused. A 204 has no cached representation behind
// it, and a plain non-2xx is the daemon's own error.
func TestModifyResponseStillPassesOtherBodilessStatuses(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusNoContent, http.StatusNotFound, http.StatusResetContent} {
		resp := newNotModifiedResponseForTest(t, http.MethodGet, "/v1.53/containers/json")
		resp.StatusCode = status

		if err := New(Options{RedactContainerEnv: true}).ModifyResponse(resp); err != nil {
			t.Fatalf("ModifyResponse(status=%d) = %v, want nil", status, err)
		}
	}
}

// TestModifyResponsePassesThroughNonGetHeadNotModified pins the fix: a 304 on
// a method other than GET/HEAD is not a cache revalidation, it is an
// idempotency status the Docker Engine API (and Podman's compat/libpod APIs)
// document on POST .../start ("container already started") and POST
// .../stop ("container already stopped"). Rejecting those turned a correct
// no-op into a 502 for orchestrators and retry loops. Every redaction option
// is enabled to prove the pass-through does not depend on Enabled() being
// false.
func TestModifyResponsePassesThroughNonGetHeadNotModified(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
	}{
		{name: "start", path: "/containers/abc/start"},
		{name: "start versioned", path: "/v1.45/containers/abc/start"},
		{name: "stop", path: "/containers/abc/stop"},
		{name: "stop versioned", path: "/v1.45/containers/abc/stop"},
		{name: "libpod start", path: "/libpod/containers/abc/start"},
		{name: "libpod stop", path: "/libpod/containers/abc/stop"},
	}

	opts := Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
		RedactSensitiveData:   true,
		RedactHostTopology:    true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := newNotModifiedResponseForTest(t, http.MethodPost, tt.path)

			if err := New(opts).ModifyResponse(resp); err != nil {
				t.Fatalf("ModifyResponse() error = %v, want nil", err)
			}
			if resp.StatusCode != http.StatusNotModified {
				t.Fatalf("StatusCode = %d, want %d preserved", resp.StatusCode, http.StatusNotModified)
			}
		})
	}
}

func newNotModifiedResponseForTest(t *testing.T, method, path string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, "http://sockguard.test"+path, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	return &http.Response{
		StatusCode: http.StatusNotModified,
		Header:     http.Header{"Etag": []string{`"upstream"`}},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}
}
