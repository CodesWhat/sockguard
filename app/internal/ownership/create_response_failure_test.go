package ownership

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/filter"
	"github.com/codeswhat/sockguard/v2/app/internal/logging"
)

// createResponseCase drives one volume or native network create through the
// ownership middleware with a fake daemon and reports what the client saw.
type createResponseCase struct {
	path        string
	requestBody string
	rollout     string
	upstream    func(http.ResponseWriter)
}

func runCreateResponseCase(t *testing.T, tc createResponseCase) (*httptest.ResponseRecorder, *logging.RequestMeta, bool) {
	t.Helper()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := &recordingInspector{}
	forwarded := false
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		tc.upstream(w)
	}))
	meta := &logging.RequestMeta{RolloutMode: tc.rollout}
	req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.requestBody))
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, meta, forwarded
}

var createResponsePaths = []struct{ name, path, body string }{
	{"volume", "/volumes/create", `{"Name":"data"}`},
	{"native volume", "/libpod/volumes/create", `{"Name":"data"}`},
	{"native network", "/libpod/networks/create?ignoreIfExists=true", `{"name":"net"}`},
}

// TestCreateResponseOversizedFailsClosed pins that a create response larger
// than the buffer is never relayed: the client gets a 502 naming the size
// limit and none of the daemon's bytes.
func TestCreateResponseOversizedFailsClosed(t *testing.T) {
	t.Parallel()
	for _, p := range createResponsePaths {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			rec, meta, _ := runCreateResponseCase(t, createResponseCase{path: p.path, requestBody: p.body, upstream: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{"Labels":{"x":"`+strings.Repeat("s", filter.MaxResponseBodyBytes)+`"}}`)
			}})
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), ownerResponseTooLargeMessage) || strings.Contains(rec.Body.String(), "sssss") {
				t.Fatalf("body = %.200s, want the size refusal and no daemon bytes", rec.Body.String())
			}
			if meta.ReasonCode != reasonCodeOwnerResponseTooLarge {
				t.Fatalf("reason code = %q, want %q", meta.ReasonCode, reasonCodeOwnerResponseTooLarge)
			}
		})
	}
}

// TestCreateResponseUndecodableEncodingFailsClosed pins that a response whose
// declared Content-Encoding cannot be decoded is refused with 502 rather than
// relayed unchecked.
func TestCreateResponseUndecodableEncodingFailsClosed(t *testing.T) {
	t.Parallel()
	for _, p := range createResponsePaths {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			rec, meta, _ := runCreateResponseCase(t, createResponseCase{path: p.path, requestBody: p.body, upstream: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", "gzip")
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, "not gzip at all")
			}})
			if rec.Code != http.StatusBadGateway || meta.ReasonCode != reasonCodeOwnerResponseFilterFail {
				t.Fatalf("status = %d reason = %q, want 502 / %q", rec.Code, meta.ReasonCode, reasonCodeOwnerResponseFilterFail)
			}
			if rec.Header().Get("Content-Encoding") != "" {
				t.Fatalf("Content-Encoding = %q, want the upstream representation headers cleared", rec.Header().Get("Content-Encoding"))
			}
		})
	}
}

// TestCreateResponseForeignOwnerUnderWarnRollout pins the rollout contract: a
// foreign result is recorded as would_deny and relayed under warn and audit,
// and refused under enforce.
func TestCreateResponseForeignOwnerUnderWarnRollout(t *testing.T) {
	t.Parallel()
	for _, p := range createResponsePaths {
		for _, mode := range []string{"warn", "audit"} {
			t.Run(p.name+" "+mode, func(t *testing.T) {
				t.Parallel()
				rec, meta, _ := runCreateResponseCase(t, createResponseCase{path: p.path, requestBody: p.body, rollout: mode, upstream: func(w http.ResponseWriter) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_, _ = io.WriteString(w, `{"Labels":{"com.sockguard.owner":"job-999"},"labels":{"com.sockguard.owner":"job-999"}}`)
				}})
				if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), "job-999") {
					t.Fatalf("status = %d body = %s, want the response relayed", rec.Code, rec.Body.String())
				}
				if meta.Decision != "would_deny" || meta.ReasonCode != reasonCodeOwnerPolicyDeniedAccess {
					t.Fatalf("decision = %q reason code = %q, want would_deny / %q", meta.Decision, meta.ReasonCode, reasonCodeOwnerPolicyDeniedAccess)
				}
			})
		}
	}
}

// TestCreateRequestBodyThatCannotBeStampedIsRefused pins that a create whose
// labels field is not an object, or whose body is not JSON, is refused with
// 400 before the daemon is asked, since the owner label can't be written.
func TestCreateRequestBodyThatCannotBeStampedIsRefused(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, path, body string }{
		{"volume labels not an object", "/volumes/create", `{"Name":"data","Labels":"x"}`},
		{"native volume labels not an object", "/libpod/volumes/create", `{"Name":"data","Labels":["x"]}`},
		{"native network labels not an object", "/libpod/networks/create", `{"name":"net","labels":"x"}`},
		{"native network malformed body", "/libpod/networks/create", `{"name":`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec, meta, forwarded := runCreateResponseCase(t, createResponseCase{path: tc.path, requestBody: tc.body, upstream: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusCreated)
			}})
			if rec.Code != http.StatusBadRequest || forwarded {
				t.Fatalf("status = %d forwarded = %v, want 400 and no forward", rec.Code, forwarded)
			}
			if meta.ReasonCode != reasonCodeOwnerRequestInvalid {
				t.Fatalf("reason code = %q, want %q", meta.ReasonCode, reasonCodeOwnerRequestInvalid)
			}
		})
	}
}
