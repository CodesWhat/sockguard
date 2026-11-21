package filter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/logging"
)

// TestNewDockerNetworkInspectorTransportAndSizeFailures pins the two lookup
// failures the status checks don't reach: a transport error and a response
// body over the read bound. Both must be errors, never a "not found" that
// would let the guard skip the target.
func TestNewDockerNetworkInspectorTransportAndSizeFailures(t *testing.T) {
	down := networkRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("socket gone")
	})
	got, found, err := NewDockerNetworkInspectorWithRoundTripper(down)(context.Background(), "abc")
	if err == nil || found || got != (NetworkInspectResult{}) {
		t.Fatalf("transport error: got %+v found=%v err=%v, want an error and no result", got, found, err)
	}

	huge := networkRoundTripFunc(func(*http.Request) (*http.Response, error) {
		body := `{"Name":"host","Driver":"host","Pad":"` + strings.Repeat("x", MaxResponseBodyBytes) + `"}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	got, found, err = NewDockerNetworkInspectorWithRoundTripper(huge)(context.Background(), "abc")
	if err == nil || found || got != (NetworkInspectResult{}) {
		t.Fatalf("oversized body: got %+v found=%v err=%v, want an error and no result", got, found, err)
	}
}

// failingBody is a request body whose read fails partway.
type failingBody struct{ sent bool }

func (b *failingBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, `{"TaskTemplate":`), nil
	}
	return 0, errors.New("connection reset")
}

func (b *failingBody) Close() error { return nil }

// TestServiceNetworkGuardBodyFailuresFailClosed pins that the host-network
// guard never forwards a service write it could not read: an oversized body
// is a 413 and a read error a 400, in every rollout mode, and neither reaches
// the daemon.
func TestServiceNetworkGuardBodyFailuresFailClosed(t *testing.T) {
	inspect := func(context.Context, string) (NetworkInspectResult, bool, error) {
		t.Fatal("no network lookup expected for an unread body")
		return NetworkInspectResult{}, false, nil
	}
	cases := []struct {
		name       string
		body       func() io.ReadCloser
		wantStatus int
		wantCode   string
	}{
		{
			name: "oversized",
			body: func() io.ReadCloser {
				return io.NopCloser(strings.NewReader(`{"TaskTemplate":{"Networks":[{"Target":"` + strings.Repeat("n", maxServiceBodyBytes) + `"}]}}`))
			},
			wantStatus: http.StatusRequestEntityTooLarge,
			wantCode:   reasonCodeRequestBodyTooLarge,
		},
		{
			name:       "read error",
			body:       func() io.ReadCloser { return &failingBody{} },
			wantStatus: http.StatusBadRequest,
			wantCode:   reasonCodeRequestBodyInspectionFailed,
		},
	}
	for _, tc := range cases {
		for _, mode := range []string{"", "warn"} {
			t.Run(tc.name+" "+mode, func(t *testing.T) {
				opts := ResourceLimitGuardOptions{InspectNetwork: inspect}
				opts.DenyResponseVerbosity = DenyResponseVerbosityVerbose
				meta := &logging.RequestMeta{RolloutMode: mode}
				req := httptest.NewRequest(http.MethodPost, "/services/create", nil)
				req.Body = tc.body()
				req.ContentLength = -1
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec := httptest.NewRecorder()
				forwarded := false
				ResourceLimitGuardWithOptions(testLogger(), opts)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					forwarded = true
				})).ServeHTTP(rec, req)
				if rec.Code != tc.wantStatus || forwarded {
					t.Fatalf("status = %d forwarded = %v, want %d and no forward; body: %s", rec.Code, forwarded, tc.wantStatus, rec.Body.String())
				}
				if meta.ReasonCode != tc.wantCode {
					t.Fatalf("reason code = %q, want %q", meta.ReasonCode, tc.wantCode)
				}
			})
		}
	}
}

// TestServiceNetworkGuardRollbackOfUnknownServiceIsLeftToTheDaemon pins that
// a manual rollback naming a service the daemon doesn't know is forwarded
// without a network lookup, since the daemon answers 404 itself.
func TestServiceNetworkGuardRollbackOfUnknownServiceIsLeftToTheDaemon(t *testing.T) {
	opts := ResourceLimitGuardOptions{
		InspectService: func(context.Context, string) (ServiceInspectResult, bool, error) {
			return ServiceInspectResult{}, false, nil
		},
		InspectNetwork: func(context.Context, string) (NetworkInspectResult, bool, error) {
			t.Fatal("no network lookup expected for an unknown service")
			return NetworkInspectResult{}, false, nil
		},
	}
	out := runResourceGuardRequest(t, opts, http.MethodPost, "/services/ghost/update?version=3&rollback=previous", `{}`, "")
	if out.status != guardedRequestAllowedStatus || out.forwarded != 1 {
		t.Fatalf("status = %d forwarded = %d, want pass-through", out.status, out.forwarded)
	}
}

// TestResourceLimitGuardRollbackNetworkLookupFailureFailsClosed pins the
// requirement-owned rollback path: with a CPU requirement configured, the
// stored PreviousSpec's networks are resolved from the same service snapshot,
// and a failed network lookup refuses the rollback with 502 instead of
// forwarding it unchecked.
func TestResourceLimitGuardRollbackNetworkLookupFailureFailsClosed(t *testing.T) {
	out := runResourceGuardRequest(t, ResourceLimitGuardOptions{
		PolicyConfig: PolicyConfig{Service: ServiceOptions{RequireCPULimit: true}},
		InspectService: func(context.Context, string) (ServiceInspectResult, bool, error) {
			return ServiceInspectResult{Version: 7, HasPreviousSpec: true, PreviousSpecNanoCPUs: 1, PreviousSpecNetworkTargets: []string{"tenant-net"}}, true, nil
		},
		InspectNetwork: func(context.Context, string) (NetworkInspectResult, bool, error) {
			return NetworkInspectResult{}, false, errors.New("daemon down")
		},
	}, http.MethodPost, "/services/svc/update?version=7&rollback=previous", `{}`, "")
	if out.status != http.StatusBadGateway || out.forwarded != 0 {
		t.Fatalf("status = %d forwarded = %d, want 502 and no forward; body: %s", out.status, out.forwarded, out.body)
	}
	if out.meta.ReasonCode != reasonCodeResourceLimitPolicyLookupFailed {
		t.Fatalf("reason code = %q, want %q", out.meta.ReasonCode, reasonCodeResourceLimitPolicyLookupFailed)
	}
	if out.meta.ResourcePolicy == nil || out.meta.ResourcePolicy.Result != "lookup_failed" {
		t.Fatalf("resource metadata = %#v, want result lookup_failed", out.meta.ResourcePolicy)
	}
}

// TestContainerStartBodyReadErrorIsAnError pins that a start body the proxy
// could not read is reported as an error rather than admitted as empty.
func TestContainerStartBodyReadErrorIsAnError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/start", nil)
	req.Body = &failingBody{}
	req.ContentLength = -1
	reason, err := containerStartPolicy{}.inspect(nil, req, "/containers/abc/start")
	if err == nil || reason != "" {
		t.Fatalf("reason = %q err = %v, want a read error", reason, err)
	}
}
