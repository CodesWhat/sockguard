package filter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
)

const guardedRequestAllowedStatus = http.StatusNoContent

type resourceGuardOutcome struct {
	status        int
	body          string
	forwarded     int
	forwardedBody string
	meta          *logging.RequestMeta
}

func runResourceGuardRequest(t *testing.T, opts ResourceLimitGuardOptions, method, target, body, rolloutMode string) resourceGuardOutcome {
	t.Helper()

	opts.DenyResponseVerbosity = DenyResponseVerbosityVerbose
	meta := &logging.RequestMeta{RolloutMode: rolloutMode}
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	forwarded := 0
	forwardedBody := ""
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read forwarded body: %v", err)
		}
		forwardedBody = string(got)
		w.WriteHeader(guardedRequestAllowedStatus)
	})

	ResourceLimitGuardWithOptions(testLogger(), opts)(next).ServeHTTP(rec, req)
	return resourceGuardOutcome{
		status:        rec.Code,
		body:          rec.Body.String(),
		forwarded:     forwarded,
		forwardedBody: forwardedBody,
		meta:          meta,
	}
}

func int64Ptr(v int64) *int64 { return &v }

func TestResourceLimitGuardContainerUpdateMatrix(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		options       ContainerUpdateOptions
		current       ContainerUpdateInspectResult
		wantStatus    int
		wantViolation string
		wantResult    string
	}{
		{
			name:       "memory omitted preserves compliant current state",
			body:       `{}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true},
			current:    ContainerUpdateInspectResult{Memory: 512 << 20},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "memory explicit zero is a daemon no-op",
			body:       `{"Memory":0}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true},
			current:    ContainerUpdateInspectResult{Memory: 512 << 20},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "memory null is unchanged",
			body:       `{"Memory":null}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true},
			current:    ContainerUpdateInspectResult{Memory: 512 << 20},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:          "memory zero cannot fabricate compliance for weak current state",
			body:          `{"Memory":0}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "memory",
			wantResult:    "deny",
		},
		{
			name:          "memory null cannot fabricate compliance for weak current state",
			body:          `{"Memory":null}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "memory",
			wantResult:    "deny",
		},
		{
			name:          "memory negative applies and denies",
			body:          `{"Memory":-1}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true},
			current:       ContainerUpdateInspectResult{Memory: 512 << 20},
			wantStatus:    http.StatusForbidden,
			wantViolation: "memory",
			wantResult:    "deny",
		},
		{
			name:       "memory weaker but positive is allowed",
			body:       `{"Memory":268435456}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true},
			current:    ContainerUpdateInspectResult{Memory: 512 << 20},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "memory stronger is allowed",
			body:       `{"Memory":1073741824}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true},
			current:    ContainerUpdateInspectResult{Memory: 512 << 20},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:          "memory ratchet denies omission on weak legacy container",
			body:          `{"RestartPolicy":{"Name":"no"}}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true},
			current:       ContainerUpdateInspectResult{Memory: 0},
			wantStatus:    http.StatusForbidden,
			wantViolation: "memory",
			wantResult:    "deny",
		},
		{
			name:       "memory ratchet accepts one compliant remediation",
			body:       `{"Memory":134217728}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true},
			current:    ContainerUpdateInspectResult{Memory: 0},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "soft cpu omitted preserves CpuShares",
			body:       `{}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimit: true},
			current:    ContainerUpdateInspectResult{CpuShares: 128},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "soft cpu scalar zero is unchanged",
			body:       `{"CpuShares":0}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimit: true},
			current:    ContainerUpdateInspectResult{CpuQuota: 50000},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "soft cpu null is unchanged",
			body:       `{"CpuQuota":null}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimit: true},
			current:    ContainerUpdateInspectResult{NanoCpus: 500000000},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:          "soft cpu zero cannot fabricate compliance for weak current state",
			body:          `{"CpuShares":0}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimit: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "cpu",
			wantResult:    "deny",
		},
		{
			name:          "soft cpu null cannot fabricate compliance for weak current state",
			body:          `{"CpuQuota":null}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimit: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "cpu",
			wantResult:    "deny",
		},
		{
			name:          "soft cpu negative alone denies",
			body:          `{"CpuShares":-2}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimit: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "cpu",
			wantResult:    "deny",
		},
		{
			name:       "soft cpu CpuPeriod alone satisfies",
			body:       `{"CpuPeriod":100000}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimit: true},
			current:    ContainerUpdateInspectResult{},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "soft cpu CpuShares alone satisfies",
			body:       `{"CpuShares":2}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimit: true},
			current:    ContainerUpdateInspectResult{},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "soft cpu weak positive remains compliant",
			body:       `{"CpuQuota":1}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimit: true},
			current:    ContainerUpdateInspectResult{CpuQuota: 50000},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "soft cpu stronger remains compliant",
			body:       `{"NanoCpus":2000000000}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimit: true},
			current:    ContainerUpdateInspectResult{NanoCpus: 500000000},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:          "soft cpu ratchet omission denies weak legacy container",
			body:          `{}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimit: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "cpu",
			wantResult:    "deny",
		},
		{
			name:       "soft cpu ratchet patch remediates weak legacy container",
			body:       `{"CpuShares":2}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimit: true},
			current:    ContainerUpdateInspectResult{},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "hard cpu omitted preserves CpuQuota",
			body:       `{}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimitHard: true},
			current:    ContainerUpdateInspectResult{CpuQuota: 50000},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "hard cpu zero is unchanged",
			body:       `{"CpuQuota":0}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimitHard: true},
			current:    ContainerUpdateInspectResult{CpuQuota: 50000},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "hard cpu null is unchanged",
			body:       `{"NanoCpus":null}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimitHard: true},
			current:    ContainerUpdateInspectResult{NanoCpus: 500000000},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:          "hard cpu zero cannot fabricate compliance for weak current state",
			body:          `{"CpuQuota":0}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimitHard: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "hard_cpu",
			wantResult:    "deny",
		},
		{
			name:          "hard cpu null cannot fabricate compliance for weak current state",
			body:          `{"NanoCpus":null}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimitHard: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "hard_cpu",
			wantResult:    "deny",
		},
		{
			name:          "hard cpu negative alone denies",
			body:          `{"CpuQuota":-1}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimitHard: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "hard_cpu",
			wantResult:    "deny",
		},
		{
			name:          "hard cpu CpuShares alone does not satisfy",
			body:          `{"CpuShares":1024}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimitHard: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "hard_cpu",
			wantResult:    "deny",
		},
		{
			name:          "hard cpu CpuPeriod alone does not satisfy",
			body:          `{"CpuPeriod":100000}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimitHard: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "hard_cpu",
			wantResult:    "deny",
		},
		{
			name:       "hard cpu CpuQuota alone satisfies",
			body:       `{"CpuQuota":1}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimitHard: true},
			current:    ContainerUpdateInspectResult{},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "hard cpu NanoCpus alone satisfies",
			body:       `{"NanoCpus":1}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireCPULimitHard: true},
			current:    ContainerUpdateInspectResult{},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "pids omitted preserves compliant current state",
			body:       `{}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequirePidsLimit: true},
			current:    ContainerUpdateInspectResult{PidsLimit: int64Ptr(64)},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "pids null is unchanged",
			body:       `{"PidsLimit":null}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequirePidsLimit: true},
			current:    ContainerUpdateInspectResult{PidsLimit: int64Ptr(64)},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:          "pids null follows weak current state",
			body:          `{"PidsLimit":null}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequirePidsLimit: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "pids",
			wantResult:    "deny",
		},
		{
			name:          "pids zero applies clear and denies",
			body:          `{"PidsLimit":0}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequirePidsLimit: true},
			current:       ContainerUpdateInspectResult{PidsLimit: int64Ptr(64)},
			wantStatus:    http.StatusForbidden,
			wantViolation: "pids",
			wantResult:    "deny",
		},
		{
			name:          "pids minus one applies clear and denies",
			body:          `{"PidsLimit":-1}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequirePidsLimit: true},
			current:       ContainerUpdateInspectResult{PidsLimit: int64Ptr(64)},
			wantStatus:    http.StatusForbidden,
			wantViolation: "pids",
			wantResult:    "deny",
		},
		{
			name:          "pids other negative denies",
			body:          `{"PidsLimit":-2}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequirePidsLimit: true},
			current:       ContainerUpdateInspectResult{PidsLimit: int64Ptr(64)},
			wantStatus:    http.StatusForbidden,
			wantViolation: "pids",
			wantResult:    "deny",
		},
		{
			name:       "pids weaker but positive is allowed",
			body:       `{"PidsLimit":1024}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequirePidsLimit: true},
			current:    ContainerUpdateInspectResult{PidsLimit: int64Ptr(64)},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "pids stronger but positive is allowed",
			body:       `{"PidsLimit":1}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequirePidsLimit: true},
			current:    ContainerUpdateInspectResult{PidsLimit: int64Ptr(64)},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:          "pids ratchet omission denies weak legacy container",
			body:          `{}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequirePidsLimit: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "pids",
			wantResult:    "deny",
		},
		{
			name:       "pids ratchet patch remediates weak legacy container",
			body:       `{"PidsLimit":64}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequirePidsLimit: true},
			current:    ContainerUpdateInspectResult{},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "mixed safe fields all pass",
			body:       `{"Memory":268435456,"CpuQuota":25000,"PidsLimit":32}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true, RequireCPULimit: true, RequireCPULimitHard: true, RequirePidsLimit: true},
			current:    ContainerUpdateInspectResult{},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:       "mixed update validates omitted memory and explicit CPU independently",
			body:       `{"NanoCpus":1000000000}`,
			options:    ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true, RequireCPULimitHard: true},
			current:    ContainerUpdateInspectResult{Memory: 512 << 20},
			wantStatus: guardedRequestAllowedStatus,
			wantResult: "allow",
		},
		{
			name:          "mixed update reports first violation in stable order",
			body:          `{"Memory":-1,"CpuQuota":-1,"PidsLimit":-1}`,
			options:       ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true, RequireCPULimit: true, RequireCPULimitHard: true, RequirePidsLimit: true},
			current:       ContainerUpdateInspectResult{},
			wantStatus:    http.StatusForbidden,
			wantViolation: "memory",
			wantResult:    "deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			out := runResourceGuardRequest(t, ResourceLimitGuardOptions{
				PolicyConfig: PolicyConfig{ContainerUpdate: tt.options},
				InspectContainer: func(_ context.Context, id string) (ContainerUpdateInspectResult, bool, error) {
					calls++
					if id != "legacy" {
						t.Fatalf("inspect id = %q, want legacy", id)
					}
					return tt.current, true, nil
				},
			}, http.MethodPost, "/v1.52/containers/legacy/update", tt.body, "")

			if out.status != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", out.status, tt.wantStatus, out.body)
			}
			if calls != 1 {
				t.Fatalf("inspect calls = %d, want 1", calls)
			}
			wantForwarded := 0
			if tt.wantStatus == guardedRequestAllowedStatus {
				wantForwarded = 1
				if out.forwardedBody != tt.body {
					t.Fatalf("forwarded body = %q, want original %q", out.forwardedBody, tt.body)
				}
			}
			if out.forwarded != wantForwarded {
				t.Fatalf("forwarded = %d, want %d", out.forwarded, wantForwarded)
			}
			if out.meta.ResourcePolicy == nil {
				t.Fatal("ResourcePolicy metadata is nil after evaluation")
			}
			if got := out.meta.ResourcePolicy.Result; got != tt.wantResult {
				t.Fatalf("resource result = %q, want %q", got, tt.wantResult)
			}
			if got := out.meta.ResourcePolicy.Violation; got != tt.wantViolation {
				t.Fatalf("violation = %q, want %q", got, tt.wantViolation)
			}
			if !out.meta.ResourcePolicy.StateLookup {
				t.Fatal("StateLookup = false, want true")
			}
		})
	}
}

func TestResourceLimitGuardContainerUpdateReadsRootFieldsOnly(t *testing.T) {
	tests := []struct {
		name    string
		current int64
		want    int
	}{
		{name: "compliant current", current: 128 << 20, want: guardedRequestAllowedStatus},
		{name: "weak current", current: 0, want: http.StatusForbidden},
	}
	decoys := []string{
		`{"HostConfig":{"Memory":999999999}}`,
		`{"Resources":{"Memory":999999999}}`,
		`{"HostConfig":{"Resources":{"Memory":999999999}}}`,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := ResourceLimitGuardOptions{
				PolicyConfig: PolicyConfig{ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true}},
				InspectContainer: func(context.Context, string) (ContainerUpdateInspectResult, bool, error) {
					return ContainerUpdateInspectResult{Memory: tt.current}, true, nil
				},
			}
			absent := runResourceGuardRequest(t, opts, http.MethodPost, "/containers/c/update", `{}`, "")
			if absent.status != tt.want {
				t.Fatalf("absent status = %d, want %d", absent.status, tt.want)
			}
			for _, decoy := range decoys {
				got := runResourceGuardRequest(t, opts, http.MethodPost, "/containers/c/update", decoy, "")
				if got.status != absent.status || got.meta.ReasonCode != absent.meta.ReasonCode || got.meta.ResourcePolicy.Violation != absent.meta.ResourcePolicy.Violation {
					t.Fatalf("decoy %s outcome = status %d code %q violation %q, absent = status %d code %q violation %q",
						decoy, got.status, got.meta.ReasonCode, got.meta.ResourcePolicy.Violation,
						absent.status, absent.meta.ReasonCode, absent.meta.ResourcePolicy.Violation)
				}
			}
		})
	}
}

func TestResourceLimitGuardContainerUpdateRejectsAmbiguousAndInvalidNumbers(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "case variant duplicate", body: `{"Memory":1,"memory":2}`},
		{name: "nested case variant duplicate", body: `{"HostConfig":{"Memory":1,"memory":2}}`},
		{name: "fraction", body: `{"Memory":1.5}`},
		{name: "string", body: `{"Memory":"1"}`},
		{name: "object", body: `{"Memory":{"value":1}}`},
		{name: "overflow", body: `{"Memory":9223372036854775808}`},
		{name: "non object array", body: `[]`},
		{name: "non object scalar", body: `1`},
		{name: "truncated", body: `{"Memory":1`},
		{name: "empty", body: ``},
		{name: "null body", body: `null`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspectCalls := 0
			out := runResourceGuardRequest(t, ResourceLimitGuardOptions{
				PolicyConfig: PolicyConfig{ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true}},
				InspectContainer: func(context.Context, string) (ContainerUpdateInspectResult, bool, error) {
					inspectCalls++
					return ContainerUpdateInspectResult{Memory: 1}, true, nil
				},
			}, http.MethodPost, "/containers/strict/update", tt.body, "")

			if out.status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", out.status, out.body)
			}
			if out.meta.ReasonCode != reasonCodeResourceLimitRequestInvalid {
				t.Fatalf("reason code = %q, want %q", out.meta.ReasonCode, reasonCodeResourceLimitRequestInvalid)
			}
			if inspectCalls != 0 {
				t.Fatalf("inspect calls = %d, want 0 for invalid request", inspectCalls)
			}
			if out.forwarded != 0 {
				t.Fatalf("forwarded = %d, want 0", out.forwarded)
			}
			if out.meta.ResourcePolicy == nil || out.meta.ResourcePolicy.Result != "invalid" {
				t.Fatalf("resource metadata = %#v, want invalid", out.meta.ResourcePolicy)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func dockerInspectResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestResourceLimitGuardContainerInspectFailuresFailClosed(t *testing.T) {
	tests := []struct {
		name        string
		transport   roundTripFunc
		wantStatus  int
		wantCode    string
		wantResult  string
		wantForward int
	}{
		{
			name: "not found passes through",
			transport: func(*http.Request) (*http.Response, error) {
				return dockerInspectResponse(http.StatusNotFound, `{}`), nil
			},
			wantStatus:  guardedRequestAllowedStatus,
			wantResult:  "allow",
			wantForward: 1,
		},
		{
			name: "daemon 500",
			transport: func(*http.Request) (*http.Response, error) {
				return dockerInspectResponse(http.StatusInternalServerError, `daemon failed`), nil
			},
			wantStatus: http.StatusBadGateway,
			wantCode:   reasonCodeResourceLimitPolicyLookupFailed,
			wantResult: "lookup_failed",
		},
		{
			name: "timeout",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, context.DeadlineExceeded
			},
			wantStatus: http.StatusBadGateway,
			wantCode:   reasonCodeResourceLimitPolicyLookupFailed,
			wantResult: "lookup_failed",
		},
		{
			name: "malformed json",
			transport: func(*http.Request) (*http.Response, error) {
				return dockerInspectResponse(http.StatusOK, `{"HostConfig":`), nil
			},
			wantStatus: http.StatusBadGateway,
			wantCode:   reasonCodeResourceLimitPolicyLookupFailed,
			wantResult: "lookup_failed",
		},
		{
			name: "body exactly one byte over cap",
			transport: func(*http.Request) (*http.Response, error) {
				return dockerInspectResponse(http.StatusOK, strings.Repeat("x", MaxResponseBodyBytes+1)), nil
			},
			wantStatus: http.StatusBadGateway,
			wantCode:   reasonCodeResourceLimitPolicyLookupFailed,
			wantResult: "lookup_failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspectRequests := 0
			rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				inspectRequests++
				if r.Method != http.MethodGet || r.URL.EscapedPath() != "/containers/lookup/json" {
					t.Fatalf("inspect request = %s %s, want GET /containers/lookup/json", r.Method, r.URL.EscapedPath())
				}
				return tt.transport(r)
			})
			out := runResourceGuardRequest(t, ResourceLimitGuardOptions{
				PolicyConfig:     PolicyConfig{ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true}},
				InspectContainer: NewDockerContainerUpdateInspectorWithRoundTripper(rt),
			}, http.MethodPost, "/containers/lookup/update", `{}`, "")

			if out.status != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", out.status, tt.wantStatus, out.body)
			}
			if out.meta.ReasonCode != tt.wantCode {
				t.Fatalf("reason code = %q, want %q", out.meta.ReasonCode, tt.wantCode)
			}
			if out.forwarded != tt.wantForward {
				t.Fatalf("forwarded update requests = %d, want %d", out.forwarded, tt.wantForward)
			}
			if inspectRequests != 1 {
				t.Fatalf("inspect requests = %d, want 1", inspectRequests)
			}
			if out.meta.ResourcePolicy == nil || out.meta.ResourcePolicy.Result != tt.wantResult {
				t.Fatalf("resource metadata = %#v, want result %q", out.meta.ResourcePolicy, tt.wantResult)
			}
		})
	}
}

func TestDockerContainerInspectorAcceptsResponseAtExactCap(t *testing.T) {
	prefix := `{"HostConfig":{"Memory":1}}`
	body := prefix + strings.Repeat(" ", MaxResponseBodyBytes-len(prefix))
	inspector := NewDockerContainerUpdateInspectorWithRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return dockerInspectResponse(http.StatusOK, body), nil
	}))

	got, found, err := inspector(context.Background(), "bounded")
	if err != nil {
		t.Fatalf("inspect at exact cap: %v", err)
	}
	if !found || got.Memory != 1 {
		t.Fatalf("inspect = (%#v, %v), want Memory=1 found=true", got, found)
	}
}

func TestResourceLimitGuardContainerInspectorNilFailsClosed(t *testing.T) {
	out := runResourceGuardRequest(t, ResourceLimitGuardOptions{
		PolicyConfig: PolicyConfig{ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true}},
	}, http.MethodPost, "/containers/unwired/update", `{}`, "")

	if out.status != http.StatusBadGateway || out.meta.ReasonCode != reasonCodeResourceLimitPolicyLookupFailed {
		t.Fatalf("outcome = status %d code %q, want 502/%s", out.status, out.meta.ReasonCode, reasonCodeResourceLimitPolicyLookupFailed)
	}
	if out.forwarded != 0 {
		t.Fatalf("forwarded = %d, want 0", out.forwarded)
	}
}

func TestResourceLimitGuardGateCoupling(t *testing.T) {
	allowUpdate, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/*/update", Action: ActionAllow})
	if err != nil {
		t.Fatalf("compile allow rule: %v", err)
	}
	denyAll, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny})
	if err != nil {
		t.Fatalf("compile deny rule: %v", err)
	}
	policy := PolicyConfig{
		DenyResponseVerbosity: DenyResponseVerbosityVerbose,
		ContainerUpdate: ContainerUpdateOptions{
			AllowResourceUpdates: false,
			RequireMemoryLimit:   true,
		},
	}
	guard := ResourceLimitGuardWithOptions(testLogger(), ResourceLimitGuardOptions{
		PolicyConfig: policy,
		InspectContainer: func(context.Context, string) (ContainerUpdateInspectResult, bool, error) {
			panic("resource inspector must not run while allow_resource_updates is false")
		},
	})
	upstreamCalls := 0
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(guardedRequestAllowedStatus)
	})
	handler := MiddlewareWithOptions([]*CompiledRule{allowUpdate, denyAll}, testLogger(), Options{PolicyConfig: policy})(guard(upstream))

	t.Run("blanket resource update denial remains authoritative", func(t *testing.T) {
		meta := &logging.RequestMeta{}
		req := httptest.NewRequest(http.MethodPost, "/containers/c/update", strings.NewReader(`{"Memory":1}`))
		req = req.WithContext(logging.WithMeta(req.Context(), meta))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body.String())
		}
		if meta.ReasonCode != reasonCodeRequestBodyPolicyDenied {
			t.Fatalf("reason code = %q, want existing %q", meta.ReasonCode, reasonCodeRequestBodyPolicyDenied)
		}
		if meta.ResourcePolicy != nil {
			t.Fatalf("ResourcePolicy = %#v, want nil because guard never ran", meta.ResourcePolicy)
		}
	})

	t.Run("non resource update passes without ratchet lookup", func(t *testing.T) {
		meta := &logging.RequestMeta{}
		req := httptest.NewRequest(http.MethodPost, "/containers/c/update", strings.NewReader(`{}`))
		req = req.WithContext(logging.WithMeta(req.Context(), meta))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != guardedRequestAllowedStatus {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, guardedRequestAllowedStatus, rec.Body.String())
		}
		if meta.ResourcePolicy != nil {
			t.Fatalf("ResourcePolicy = %#v, want nil because guard was gated off", meta.ResourcePolicy)
		}
	})

	if upstreamCalls != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls)
	}
}

func TestResourceLimitGuardNoRequirementsIsPurePassThrough(t *testing.T) {
	tests := []struct {
		name   string
		target string
		body   string
	}{
		{name: "container", target: "/containers/c/update", body: `not-json-at-all`},
		{name: "service", target: "/services/create", body: `not-json-at-all`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runResourceGuardRequest(t, ResourceLimitGuardOptions{
				PolicyConfig: PolicyConfig{ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true}},
				InspectContainer: func(context.Context, string) (ContainerUpdateInspectResult, bool, error) {
					panic("container inspect must not run with no requirements")
				},
				InspectService: func(context.Context, string) (ServiceInspectResult, bool, error) {
					panic("service inspect must not run with no requirements")
				},
			}, http.MethodPost, tt.target, tt.body, "")

			if out.status != guardedRequestAllowedStatus || out.forwarded != 1 || out.forwardedBody != tt.body {
				t.Fatalf("pass-through = status %d forwarded %d body %q", out.status, out.forwarded, out.forwardedBody)
			}
			if out.meta.ResourcePolicy != nil {
				t.Fatalf("ResourcePolicy = %#v, want nil", out.meta.ResourcePolicy)
			}
		})
	}
}

func TestResourceLimitGuardServiceCreateAndOrdinaryUpdateMatrix(t *testing.T) {
	tests := []struct {
		name             string
		target           string
		body             string
		service          ServiceOptions
		wantStatus       int
		wantOperation    string
		wantRequirements string
	}{
		{name: "create soft missing resources", target: "/services/create", body: `{"TaskTemplate":{}}`, service: ServiceOptions{RequireCPULimit: true}, wantStatus: http.StatusForbidden, wantOperation: "create", wantRequirements: "cpu"},
		{name: "create soft zero", target: "/services/create", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":0}}}}`, service: ServiceOptions{RequireCPULimit: true}, wantStatus: http.StatusForbidden, wantOperation: "create", wantRequirements: "cpu"},
		{name: "create soft negative", target: "/services/create", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":-1}}}}`, service: ServiceOptions{RequireCPULimit: true}, wantStatus: http.StatusForbidden, wantOperation: "create", wantRequirements: "cpu"},
		{name: "create soft reservation only", target: "/services/create", body: `{"TaskTemplate":{"Resources":{"Reservations":{"NanoCPUs":1000000000}}}}`, service: ServiceOptions{RequireCPULimit: true}, wantStatus: http.StatusForbidden, wantOperation: "create", wantRequirements: "cpu"},
		{name: "create soft positive", target: "/services/create", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":1}}}}`, service: ServiceOptions{RequireCPULimit: true}, wantStatus: guardedRequestAllowedStatus, wantOperation: "create", wantRequirements: "cpu"},
		{name: "create hard missing resources", target: "/services/create", body: `{"TaskTemplate":{}}`, service: ServiceOptions{RequireCPULimitHard: true}, wantStatus: http.StatusForbidden, wantOperation: "create", wantRequirements: "hard_cpu"},
		{name: "create hard positive", target: "/services/create", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":1}}}}`, service: ServiceOptions{RequireCPULimitHard: true}, wantStatus: guardedRequestAllowedStatus, wantOperation: "create", wantRequirements: "hard_cpu"},
		{name: "create both positive", target: "/services/create", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":1}}}}`, service: ServiceOptions{RequireCPULimit: true, RequireCPULimitHard: true}, wantStatus: guardedRequestAllowedStatus, wantOperation: "create", wantRequirements: "cpu,hard_cpu"},
		{name: "ordinary update omission is unset", target: "/services/svc/update?version=7", body: `{"TaskTemplate":{}}`, service: ServiceOptions{RequireCPULimit: true}, wantStatus: http.StatusForbidden, wantOperation: "update", wantRequirements: "cpu"},
		{name: "ordinary update zero is unset", target: "/services/svc/update?version=7", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":0}}}}`, service: ServiceOptions{RequireCPULimit: true}, wantStatus: http.StatusForbidden, wantOperation: "update", wantRequirements: "cpu"},
		{name: "ordinary update negative denies", target: "/services/svc/update?version=7", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":-1}}}}`, service: ServiceOptions{RequireCPULimit: true}, wantStatus: http.StatusForbidden, wantOperation: "update", wantRequirements: "cpu"},
		{name: "ordinary update reservation only denies", target: "/services/svc/update?version=7", body: `{"TaskTemplate":{"Resources":{"Reservations":{"NanoCPUs":1000000000}}}}`, service: ServiceOptions{RequireCPULimit: true}, wantStatus: http.StatusForbidden, wantOperation: "update", wantRequirements: "cpu"},
		{name: "ordinary update soft positive", target: "/services/svc/update?version=7", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":1}}}}`, service: ServiceOptions{RequireCPULimit: true}, wantStatus: guardedRequestAllowedStatus, wantOperation: "update", wantRequirements: "cpu"},
		{name: "ordinary update positive", target: "/services/svc/update?version=7", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":1000000000}}}}`, service: ServiceOptions{RequireCPULimitHard: true}, wantStatus: guardedRequestAllowedStatus, wantOperation: "update", wantRequirements: "hard_cpu"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runResourceGuardRequest(t, ResourceLimitGuardOptions{
				PolicyConfig: PolicyConfig{Service: tt.service},
				InspectService: func(context.Context, string) (ServiceInspectResult, bool, error) {
					panic("ordinary create/update must not inspect service state")
				},
			}, http.MethodPost, tt.target, tt.body, "")

			if out.status != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", out.status, tt.wantStatus, out.body)
			}
			if out.meta.ResourcePolicy == nil {
				t.Fatal("ResourcePolicy = nil, want evaluated metadata")
			}
			if got := out.meta.ResourcePolicy.Operation; got != tt.wantOperation {
				t.Fatalf("operation = %q, want %q", got, tt.wantOperation)
			}
			if got := out.meta.ResourcePolicy.Requirements; got != tt.wantRequirements {
				t.Fatalf("requirements = %q, want %q", got, tt.wantRequirements)
			}
			wantForwarded := 0
			if tt.wantStatus == guardedRequestAllowedStatus {
				wantForwarded = 1
			}
			if out.forwarded != wantForwarded {
				t.Fatalf("forwarded = %d, want %d", out.forwarded, wantForwarded)
			}
		})
	}
}

func TestResourceLimitGuardServiceManualRollback(t *testing.T) {
	safeBody := `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":1000000000}}}}`
	weakBody := `{"TaskTemplate":{},"PreviousSpec":{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":9999999999}}}}}`
	tests := []struct {
		name         string
		target       string
		body         string
		inspect      ServiceInspectResult
		found        bool
		inspectErr   error
		nilInspector bool
		wantStatus   int
		wantCode     string
		wantForward  int
		wantResult   string
	}{
		{name: "safe body cannot rescue weak PreviousSpec", target: "/services/svc/update?version=7&rollback=previous", body: safeBody, inspect: ServiceInspectResult{Version: 7, HasPreviousSpec: true, PreviousSpecNanoCPUs: 0}, found: true, wantStatus: http.StatusForbidden, wantCode: reasonCodeResourceLimitPolicyDenied, wantResult: "deny"},
		{name: "request PreviousSpec cannot rescue weak daemon PreviousSpec", target: "/services/svc/update?version=7&rollback=previous", body: weakBody, inspect: ServiceInspectResult{Version: 7, HasPreviousSpec: true, PreviousSpecNanoCPUs: 0}, found: true, wantStatus: http.StatusForbidden, wantCode: reasonCodeResourceLimitPolicyDenied, wantResult: "deny"},
		{name: "request RollbackConfig cannot rescue weak daemon PreviousSpec", target: "/services/svc/update?version=7&rollback=previous", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":1}}},"RollbackConfig":{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":999}}}}}`, inspect: ServiceInspectResult{Version: 7, HasPreviousSpec: true, PreviousSpecNanoCPUs: 0}, found: true, wantStatus: http.StatusForbidden, wantCode: reasonCodeResourceLimitPolicyDenied, wantResult: "deny"},
		{name: "weak body ignored when daemon PreviousSpec is safe", target: "/services/svc/update?version=7&rollback=previous", body: weakBody, inspect: ServiceInspectResult{Version: 7, HasPreviousSpec: true, PreviousSpecNanoCPUs: 1}, found: true, wantStatus: guardedRequestAllowedStatus, wantForward: 1, wantResult: "allow"},
		{name: "PreviousSpec absent denies", target: "/services/svc/update?version=7&rollback=previous", body: safeBody, inspect: ServiceInspectResult{Version: 7}, found: true, wantStatus: http.StatusForbidden, wantCode: reasonCodeResourceLimitPolicyDenied, wantResult: "deny"},
		{name: "version mismatch conflicts", target: "/services/svc/update?version=6&rollback=previous", body: safeBody, inspect: ServiceInspectResult{Version: 7, HasPreviousSpec: true, PreviousSpecNanoCPUs: 1}, found: true, wantStatus: http.StatusConflict, wantCode: reasonCodeResourceLimitPolicyStateChanged, wantResult: "state_changed"},
		{name: "duplicate rollback values invalid", target: "/services/svc/update?version=7&rollback=previous&rollback=previous", body: safeBody, inspect: ServiceInspectResult{Version: 7, HasPreviousSpec: true, PreviousSpecNanoCPUs: 1}, found: true, wantStatus: http.StatusBadRequest, wantCode: reasonCodeResourceLimitRequestInvalid, wantResult: "invalid"},
		{name: "conflicting rollback values invalid", target: "/services/svc/update?version=7&rollback=previous&rollback=none", body: safeBody, inspect: ServiceInspectResult{Version: 7, HasPreviousSpec: true, PreviousSpecNanoCPUs: 1}, found: true, wantStatus: http.StatusBadRequest, wantCode: reasonCodeResourceLimitRequestInvalid, wantResult: "invalid"},
		{name: "missing version invalid", target: "/services/svc/update?rollback=previous", body: safeBody, inspect: ServiceInspectResult{Version: 7, HasPreviousSpec: true, PreviousSpecNanoCPUs: 1}, found: true, wantStatus: http.StatusBadRequest, wantCode: reasonCodeResourceLimitRequestInvalid, wantResult: "invalid"},
		{name: "inspect 404 passes through", target: "/services/svc/update?version=7&rollback=previous", body: safeBody, found: false, wantStatus: guardedRequestAllowedStatus, wantForward: 1, wantResult: "allow"},
		{name: "inspect failure fails closed", target: "/services/svc/update?version=7&rollback=previous", body: safeBody, inspectErr: errors.New("daemon unavailable"), wantStatus: http.StatusBadGateway, wantCode: reasonCodeResourceLimitPolicyLookupFailed, wantResult: "lookup_failed"},
		{name: "nil inspector fails closed", target: "/services/svc/update?version=7&rollback=previous", body: safeBody, nilInspector: true, wantStatus: http.StatusBadGateway, wantCode: reasonCodeResourceLimitPolicyLookupFailed, wantResult: "lookup_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspectCalls := 0
			var inspector ServiceInspectFunc
			if !tt.nilInspector {
				inspector = func(_ context.Context, id string) (ServiceInspectResult, bool, error) {
					inspectCalls++
					if id != "svc" {
						t.Fatalf("inspect id = %q, want svc", id)
					}
					return tt.inspect, tt.found, tt.inspectErr
				}
			}
			out := runResourceGuardRequest(t, ResourceLimitGuardOptions{
				PolicyConfig:   PolicyConfig{Service: ServiceOptions{RequireCPULimit: true}},
				InspectService: inspector,
			}, http.MethodPost, tt.target, tt.body, "")

			if out.status != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", out.status, tt.wantStatus, out.body)
			}
			if out.meta.ReasonCode != tt.wantCode {
				t.Fatalf("reason code = %q, want %q", out.meta.ReasonCode, tt.wantCode)
			}
			if out.forwarded != tt.wantForward {
				t.Fatalf("forwarded = %d, want %d", out.forwarded, tt.wantForward)
			}
			if out.meta.ResourcePolicy == nil || out.meta.ResourcePolicy.Result != tt.wantResult {
				t.Fatalf("resource metadata = %#v, want result %q", out.meta.ResourcePolicy, tt.wantResult)
			}
			if out.meta.ResourcePolicy.Operation != "manual_rollback" {
				t.Fatalf("operation = %q, want manual_rollback", out.meta.ResourcePolicy.Operation)
			}
			if (strings.Contains(tt.name, "duplicate") || strings.Contains(tt.name, "conflicting") || strings.Contains(tt.name, "missing version") || tt.nilInspector) && inspectCalls != 0 {
				t.Fatalf("inspect calls = %d, want 0", inspectCalls)
			}
		})
	}
}

func TestResourceLimitGuardServiceAutomaticRollback(t *testing.T) {
	safeRequest := `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":1000000000}}},"UpdateConfig":{"FailureAction":"rollback"}}`
	tests := []struct {
		name          string
		body          string
		inspect       ServiceInspectResult
		wantStatus    int
		wantForward   int
		wantInspect   int
		wantOperation string
	}{
		{name: "weak current spec denies rollback capable update", body: safeRequest, inspect: ServiceInspectResult{Version: 7, SpecNanoCPUs: 0}, wantStatus: http.StatusForbidden, wantInspect: 1, wantOperation: "automatic_rollback"},
		{name: "safe current spec allows rollback capable update", body: safeRequest, inspect: ServiceInspectResult{Version: 7, SpecNanoCPUs: 1}, wantStatus: guardedRequestAllowedStatus, wantForward: 1, wantInspect: 1, wantOperation: "automatic_rollback"},
		{name: "pause remediation needs no current lookup", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":1}}},"UpdateConfig":{"FailureAction":"pause"}}`, wantStatus: guardedRequestAllowedStatus, wantForward: 1, wantOperation: "update"},
		{name: "continue remediation needs no current lookup", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":1}}},"UpdateConfig":{"FailureAction":"continue"}}`, wantStatus: guardedRequestAllowedStatus, wantForward: 1, wantOperation: "update"},
		{name: "request PreviousSpec cannot rescue weak current spec", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":1}}},"PreviousSpec":{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":999}}}},"UpdateConfig":{"FailureAction":"rollback"}}`, inspect: ServiceInspectResult{Version: 7, SpecNanoCPUs: 0}, wantStatus: http.StatusForbidden, wantInspect: 1, wantOperation: "automatic_rollback"},
		{name: "RollbackConfig resources cannot satisfy weak request", body: `{"TaskTemplate":{},"RollbackConfig":{"FailureAction":"rollback","TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":999}}}}}`, wantStatus: http.StatusForbidden, wantOperation: "update"},
		{name: "RollbackConfig FailureAction does not trigger state lookup", body: `{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":1}}},"RollbackConfig":{"FailureAction":"rollback"}}`, wantStatus: guardedRequestAllowedStatus, wantForward: 1, wantOperation: "update"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspectCalls := 0
			out := runResourceGuardRequest(t, ResourceLimitGuardOptions{
				PolicyConfig: PolicyConfig{Service: ServiceOptions{RequireCPULimitHard: true}},
				InspectService: func(context.Context, string) (ServiceInspectResult, bool, error) {
					inspectCalls++
					return tt.inspect, true, nil
				},
			}, http.MethodPost, "/services/svc/update?version=7", tt.body, "")

			if out.status != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", out.status, tt.wantStatus, out.body)
			}
			if out.forwarded != tt.wantForward {
				t.Fatalf("forwarded = %d, want %d", out.forwarded, tt.wantForward)
			}
			if inspectCalls != tt.wantInspect {
				t.Fatalf("inspect calls = %d, want %d", inspectCalls, tt.wantInspect)
			}
			if out.meta.ResourcePolicy == nil || out.meta.ResourcePolicy.Operation != tt.wantOperation {
				t.Fatalf("resource metadata = %#v, want operation %q", out.meta.ResourcePolicy, tt.wantOperation)
			}
		})
	}
}

func TestDockerServiceInspectorBoundsAndDecodesState(t *testing.T) {
	t.Run("decodes daemon owned state", func(t *testing.T) {
		inspector := NewDockerServiceInspectorWithRoundTripper(roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.EscapedPath() != "/services/svc" {
				t.Fatalf("path = %q, want /services/svc", r.URL.EscapedPath())
			}
			return dockerInspectResponse(http.StatusOK, `{"Version":{"Index":7},"Spec":{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":1}}}},"PreviousSpec":{"TaskTemplate":{"Resources":{"Limits":{"NanoCPUs":2}}}}}`), nil
		}))
		got, found, err := inspector(context.Background(), "svc")
		if err != nil || !found {
			t.Fatalf("inspect = (%#v, %v, %v), want found", got, found, err)
		}
		if got.Version != 7 || got.SpecNanoCPUs != 1 || !got.HasPreviousSpec || got.PreviousSpecNanoCPUs != 2 {
			t.Fatalf("inspect result = %#v", got)
		}
	})

	t.Run("one byte over response cap fails", func(t *testing.T) {
		inspector := NewDockerServiceInspectorWithRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return dockerInspectResponse(http.StatusOK, strings.Repeat("x", MaxResponseBodyBytes+1)), nil
		}))
		if _, _, err := inspector(context.Background(), "svc"); err == nil {
			t.Fatal("inspect error = nil, want oversized response failure")
		}
	})
}

func TestResourceLimitGuardReasonCodesStatusesAndStaticMessages(t *testing.T) {
	const targetID = "sensitive-container-987654"
	tests := []struct {
		name       string
		target     string
		body       string
		opts       ResourceLimitGuardOptions
		wantStatus int
		wantCode   string
		wantReason string
	}{
		{
			name:       "request invalid",
			target:     "/containers/" + targetID + "/update",
			body:       `{"Memory":1.5}`,
			opts:       ResourceLimitGuardOptions{PolicyConfig: PolicyConfig{ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true}}},
			wantStatus: http.StatusBadRequest,
			wantCode:   reasonCodeResourceLimitRequestInvalid,
			wantReason: "container update denied: request body could not be inspected",
		},
		{
			name:   "policy denied",
			target: "/containers/" + targetID + "/update",
			body:   `{}`,
			opts: ResourceLimitGuardOptions{
				PolicyConfig: PolicyConfig{ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true}},
				InspectContainer: func(context.Context, string) (ContainerUpdateInspectResult, bool, error) {
					return ContainerUpdateInspectResult{}, true, nil
				},
			},
			wantStatus: http.StatusForbidden,
			wantCode:   reasonCodeResourceLimitPolicyDenied,
			wantReason: "container update denied: a memory limit is required (set HostConfig.Memory)",
		},
		{
			name:   "lookup failed",
			target: "/containers/" + targetID + "/update",
			body:   `{}`,
			opts: ResourceLimitGuardOptions{
				PolicyConfig: PolicyConfig{ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true}},
				InspectContainer: func(context.Context, string) (ContainerUpdateInspectResult, bool, error) {
					return ContainerUpdateInspectResult{}, false, errors.New("labels=secret")
				},
			},
			wantStatus: http.StatusBadGateway,
			wantCode:   reasonCodeResourceLimitPolicyLookupFailed,
			wantReason: "container update denied: resource requirement verification unavailable",
		},
		{
			name:   "state changed",
			target: "/services/" + targetID + "/update?version=6&rollback=previous",
			body:   `{}`,
			opts: ResourceLimitGuardOptions{
				PolicyConfig: PolicyConfig{Service: ServiceOptions{RequireCPULimit: true}},
				InspectService: func(context.Context, string) (ServiceInspectResult, bool, error) {
					return ServiceInspectResult{Version: 7, HasPreviousSpec: true, PreviousSpecNanoCPUs: 1}, true, nil
				},
			},
			wantStatus: http.StatusConflict,
			wantCode:   reasonCodeResourceLimitPolicyStateChanged,
			wantReason: "service update denied: the service state changed since it was inspected; retry with the current version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runResourceGuardRequest(t, tt.opts, http.MethodPost, tt.target, tt.body, "")
			if out.status != tt.wantStatus || out.meta.ReasonCode != tt.wantCode {
				t.Fatalf("outcome = %d/%q, want %d/%q", out.status, out.meta.ReasonCode, tt.wantStatus, tt.wantCode)
			}
			if out.meta.Reason != tt.wantReason {
				t.Fatalf("reason = %q, want static %q", out.meta.Reason, tt.wantReason)
			}
			for _, secret := range []string{targetID, "987654", "labels=secret"} {
				if strings.Contains(out.meta.Reason, secret) {
					t.Fatalf("reason %q contains request/state value %q", out.meta.Reason, secret)
				}
			}
		})
	}
}

func TestResourceLimitGuardRolloutOnlySoftensPolicyDenied(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		body       string
		opts       ResourceLimitGuardOptions
		wantStatus int
		wantCode   string
		wantResult string
		softened   bool
	}{
		{
			name:   "policy denied",
			target: "/containers/c/update",
			body:   `{}`,
			opts: ResourceLimitGuardOptions{PolicyConfig: PolicyConfig{ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true}}, InspectContainer: func(context.Context, string) (ContainerUpdateInspectResult, bool, error) {
				return ContainerUpdateInspectResult{}, true, nil
			}},
			wantStatus: guardedRequestAllowedStatus,
			wantCode:   reasonCodeResourceLimitPolicyDenied,
			wantResult: "would_deny",
			softened:   true,
		},
		{
			name:       "invalid remains hard",
			target:     "/containers/c/update",
			body:       `{"Memory":1.5}`,
			opts:       ResourceLimitGuardOptions{PolicyConfig: PolicyConfig{ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true}}},
			wantStatus: http.StatusBadRequest,
			wantCode:   reasonCodeResourceLimitRequestInvalid,
			wantResult: "invalid",
		},
		{
			name:   "lookup failure remains hard",
			target: "/containers/c/update",
			body:   `{}`,
			opts: ResourceLimitGuardOptions{PolicyConfig: PolicyConfig{ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true}}, InspectContainer: func(context.Context, string) (ContainerUpdateInspectResult, bool, error) {
				return ContainerUpdateInspectResult{}, false, errors.New("down")
			}},
			wantStatus: http.StatusBadGateway,
			wantCode:   reasonCodeResourceLimitPolicyLookupFailed,
			wantResult: "lookup_failed",
		},
		{
			name:   "state change remains hard",
			target: "/services/s/update?version=1&rollback=previous",
			body:   `{}`,
			opts: ResourceLimitGuardOptions{PolicyConfig: PolicyConfig{Service: ServiceOptions{RequireCPULimit: true}}, InspectService: func(context.Context, string) (ServiceInspectResult, bool, error) {
				return ServiceInspectResult{Version: 2, HasPreviousSpec: true, PreviousSpecNanoCPUs: 1}, true, nil
			}},
			wantStatus: http.StatusConflict,
			wantCode:   reasonCodeResourceLimitPolicyStateChanged,
			wantResult: "state_changed",
		},
	}

	for _, mode := range []string{"warn", "audit"} {
		t.Run(mode, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					out := runResourceGuardRequest(t, tt.opts, http.MethodPost, tt.target, tt.body, mode)
					if out.status != tt.wantStatus || out.meta.ReasonCode != tt.wantCode {
						t.Fatalf("outcome = %d/%q, want %d/%q", out.status, out.meta.ReasonCode, tt.wantStatus, tt.wantCode)
					}
					wantForwarded := 0
					wantDecision := logging.DecisionDeny
					if tt.softened {
						wantForwarded = 1
						wantDecision = logging.DecisionWouldDeny
					}
					if out.forwarded != wantForwarded || out.meta.Decision != wantDecision {
						t.Fatalf("forwarded/decision = %d/%q, want %d/%q", out.forwarded, out.meta.Decision, wantForwarded, wantDecision)
					}
					if out.meta.ResourcePolicy == nil || out.meta.ResourcePolicy.Result != tt.wantResult {
						t.Fatalf("resource metadata = %#v, want result %q", out.meta.ResourcePolicy, tt.wantResult)
					}
				})
			}
		})
	}
}

func FuzzResourceLimitGuardContainerRequestDecode(f *testing.F) {
	for _, seed := range []string{
		`{}`,
		`{"Memory":0}`,
		`{"PidsLimit":-1}`,
		`{"Memory":1,"memory":0}`,
		`{"HostConfig":{"Memory":1}}`,
		`{"Memory":9223372036854775808}`,
		`null`,
		`[1]`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, body string) {
		out := runResourceGuardRequest(t, ResourceLimitGuardOptions{
			PolicyConfig: PolicyConfig{ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true, RequirePidsLimit: true}},
			InspectContainer: func(context.Context, string) (ContainerUpdateInspectResult, bool, error) {
				return ContainerUpdateInspectResult{Memory: 1, PidsLimit: int64Ptr(1)}, true, nil
			},
		}, http.MethodPost, "/containers/fuzz/update", body, "")

		switch out.status {
		case guardedRequestAllowedStatus:
			if out.forwardedBody != body {
				t.Fatalf("forwarded body changed: got %q want %q", out.forwardedBody, body)
			}
		case http.StatusBadRequest, http.StatusForbidden, http.StatusRequestEntityTooLarge:
			if out.forwarded != 0 {
				t.Fatalf("denied request forwarded %d times", out.forwarded)
			}
		default:
			t.Fatalf("unexpected status %d for body %q", out.status, body)
		}
	})
}
