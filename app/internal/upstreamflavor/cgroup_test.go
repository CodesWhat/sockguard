package upstreamflavor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbeCgroupVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		status  int
		body    string
		want    string
		wantErr string
	}{
		{name: "v1", status: http.StatusOK, body: `{"CgroupVersion":"1","CgroupDriver":"cgroupfs"}`, want: "1"},
		{name: "v2", status: http.StatusOK, body: `{"CgroupVersion":"2"}`, want: "2"},
		{name: "absent", status: http.StatusOK, body: `{"ID":"x"}`, wantErr: "no string CgroupVersion"},
		{name: "numeric", status: http.StatusOK, body: `{"CgroupVersion":1}`, wantErr: "no string CgroupVersion"},
		{name: "unrecognized", status: http.StatusOK, body: `{"CgroupVersion":"3"}`, wantErr: "unrecognized"},
		{name: "empty", status: http.StatusOK, body: `{"CgroupVersion":""}`, wantErr: "unrecognized"},
		{name: "bad json", status: http.StatusOK, body: `{`, wantErr: "decode"},
		{name: "http error", status: http.StatusInternalServerError, body: `{"CgroupVersion":"1"}`, wantErr: "HTTP 500"},
		{name: "oversized", status: http.StatusOK, body: `{"x":"` + strings.Repeat("a", maxInfoBodyBytes) + `"}`, wantErr: "exceeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/info" {
					t.Errorf("path = %q, want /info", r.URL.Path)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			got, err := ProbeCgroupVersion(context.Background(), rewriteClient(srv))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				if got != "" {
					t.Fatalf("version = %q on error, want empty", got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("ProbeCgroupVersion() = %q, %v, want %q", got, err, tt.want)
			}
		})
	}
}

func TestProbeCgroupVersionNilClient(t *testing.T) {
	t.Parallel()
	if _, err := ProbeCgroupVersion(context.Background(), nil); err == nil {
		t.Fatal("error = nil, want one for a nil client")
	}
}

// rewriteClient sends the fixed http://docker/... probe URL to srv.
func rewriteClient(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.URL.Scheme = "http"
		r.URL.Host = srv.Listener.Addr().String()
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProbeCgroupVersionAtResponseLimit(t *testing.T) {
	t.Parallel()
	const document = `{"CgroupVersion":"1"}`
	for _, tt := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "below limit", size: maxInfoBodyBytes - 1},
		{name: "exact limit", size: maxInfoBodyBytes},
		{name: "over limit", size: maxInfoBodyBytes + 1, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := document + strings.Repeat(" ", tt.size-len(document))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer srv.Close()
			version, err := ProbeCgroupVersion(t.Context(), rewriteClient(srv))
			if tt.wantErr {
				if err == nil || version != "" || !strings.Contains(err.Error(), "exceeds") {
					t.Fatalf("probe=(%q,%v), want size refusal", version, err)
				}
				return
			}
			if err != nil || version != "1" {
				t.Fatalf("probe=(%q,%v), want cgroup v1", version, err)
			}
		})
	}
}
