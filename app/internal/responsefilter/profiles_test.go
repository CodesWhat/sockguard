package responsefilter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewWithProfilesSelectsEffectiveOptions(t *testing.T) {
	root := Options{RedactContainerEnv: true}
	profiles := map[string]Options{"open": {}, "strict": {RedactContainerEnv: true, RedactMountPaths: true}}
	byHeader := func(r *http.Request) (string, bool) {
		name := r.Header.Get("X-Profile")
		return name, name != ""
	}
	tests := []struct {
		name    string
		resolve func(*http.Request) (string, bool)
		profile string
		wantEnv bool
	}{
		{"profile turns env off", byHeader, "open", true},
		{"profile keeps env redacted", byHeader, "strict", false},
		{"no profile uses root", byHeader, "", false},
		{"unknown profile uses root", byHeader, "ghost", false},
		{"nil resolver uses root", nil, "open", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewWithProfiles(root, profiles, tt.resolve)
			req := httptest.NewRequest(http.MethodGet, "/containers/c1/json", nil)
			if tt.profile != "" {
				req.Header.Set("X-Profile", tt.profile)
			}
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"Config":{"Env":["A=b"]}}`)),
				Request:    req,
			}
			if err := f.ModifyResponse(resp); err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			if got := strings.Contains(string(body), "A=b"); got != tt.wantEnv {
				t.Fatalf("env visible = %v, want %v; body %s", got, tt.wantEnv, body)
			}
		})
	}
}
