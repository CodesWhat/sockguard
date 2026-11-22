package logging

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuditOwnershipContextFollowsSelectedProfile(t *testing.T) {
	opts := AuditOptions{
		OwnershipOwner:    "root-owner",
		OwnershipLabelKey: "com.sockguard.owner",
		ProfileOwnership: map[string]AuditOwnership{
			"app-a": {Owner: "A", Scope: "owner"},
			"admin": {Owner: "ADM", Scope: "all"},
			"bare":  {Owner: "", Scope: "owner"},
		},
	}
	tests := []struct {
		name, profile string
		opts          AuditOptions
		wantEnabled   bool
		wantOwner     string
		wantScope     string
	}{
		{"no profile uses root", "", opts, true, "root-owner", "owner"},
		{"profile without override uses root", "other", opts, true, "root-owner", "owner"},
		{"profile owner", "app-a", opts, true, "A", "owner"},
		{"scope all", "admin", opts, true, "ADM", "all"},
		{"profile that clears the owner", "bare", opts, false, "", ""},
		{"ownership off", "", AuditOptions{}, false, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			auditLogger := NewAuditLogger(&buf)
			handler := AuditLogMiddleware(auditLogger, tt.opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if meta := MetaFromResponseWriter(w); meta != nil {
					meta.Profile = tt.profile
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/_ping", nil))
			closeAuditLogger(t, auditLogger)

			var event struct {
				Ownership map[string]any `json:"ownership"`
			}
			if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
				t.Fatalf("decode: %v\n%s", err, buf.String())
			}
			if got := event.Ownership["enabled"]; got != tt.wantEnabled {
				t.Errorf("enabled = %v, want %v", got, tt.wantEnabled)
			}
			if got := event.Ownership["owner"]; got != tt.wantOwner {
				t.Errorf("owner = %v, want %q", got, tt.wantOwner)
			}
			if got := event.Ownership["ownership_scope"]; got != tt.wantScope {
				t.Errorf("ownership_scope = %v, want %q", got, tt.wantScope)
			}
		})
	}
}
