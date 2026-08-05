package filter

import (
	"encoding/base64"
	"strings"
	"testing"
)

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestDenyRegistryAuthHeaderReason(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		allowAll   bool
		allowed    []string
		wantReason string
	}{
		{
			name: "empty header is a no-op",
		},
		{
			name:   "well-formed auth with no allowlist configured passes through",
			header: b64(`{"username":"u","password":"p","serveraddress":"anything.example.com"}`),
		},
		{
			name:     "allow-all bypasses host check",
			header:   b64(`{"serveraddress":"anything.example.com"}`),
			allowAll: true,
			allowed:  []string{"registry.internal"},
		},
		{
			name:    "allowlisted host passes",
			header:  b64(`{"serveraddress":"registry.internal"}`),
			allowed: []string{"registry.internal"},
		},
		{
			name:    "allowlisted host with scheme and path passes",
			header:  b64(`{"serveraddress":"https://registry.internal/v2/"}`),
			allowed: []string{"registry.internal"},
		},
		{
			name:       "non-allowlisted host denied",
			header:     b64(`{"serveraddress":"evil.example.com"}`),
			allowed:    []string{"registry.internal"},
			wantReason: "image pull denied: X-Registry-Auth serveraddress is not allowlisted",
		},
		{
			name:    "empty serveraddress passes through even with allowlist",
			header:  b64(`{"username":"u"}`),
			allowed: []string{"registry.internal"},
		},
		{
			name:       "not valid base64 denied",
			header:     "not-base64!!!",
			wantReason: "image pull denied: X-Registry-Auth header is not valid base64",
		},
		{
			name:       "valid base64 but not JSON denied",
			header:     b64("not json"),
			wantReason: "image pull denied: X-Registry-Auth header is not valid JSON",
		},
		{
			name:       "oversized header denied before decode",
			header:     strings.Repeat("A", maxRegistryAuthHeaderBytes+1),
			wantReason: "image pull denied: X-Registry-Auth header exceeds 8192 byte limit",
		},
		{
			name:    "url-safe base64 alphabet decodes",
			header:  base64.URLEncoding.EncodeToString([]byte(`{"serveraddress":"registry.internal"}`)),
			allowed: []string{"registry.internal"},
		},
		{
			name:    "raw standard base64 (no padding) decodes",
			header:  base64.RawStdEncoding.EncodeToString([]byte(`{"serveraddress":"registry.internal"}`)),
			allowed: []string{"registry.internal"},
		},
		{
			name:    "raw url-safe base64 (no padding) decodes",
			header:  base64.RawURLEncoding.EncodeToString([]byte(`{"serveraddress":"registry.internal"}`)),
			allowed: []string{"registry.internal"},
		},
		{
			name:    "duplicate serveraddress keys use last value per encoding/json",
			header:  b64(`{"serveraddress":"evil.example.com","serveraddress":"registry.internal"}`),
			allowed: []string{"registry.internal"},
		},
		{
			name:       "mismatched host across scheme and port denied",
			header:     b64(`{"serveraddress":"https://evil.example.com:5000/v2/"}`),
			allowed:    []string{"registry.internal"},
			wantReason: "image pull denied: X-Registry-Auth serveraddress is not allowlisted",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := denyRegistryAuthHeaderReason(tt.header, tt.allowAll, tt.allowed, "image pull")
			if got != tt.wantReason {
				t.Fatalf("denyRegistryAuthHeaderReason() = %q, want %q", got, tt.wantReason)
			}
		})
	}
}

// TestDenyRegistryAuthHeaderReasonNeverLeaksCredentials asserts that decoded
// credential material (username/password/identitytoken) never appears in a
// deny reason string, even when the header content is itself malformed or
// carries those fields alongside a non-allowlisted serveraddress. Deny
// reasons are surfaced in logs and (depending on deny_response_verbosity)
// API responses, so they must stay secret-safe by construction rather than
// by accident of which fields registryAuthHeader happens to decode today.
func TestDenyRegistryAuthHeaderReasonNeverLeaksCredentials(t *testing.T) {
	const secret = "tr0ub4dor-super-secret-password"

	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "non-allowlisted host with credentials present",
			header: b64(`{"username":"admin","password":"` + secret + `","serveraddress":"evil.example.com"}`),
		},
		{
			name:   "malformed JSON still containing the secret literal",
			header: b64(`{"username":"admin","password":"` + secret + `"`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := denyRegistryAuthHeaderReason(tt.header, false, []string{"registry.internal"}, "image pull")
			if got == "" {
				t.Fatal("expected a deny reason, got empty string")
			}
			if strings.Contains(got, secret) {
				t.Fatalf("deny reason leaked credential material: %q", got)
			}
		})
	}
}

func TestDenyRegistryConfigHeaderReason(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantReason string
	}{
		{
			name: "empty header is a no-op",
		},
		{
			name:   "well-formed multi-registry map passes",
			header: b64(`{"registry.internal":{"username":"u","password":"p"},"other.example.com":{}}`),
		},
		{
			name:       "not valid base64 denied",
			header:     "!!!not-base64",
			wantReason: "build denied: X-Registry-Config header is not valid base64",
		},
		{
			name:       "valid base64 but not a JSON object denied",
			header:     b64(`["not","an","object"]`),
			wantReason: "build denied: X-Registry-Config header is not valid JSON",
		},
		{
			name:       "oversized header denied before decode",
			header:     strings.Repeat("A", maxRegistryAuthHeaderBytes+1),
			wantReason: "build denied: X-Registry-Config header exceeds 8192 byte limit",
		},
		{
			name:   "url-safe base64 alphabet decodes",
			header: base64.URLEncoding.EncodeToString([]byte(`{"registry.internal":{"username":"u"}}`)),
		},
		{
			name:   "raw standard base64 (no padding) decodes",
			header: base64.RawStdEncoding.EncodeToString([]byte(`{"registry.internal":{"username":"u"}}`)),
		},
		{
			name:   "duplicate registry host keys use last value per encoding/json",
			header: b64(`{"registry.internal":{"username":"u"},"registry.internal":{"username":"other"}}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := denyRegistryConfigHeaderReason(tt.header, "build")
			if got != tt.wantReason {
				t.Fatalf("denyRegistryConfigHeaderReason() = %q, want %q", got, tt.wantReason)
			}
		})
	}
}

func TestStripRegistryHeaderScheme(t *testing.T) {
	tests := []struct{ in, want string }{
		{"registry.internal", "registry.internal"},
		{"registry.internal:5000", "registry.internal:5000"},
		{"https://registry.internal", "registry.internal"},
		{"https://registry.internal/v2/", "registry.internal"},
		{"http://registry.internal:5000/v1/", "registry.internal:5000"},
	}
	for _, tt := range tests {
		if got := stripRegistryHeaderScheme(tt.in); got != tt.want {
			t.Errorf("stripRegistryHeaderScheme(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
