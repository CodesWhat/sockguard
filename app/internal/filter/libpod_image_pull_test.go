package filter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// libpodPullAllowlist is the posture every case below is judged against: an
// operator who configured request_body.image_pull.allowed_registries and
// expects it to hold on both API surfaces.
func libpodPullAllowlist() ImagePullOptions {
	return ImagePullOptions{AllowedRegistries: []string{"ghcr.io"}}
}

// TestLibpodImagePullInspect pins the registry allowlist on Podman's native
// POST /libpod/images/pull. Every query spelling here is one Podman v5.8.1
// actually accepts: its ImagesPull handler decodes the query with
// gorilla/schema v1.4.1, which matches the `reference` tag with
// strings.EqualFold and takes the LAST value when the key repeats — neither of
// which net/url's Query().Get reproduces.
func TestLibpodImagePullInspect(t *testing.T) {
	const path = "/libpod/images/pull"

	tests := []struct {
		name        string
		opts        ImagePullOptions
		rawQuery    string
		authHeader  string
		wantDeny    bool
		wantReasonC string
	}{
		{
			name:        "denies a registry outside the allowlist",
			opts:        libpodPullAllowlist(),
			rawQuery:    "reference=evil.example.com/acme/app:latest",
			wantDeny:    true,
			wantReasonC: "evil.example.com",
		},
		{
			name:     "allows a registry inside the allowlist",
			opts:     libpodPullAllowlist(),
			rawQuery: "reference=ghcr.io/acme/app:v1.2.3",
		},
		{
			name:     "allows a Docker Hub official image when allow_official is set",
			opts:     ImagePullOptions{AllowOfficial: true},
			rawQuery: "reference=busybox:latest",
		},
		{
			name:        "denies a non-official Docker Hub image under allow_official alone",
			opts:        ImagePullOptions{AllowOfficial: true},
			rawQuery:    "reference=evil.example.com/acme/app",
			wantDeny:    true,
			wantReasonC: "evil.example.com",
		},
		{
			// gorilla/schema's structInfo.get compares aliases with
			// strings.EqualFold, so Podman decodes this into Reference.
			name:        "denies the case-folded Reference spelling Podman accepts",
			opts:        libpodPullAllowlist(),
			rawQuery:    "Reference=evil.example.com/acme/app",
			wantDeny:    true,
			wantReasonC: "evil.example.com",
		},
		{
			name:        "denies the shouted REFERENCE spelling Podman accepts",
			opts:        libpodPullAllowlist(),
			rawQuery:    "REFERENCE=evil.example.com/acme/app",
			wantDeny:    true,
			wantReasonC: "evil.example.com",
		},
		{
			// Podman reads the LAST value; a proxy reading only the first
			// would allow this.
			name:        "denies a repeated reference whose last value is off-allowlist",
			opts:        libpodPullAllowlist(),
			rawQuery:    "reference=ghcr.io/acme/app&reference=evil.example.com/acme/app",
			wantDeny:    true,
			wantReasonC: "evil.example.com",
		},
		{
			// The mirror image: a proxy reading only the last value would
			// allow this if Podman ever changed to first-wins.
			name:        "denies a repeated reference whose first value is off-allowlist",
			opts:        libpodPullAllowlist(),
			rawQuery:    "reference=evil.example.com/acme/app&reference=ghcr.io/acme/app",
			wantDeny:    true,
			wantReasonC: "evil.example.com",
		},
		{
			name:        "denies a case-variant duplicate that smuggles a second registry",
			opts:        libpodPullAllowlist(),
			rawQuery:    "reference=ghcr.io/acme/app&Reference=evil.example.com/acme/app",
			wantDeny:    true,
			wantReasonC: "evil.example.com",
		},
		{
			// utils.IsRegistryReference admits the docker transport, and
			// libimage.Pull routes it straight to copyFromRegistry.
			name:        "denies a docker:// transport reference outside the allowlist",
			opts:        libpodPullAllowlist(),
			rawQuery:    "reference=docker://evil.example.com/acme/app",
			wantDeny:    true,
			wantReasonC: "evil.example.com",
		},
		{
			name:     "allows a docker:// transport reference inside the allowlist",
			opts:     libpodPullAllowlist(),
			rawQuery: "reference=docker://ghcr.io/acme/app:v1",
		},
		{
			// The regression guard: an inspector wired to the Docker
			// spelling would find nothing here and allow the pull.
			name:        "denies when no reference parameter is present at all",
			opts:        libpodPullAllowlist(),
			rawQuery:    "",
			wantDeny:    true,
			wantReasonC: "no reference parameter",
		},
		{
			name:        "denies when only the Docker fromImage spelling is present",
			opts:        libpodPullAllowlist(),
			rawQuery:    "fromImage=evil.example.com/acme/app&tag=latest",
			wantDeny:    true,
			wantReasonC: "no reference parameter",
		},
		{
			name:        "denies when reference is present but empty",
			opts:        libpodPullAllowlist(),
			rawQuery:    "reference=%20%20",
			wantDeny:    true,
			wantReasonC: "no reference parameter",
		},
		{
			name:     "allows a reference-less request when every registry is allowed",
			opts:     ImagePullOptions{AllowAllRegistries: true},
			rawQuery: "",
		},
		{
			name:     "allows any registry when allow_all_registries is set",
			opts:     ImagePullOptions{AllowAllRegistries: true},
			rawQuery: "reference=evil.example.com/acme/app",
		},
		{
			name:        "denies an X-Registry-Auth serveraddress outside the allowlist",
			opts:        libpodPullAllowlist(),
			rawQuery:    "reference=ghcr.io/acme/app",
			authHeader:  b64(`{"serveraddress":"evil.example.com"}`),
			wantDeny:    true,
			wantReasonC: "serveraddress",
		},
		{
			name:       "allows an X-Registry-Auth serveraddress inside the allowlist",
			opts:       libpodPullAllowlist(),
			rawQuery:   "reference=ghcr.io/acme/app",
			authHeader: b64(`{"serveraddress":"https://ghcr.io/v2/"}`),
		},
		{
			name:        "denies a malformed X-Registry-Auth header fail-closed",
			opts:        libpodPullAllowlist(),
			rawQuery:    "reference=ghcr.io/acme/app",
			authHeader:  "!!!not base64!!!",
			wantDeny:    true,
			wantReasonC: "not valid base64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newImagePullPolicy(tt.opts)
			target := path
			if tt.rawQuery != "" {
				target += "?" + tt.rawQuery
			}
			req := httptest.NewRequest(http.MethodPost, target, nil)
			if tt.authHeader != "" {
				req.Header.Set("X-Registry-Auth", tt.authHeader)
			}

			reason, err := policy.inspectLibpod(nil, req, path)
			if err != nil {
				t.Fatalf("inspectLibpod() error = %v", err)
			}
			if tt.wantDeny {
				if reason == "" {
					t.Fatalf("inspectLibpod() allowed %q, want deny", tt.rawQuery)
				}
				if !strings.Contains(reason, tt.wantReasonC) {
					t.Fatalf("reason = %q, want it to mention %q", reason, tt.wantReasonC)
				}
				if !strings.HasPrefix(reason, libpodImagePullSubject) {
					t.Fatalf("reason = %q, want the %q libpod-family prefix", reason, libpodImagePullSubject)
				}
				return
			}
			if reason != "" {
				t.Fatalf("inspectLibpod() denied %q with %q, want allow", tt.rawQuery, reason)
			}
		})
	}
}

// TestLibpodImagePullInspectIsPathExclusive asserts the libpod pull inspector
// is a structural no-op anywhere other than its own path, and that the
// Docker-compat inspector stays a no-op on the libpod path — the same
// routing-safety invariant TestInspectorRoutingIsPathExclusive pins for
// container create.
func TestLibpodImagePullInspectIsPathExclusive(t *testing.T) {
	policy := newImagePullPolicy(libpodPullAllowlist())

	t.Run("libpod inspector ignores the Docker-compat path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/images/create?fromImage=evil.example.com/acme/app", nil)
		reason, err := policy.inspectLibpod(nil, req, "/images/create")
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpod() = (%q, %v), want (\"\", nil)", reason, err)
		}
	})

	t.Run("Docker inspector ignores the libpod path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/libpod/images/pull?reference=evil.example.com/acme/app", nil)
		reason, err := policy.inspect(nil, req, "/libpod/images/pull")
		if err != nil || reason != "" {
			t.Fatalf("inspect() = (%q, %v), want (\"\", nil)", reason, err)
		}
	})

	t.Run("libpod inspector ignores a nil request", func(t *testing.T) {
		reason, err := policy.inspectLibpod(nil, nil, "/libpod/images/pull")
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpod(nil) = (%q, %v), want (\"\", nil)", reason, err)
		}
	})

	t.Run("libpod inspector ignores a non-POST method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/libpod/images/pull?reference=evil.example.com/acme/app", nil)
		reason, err := policy.inspectLibpod(nil, req, "/libpod/images/pull")
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpod() = (%q, %v), want (\"\", nil)", reason, err)
		}
	})
}

// TestLibpodImagePullMiddlewareEnforcesAllowlist drives the full middleware
// rather than the inspector directly, so it fails if the libpod pull path is
// ever dropped from compileRuntimePolicy's inspection table again — which is
// the actual defect this test exists for. It also pins that the libpod path
// reads the SAME request_body.image_pull config as the Docker-compat one.
func TestLibpodImagePullMiddlewareEnforcesAllowlist(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		wantStatus int
		wantReason string
	}{
		{
			name:       "denies an off-allowlist registry on the libpod path",
			target:     "/libpod/images/pull?reference=evil.example.com%2Facme%2Fapp",
			wantStatus: http.StatusForbidden,
			wantReason: "evil.example.com",
		},
		{
			name:       "denies an off-allowlist registry behind a Podman version prefix",
			target:     "/v5.0.0/libpod/images/pull?reference=evil.example.com%2Facme%2Fapp",
			wantStatus: http.StatusForbidden,
			wantReason: "evil.example.com",
		},
		{
			name:       "denies the case-folded Reference spelling through the middleware",
			target:     "/libpod/images/pull?Reference=evil.example.com%2Facme%2Fapp",
			wantStatus: http.StatusForbidden,
			wantReason: "evil.example.com",
		},
		{
			name:       "allows an allowlisted registry on the libpod path",
			target:     "/libpod/images/pull?reference=ghcr.io%2Facme%2Fapp&tlsVerify=true",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "allows an allowlisted registry behind a Podman version prefix",
			target:     "/v5.0.0/libpod/images/pull?reference=ghcr.io%2Facme%2Fapp",
			wantStatus: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allow, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/libpod/images/pull", Action: ActionAllow, Index: 0})
			if err != nil {
				t.Fatalf("CompileRule() error = %v", err)
			}
			denyAll, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
			if err != nil {
				t.Fatalf("CompileRule() error = %v", err)
			}

			handler := MiddlewareWithOptions([]*CompiledRule{allow, denyAll}, testLogger(), Options{
				PolicyConfig: PolicyConfig{
					DenyResponseVerbosity: DenyResponseVerbosityVerbose,
					// The one config surface, shared with POST /images/create.
					ImagePull: libpodPullAllowlist(),
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusCreated)
			}))

			req := httptest.NewRequest(http.MethodPost, tt.target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantReason == "" {
				return
			}
			var body DenialResponse
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if !strings.Contains(body.Reason, tt.wantReason) {
				t.Fatalf("reason = %q, want it to mention %q", body.Reason, tt.wantReason)
			}
		})
	}
}
