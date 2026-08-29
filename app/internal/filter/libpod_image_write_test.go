package filter

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// libpodImageLoadAllowlist is the posture the load cases are judged against:
// an operator who set request_body.image_load.allowed_registries and expects
// it to hold on Podman's native surface too.
func libpodImageLoadAllowlist() ImageLoadOptions {
	return ImageLoadOptions{AllowedRegistries: []string{"ghcr.io"}}
}

// TestLibpodImageLoadSharesTheDockerCompatInspector pins that
// POST /libpod/images/load is read by the SAME imageLoadPolicy as
// POST /images/load, against the same request_body.image_load config.
//
// It can be one shared policy because the two endpoints take the same input
// in the same place: Podman v5.8.1's pkg/api/handlers/libpod/images.go
// ImagesLoad copies the whole request body to a temp file and hands it to
// imageEngine.Load, and pkg/api/server/register_images.go declares no query
// parameters for the route at all. Each case therefore runs on both paths and
// asserts the identical verdict — a future edit that gives one surface a
// different answer fails here.
func TestLibpodImageLoadSharesTheDockerCompatInspector(t *testing.T) {
	tests := []struct {
		name        string
		opts        ImageLoadOptions
		manifest    string
		wantDeny    bool
		wantReasonC string
	}{
		{
			name:        "denies a RepoTag from a registry outside the allowlist",
			opts:        libpodImageLoadAllowlist(),
			manifest:    `[{"RepoTags":["evil.example.com/acme/app:latest"]}]`,
			wantDeny:    true,
			wantReasonC: "evil.example.com",
		},
		{
			name:     "allows a RepoTag from a registry inside the allowlist",
			opts:     libpodImageLoadAllowlist(),
			manifest: `[{"RepoTags":["ghcr.io/acme/app:v1.2.3"]}]`,
		},
		{
			name:        "denies a second RepoTag that smuggles an off-allowlist registry",
			opts:        libpodImageLoadAllowlist(),
			manifest:    `[{"RepoTags":["ghcr.io/acme/app:v1","evil.example.com/acme/app:v1"]}]`,
			wantDeny:    true,
			wantReasonC: "evil.example.com",
		},
		{
			name:        "denies an untagged archive when allow_untagged is off",
			opts:        libpodImageLoadAllowlist(),
			manifest:    `[{"RepoTags":[]}]`,
			wantDeny:    true,
			wantReasonC: "untagged images are not allowed",
		},
		{
			name:        "denies every archive under the default posture",
			opts:        ImageLoadOptions{},
			manifest:    `[{"RepoTags":["ghcr.io/acme/app:v1"]}]`,
			wantDeny:    true,
			wantReasonC: "loading image archives is not allowed",
		},
	}

	for _, tt := range tests {
		for _, path := range []string{"/images/load", "/libpod/images/load"} {
			t.Run(tt.name+" on "+path, func(t *testing.T) {
				payload := mustImageLoadTar(t, tt.manifest)
				wantDigest := sha256.Sum256(payload)
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(payload)))

				reason, err := newImageLoadPolicy(tt.opts).inspect(nil, req, NormalizePath(req.URL.Path))
				if err != nil {
					t.Fatalf("inspect() error = %v", err)
				}
				if tt.wantDeny {
					if reason == "" {
						t.Fatalf("inspect() allowed %s, want deny", path)
					}
					if !strings.Contains(reason, tt.wantReasonC) {
						t.Fatalf("reason = %q, want it to mention %q", reason, tt.wantReasonC)
					}
					return
				}
				if reason != "" {
					t.Fatalf("inspect() denied %s with %q, want allow", path, reason)
				}

				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("read body: %v", err)
				}
				if gotDigest := sha256.Sum256(body); gotDigest != wantDigest {
					t.Fatalf("forwarded body digest changed on %s", path)
				}
				if req.ContentLength != int64(len(payload)) {
					t.Fatalf("content length = %d, want %d", req.ContentLength, len(payload))
				}
			})
		}
	}
}

// TestLibpodLocalImageLoadRequiresBlindWriteAck pins the load half of the
// "local API" pair. POST /libpod/local/images/load never sends the archive:
// it names one by absolute path on the daemon host in a required `path`
// query parameter that Podman v5.8.1 checks only with
// internal/localapi.ValidatePathForLocalAPI (absolute, and exists). With no
// bytes on the wire the registry allowlist cannot be applied at all, so the
// endpoint has to be refused outright rather than sailing through
// inspect()'s empty-body allow.
func TestLibpodLocalImageLoadRequiresBlindWriteAck(t *testing.T) {
	const path = "/libpod/local/images/load"

	t.Run("denies a daemon-host path even when every registry is allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, path+"?path=%2Fetc", nil)
		reason, err := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true, AllowUntagged: true}).inspect(nil, req, NormalizePath(req.URL.Path))
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if !strings.Contains(reason, "insecure_allow_body_blind_writes") {
			t.Fatalf("reason = %q, want it to name the blind-write acknowledgment", reason)
		}
	})

	t.Run("denies under the default posture too", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, path+"?path=%2Fetc", nil)
		reason, err := newImageLoadPolicy(ImageLoadOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if reason == "" {
			t.Fatal("inspect() allowed the local load under the default posture, want deny")
		}
	})

	t.Run("allows once the operator acknowledges the blind write", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, path+"?path=%2Fetc", nil)
		reason, err := newImageLoadPolicy(ImageLoadOptions{AllowBlindWrites: true}).inspect(nil, req, NormalizePath(req.URL.Path))
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if reason != "" {
			t.Fatalf("inspect() denied with %q, want allow once acknowledged", reason)
		}
	})

	t.Run("the acknowledgment does not weaken the real image load paths", func(t *testing.T) {
		opts := libpodImageLoadAllowlist()
		opts.AllowBlindWrites = true
		for _, twin := range []string{"/images/load", "/libpod/images/load"} {
			payload := mustImageLoadTar(t, `[{"RepoTags":["evil.example.com/acme/app:latest"]}]`)
			req := httptest.NewRequest(http.MethodPost, twin, strings.NewReader(string(payload)))
			reason, err := newImageLoadPolicy(opts).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if !strings.Contains(reason, "evil.example.com") {
				t.Fatalf("%s: reason = %q, want the allowlist still enforced", twin, reason)
			}
		}
	})
}

// TestLibpodImageImportInspect pins request_body.image_pull.allow_imports on
// Podman's native POST /libpod/images/import.
//
// Verified against Podman v5.8.1's pkg/api/handlers/libpod/images.go
// ImagesImport: every request to the path is an import, taking the tarball
// from a caller-supplied `URL` when one is present and from the request body
// otherwise, so the flag alone decides and no query spelling can steer the
// verdict. The URL cases exist to pin that the denial names the source, not
// that the source changes the answer.
func TestLibpodImageImportInspect(t *testing.T) {
	const path = "/libpod/images/import"

	tests := []struct {
		name        string
		opts        ImagePullOptions
		rawQuery    string
		wantDeny    bool
		wantReasonC string
	}{
		{
			name:        "denies a body import under the default posture",
			opts:        ImagePullOptions{},
			rawQuery:    "reference=acme%2Fapp%3Alatest",
			wantDeny:    true,
			wantReasonC: "importing images is not allowed",
		},
		{
			name:        "denies a URL import and names the source",
			opts:        ImagePullOptions{},
			rawQuery:    "URL=http%3A%2F%2Fevil.example.com%2Fx.tar",
			wantDeny:    true,
			wantReasonC: "http://evil.example.com/x.tar",
		},
		{
			// gorilla/schema matches the `URL` tag with strings.EqualFold,
			// so Podman binds the lowercase spelling to the same field.
			name:        "denies the case-folded url spelling Podman accepts",
			opts:        ImagePullOptions{},
			rawQuery:    "url=http%3A%2F%2Fevil.example.com%2Fx.tar",
			wantDeny:    true,
			wantReasonC: "http://evil.example.com/x.tar",
		},
		{
			// Podman's scalar decode takes the LAST value of a repeated key.
			name:        "names the last value of a repeated url the way Podman reads it",
			opts:        ImagePullOptions{},
			rawQuery:    "url=http%3A%2F%2Ffirst.example.com%2Fx.tar&URL=http%3A%2F%2Flast.example.com%2Fx.tar",
			wantDeny:    true,
			wantReasonC: "http://last.example.com/x.tar",
		},
		{
			name:        "denies even with a registry allowlist configured, since allow_imports is separate",
			opts:        ImagePullOptions{AllowedRegistries: []string{"ghcr.io"}},
			rawQuery:    "reference=ghcr.io%2Facme%2Fapp",
			wantDeny:    true,
			wantReasonC: "importing images is not allowed",
		},
		{
			name:        "denies even when every registry is allowed, since allow_imports is separate",
			opts:        ImagePullOptions{AllowAllRegistries: true},
			rawQuery:    "",
			wantDeny:    true,
			wantReasonC: "importing images is not allowed",
		},
		{
			name:     "allows once allow_imports is set",
			opts:     ImagePullOptions{AllowImports: true},
			rawQuery: "reference=acme%2Fapp%3Alatest",
		},
		{
			name:     "allows a URL import once allow_imports is set",
			opts:     ImagePullOptions{AllowImports: true},
			rawQuery: "URL=http%3A%2F%2Fexample.com%2Fx.tar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := path
			if tt.rawQuery != "" {
				target += "?" + tt.rawQuery
			}
			req := httptest.NewRequest(http.MethodPost, target, nil)

			reason, err := newImagePullPolicy(tt.opts).inspectLibpodImport(nil, req, path)
			if err != nil {
				t.Fatalf("inspectLibpodImport() error = %v", err)
			}
			if tt.wantDeny {
				if reason == "" {
					t.Fatalf("inspectLibpodImport() allowed %q, want deny", tt.rawQuery)
				}
				if !strings.Contains(reason, tt.wantReasonC) {
					t.Fatalf("reason = %q, want it to mention %q", reason, tt.wantReasonC)
				}
				if !strings.HasPrefix(reason, libpodImageImportSubject) {
					t.Fatalf("reason = %q, want the %q libpod-family prefix", reason, libpodImageImportSubject)
				}
				return
			}
			if reason != "" {
				t.Fatalf("inspectLibpodImport() denied %q with %q, want allow", tt.rawQuery, reason)
			}
		})
	}
}

// TestLibpodImageImportInspectIsPathExclusive asserts the import inspector is
// a structural no-op everywhere but its own path, and that widening it never
// changed how the Docker-compat fromSrc import behaves.
func TestLibpodImageImportInspectIsPathExclusive(t *testing.T) {
	policy := newImagePullPolicy(ImagePullOptions{})

	t.Run("import inspector ignores the Docker-compat pull path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/images/create?fromSrc=http%3A%2F%2Fevil.example.com%2Fx.tar", nil)
		reason, err := policy.inspectLibpodImport(nil, req, "/images/create")
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpodImport() = (%q, %v), want (\"\", nil)", reason, err)
		}
	})

	t.Run("import inspector ignores the libpod pull path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/libpod/images/pull?reference=ghcr.io%2Facme%2Fapp", nil)
		reason, err := policy.inspectLibpodImport(nil, req, "/libpod/images/pull")
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpodImport() = (%q, %v), want (\"\", nil)", reason, err)
		}
	})

	t.Run("import inspector ignores a nil request", func(t *testing.T) {
		reason, err := policy.inspectLibpodImport(nil, nil, "/libpod/images/import")
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpodImport(nil) = (%q, %v), want (\"\", nil)", reason, err)
		}
	})

	t.Run("import inspector ignores a non-POST method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/libpod/images/import", nil)
		reason, err := policy.inspectLibpodImport(nil, req, "/libpod/images/import")
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpodImport() = (%q, %v), want (\"\", nil)", reason, err)
		}
	})

	t.Run("Docker fromSrc import still denies and still allows on the same flag", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/images/create?fromSrc=http%3A%2F%2Fevil.example.com%2Fx.tar", nil)
		reason, err := policy.inspect(nil, req, "/images/create")
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if !strings.Contains(reason, "evil.example.com") {
			t.Fatalf("reason = %q, want the Docker-compat import still denied", reason)
		}

		allowing := newImagePullPolicy(ImagePullOptions{AllowImports: true})
		reason, err = allowing.inspect(nil, req, "/images/create")
		if err != nil || reason != "" {
			t.Fatalf("inspect() = (%q, %v), want (\"\", nil) once allow_imports is set", reason, err)
		}
	})
}

// TestLibpodLocalBuildRequiresBlindWriteAck pins the build half of the "local
// API" pair. POST /libpod/local/build shares Podman's build handler with
// POST /libpod/build (compat.buildImage in v5.8.1's
// pkg/api/handlers/compat/images_build.go) but takes its context from the
// required `localcontextdir` query parameter — an absolute daemon-host path —
// so request_body.build's Dockerfile scan has no bytes to read. Routed
// through buildPolicy without this branch it would reach the size==0 allow
// and be forwarded as though it had been inspected.
func TestLibpodLocalBuildRequiresBlindWriteAck(t *testing.T) {
	const path = "/libpod/local/build"

	t.Run("denies a daemon-host build context under the default posture", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, path+"?localcontextdir=%2Fetc", nil)
		reason, err := newBuildPolicy(BuildOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if !strings.Contains(reason, "insecure_allow_body_blind_writes") {
			t.Fatalf("reason = %q, want it to name the blind-write acknowledgment", reason)
		}
	})

	t.Run("denies even when RUN instructions are already allowed", func(t *testing.T) {
		// allow_run_instructions is what turns the body scan off for
		// /libpod/build; it must not double as consent for a build whose
		// context is a host directory.
		req := httptest.NewRequest(http.MethodPost, path+"?localcontextdir=%2Fetc", nil)
		reason, err := newBuildPolicy(BuildOptions{AllowRunInstructions: true, AllowRemoteContext: true}).inspect(nil, req, NormalizePath(req.URL.Path))
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if !strings.Contains(reason, "insecure_allow_body_blind_writes") {
			t.Fatalf("reason = %q, want it to name the blind-write acknowledgment", reason)
		}
	})

	t.Run("allows once the operator acknowledges the blind write", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, path+"?localcontextdir=%2Fsrv%2Fapp", nil)
		reason, err := newBuildPolicy(BuildOptions{AllowBlindWrites: true, AllowRunInstructions: true}).inspect(nil, req, NormalizePath(req.URL.Path))
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if reason != "" {
			t.Fatalf("inspect() denied with %q, want allow once acknowledged", reason)
		}
	})

	t.Run("the acknowledged local build still gets the libpod build controls", func(t *testing.T) {
		// Both endpoints run through compat.buildImage, so the host-network
		// control applies to the local spelling too.
		req := httptest.NewRequest(http.MethodPost, path+"?localcontextdir=%2Fsrv%2Fapp&networkmode=host", nil)
		reason, err := newBuildPolicy(BuildOptions{AllowBlindWrites: true, AllowRunInstructions: true}).inspect(nil, req, NormalizePath(req.URL.Path))
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if !strings.Contains(reason, "host network mode") {
			t.Fatalf("reason = %q, want the host-network control still enforced", reason)
		}
	})

	t.Run("libpod build with a real body is unchanged", func(t *testing.T) {
		payload := mustBuildContextTar(t, "Dockerfile", "FROM alpine\nRUN echo hi\n")
		req := httptest.NewRequest(http.MethodPost, "/libpod/build", strings.NewReader(string(payload)))
		reason, err := newBuildPolicy(BuildOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if reason != "build denied: RUN instructions are not allowed" {
			t.Fatalf("reason = %q, want the body scan still running on /libpod/build", reason)
		}
	})
}

// TestLibpodImageWriteMiddlewareRouting drives the full middleware rather
// than the inspectors directly, so it fails if any of these paths is ever
// dropped from compileRuntimePolicy's table again — the actual defect class
// this file exists for. Each libpod case is repeated behind a Podman version
// prefix, and the Docker-compat twins are asserted unchanged.
func TestLibpodImageWriteMiddlewareRouting(t *testing.T) {
	loadArchive := mustImageLoadTar(t, `[{"RepoTags":["evil.example.com/acme/app:latest"]}]`)
	allowedArchive := mustImageLoadTar(t, `[{"RepoTags":["ghcr.io/acme/app:v1"]}]`)

	tests := []struct {
		name       string
		policy     PolicyConfig
		target     string
		body       []byte
		wantStatus int
		wantReason string
	}{
		{
			name:       "libpod image load denies an off-allowlist archive",
			policy:     PolicyConfig{ImageLoad: libpodImageLoadAllowlist()},
			target:     "/libpod/images/load",
			body:       loadArchive,
			wantStatus: http.StatusForbidden,
			wantReason: "evil.example.com",
		},
		{
			name:       "libpod image load denies behind a Podman version prefix",
			policy:     PolicyConfig{ImageLoad: libpodImageLoadAllowlist()},
			target:     "/v5.0/libpod/images/load",
			body:       loadArchive,
			wantStatus: http.StatusForbidden,
			wantReason: "evil.example.com",
		},
		{
			name:       "libpod image load allows an allowlisted archive",
			policy:     PolicyConfig{ImageLoad: libpodImageLoadAllowlist()},
			target:     "/libpod/images/load",
			body:       allowedArchive,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "libpod image load allows an allowlisted archive behind a version prefix",
			policy:     PolicyConfig{ImageLoad: libpodImageLoadAllowlist()},
			target:     "/v5.0/libpod/images/load",
			body:       allowedArchive,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "docker image load twin still denies the same archive",
			policy:     PolicyConfig{ImageLoad: libpodImageLoadAllowlist()},
			target:     "/images/load",
			body:       loadArchive,
			wantStatus: http.StatusForbidden,
			wantReason: "evil.example.com",
		},
		{
			name:       "docker image load twin still allows the same allowlisted archive",
			policy:     PolicyConfig{ImageLoad: libpodImageLoadAllowlist()},
			target:     "/images/load",
			body:       allowedArchive,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "libpod image import denies under the default posture",
			target:     "/libpod/images/import?URL=http%3A%2F%2Fevil.example.com%2Fx.tar",
			wantStatus: http.StatusForbidden,
			wantReason: "evil.example.com",
		},
		{
			name:       "libpod image import denies behind a Podman version prefix",
			target:     "/v5.0/libpod/images/import?URL=http%3A%2F%2Fevil.example.com%2Fx.tar",
			wantStatus: http.StatusForbidden,
			wantReason: "evil.example.com",
		},
		{
			name:       "libpod image import allows once allow_imports is set",
			policy:     PolicyConfig{ImagePull: ImagePullOptions{AllowImports: true}},
			target:     "/libpod/images/import?URL=http%3A%2F%2Fexample.com%2Fx.tar",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "libpod image import allows behind a version prefix once allow_imports is set",
			policy:     PolicyConfig{ImagePull: ImagePullOptions{AllowImports: true}},
			target:     "/v5.0/libpod/images/import?URL=http%3A%2F%2Fexample.com%2Fx.tar",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "docker fromSrc import twin still denies on the same flag",
			target:     "/images/create?fromSrc=http%3A%2F%2Fevil.example.com%2Fx.tar",
			wantStatus: http.StatusForbidden,
			wantReason: "evil.example.com",
		},
		{
			name:       "libpod local image load denies a daemon-host path",
			policy:     PolicyConfig{ImageLoad: ImageLoadOptions{AllowAllRegistries: true}},
			target:     "/libpod/local/images/load?path=%2Fetc",
			wantStatus: http.StatusForbidden,
			wantReason: "insecure_allow_body_blind_writes",
		},
		{
			name:       "libpod local image load denies behind a Podman version prefix",
			policy:     PolicyConfig{ImageLoad: ImageLoadOptions{AllowAllRegistries: true}},
			target:     "/v5.0/libpod/local/images/load?path=%2Fetc",
			wantStatus: http.StatusForbidden,
			wantReason: "insecure_allow_body_blind_writes",
		},
		{
			name:       "libpod local image load allows once acknowledged",
			policy:     PolicyConfig{ImageLoad: ImageLoadOptions{AllowBlindWrites: true}},
			target:     "/libpod/local/images/load?path=%2Fetc",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "libpod local build denies a daemon-host build context",
			target:     "/libpod/local/build?localcontextdir=%2Fetc",
			wantStatus: http.StatusForbidden,
			wantReason: "insecure_allow_body_blind_writes",
		},
		{
			name:       "libpod local build denies behind a Podman version prefix",
			target:     "/v5.0/libpod/local/build?localcontextdir=%2Fetc",
			wantStatus: http.StatusForbidden,
			wantReason: "insecure_allow_body_blind_writes",
		},
		{
			name:       "libpod local build allows once acknowledged",
			policy:     PolicyConfig{Build: BuildOptions{AllowBlindWrites: true, AllowRunInstructions: true}},
			target:     "/libpod/local/build?localcontextdir=%2Fsrv%2Fapp",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "libpod build twin is untouched by the local-build branch",
			policy:     PolicyConfig{Build: BuildOptions{AllowRunInstructions: true}},
			target:     "/libpod/build",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "docker build twin is untouched by the local-build branch",
			policy:     PolicyConfig{Build: BuildOptions{AllowRunInstructions: true}},
			target:     "/build",
			wantStatus: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allow, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/**", Action: ActionAllow, Index: 0})
			if err != nil {
				t.Fatalf("CompileRule() error = %v", err)
			}
			denyAll, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
			if err != nil {
				t.Fatalf("CompileRule() error = %v", err)
			}

			policy := tt.policy
			policy.DenyResponseVerbosity = DenyResponseVerbosityVerbose
			handler := MiddlewareWithOptions([]*CompiledRule{allow, denyAll}, testLogger(), Options{PolicyConfig: policy})(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusCreated)
				}))

			var body io.Reader
			if len(tt.body) > 0 {
				body = strings.NewReader(string(tt.body))
			}
			req := httptest.NewRequest(http.MethodPost, tt.target, body)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantReason == "" {
				return
			}
			var denial DenialResponse
			if err := json.NewDecoder(rec.Body).Decode(&denial); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if !strings.Contains(denial.Reason, tt.wantReason) {
				t.Fatalf("reason = %q, want it to mention %q", denial.Reason, tt.wantReason)
			}
		})
	}
}
