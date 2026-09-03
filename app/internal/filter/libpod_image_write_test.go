package filter

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
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

func TestLibpodImageLoadEnforcesOCIArchiveRegistryPolicy(t *testing.T) {
	tests := []struct {
		name        string
		opts        ImageLoadOptions
		reference   string
		gzip        bool
		wantDeny    bool
		wantReasonC string
	}{
		{
			name:        "denies an OCI ref-name outside the allowlist",
			opts:        libpodImageLoadAllowlist(),
			reference:   "evil.example.com/acme/app:latest",
			wantDeny:    true,
			wantReasonC: "evil.example.com",
		},
		{
			name:      "allows an OCI ref-name inside the allowlist",
			opts:      libpodImageLoadAllowlist(),
			reference: "ghcr.io/acme/app:v1.2.3",
		},
		{
			name:      "allows a gzipped OCI archive inside the allowlist",
			opts:      libpodImageLoadAllowlist(),
			reference: "ghcr.io/acme/app:gzip",
			gzip:      true,
		},
		{
			name:        "allow_untagged never bypasses a tagged OCI archive",
			opts:        ImageLoadOptions{AllowedRegistries: []string{"ghcr.io"}, AllowUntagged: true},
			reference:   "evil.example.com/acme/app:latest",
			wantDeny:    true,
			wantReasonC: "evil.example.com",
		},
		{
			name:        "a bare OCI ref-name is the localhost name Podman loads",
			opts:        ImageLoadOptions{AllowOfficial: true, AllowUntagged: true},
			reference:   "busybox:latest",
			wantDeny:    true,
			wantReasonC: "localhost",
		},
		{
			name:      "a bare OCI ref-name is allowed when localhost is allowlisted",
			opts:      ImageLoadOptions{AllowedRegistries: []string{"localhost"}},
			reference: "busybox:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := mustOCIImageLoadTar(t, []string{tt.reference})
			if tt.gzip {
				payload = mustGzip(t, payload)
			}
			req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(payload))

			reason, err := newImageLoadPolicy(tt.opts).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if tt.wantDeny {
				if !strings.Contains(reason, tt.wantReasonC) {
					t.Fatalf("reason = %q, want it to mention %q", reason, tt.wantReasonC)
				}
				return
			}
			if reason != "" {
				t.Fatalf("inspect() denied with %q, want allow", reason)
			}
			forwarded, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read forwarded body: %v", err)
			}
			if !bytes.Equal(forwarded, payload) {
				t.Fatal("forwarded OCI archive body changed")
			}
			if err := req.Body.Close(); err != nil {
				t.Fatalf("close forwarded body: %v", err)
			}
			if req.ContentLength != int64(len(payload)) {
				t.Fatalf("content length = %d, want %d", req.ContentLength, len(payload))
			}
		})
	}
}

func TestLibpodImageLoadUsesPodmanOCINamePrecedence(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		opts        ImageLoadOptions
		wantDeny    bool
	}{
		{
			name: "containerd name overrides the standard ref name",
			annotations: map[string]string{
				"org.opencontainers.image.ref.name": "ghcr.io/acme/app:v1",
				"io.containerd.image.name":          "evil.example.com/acme/app:v1",
			},
			opts:     libpodImageLoadAllowlist(),
			wantDeny: true,
		},
		{
			name: "containerd-only name is not untagged",
			annotations: map[string]string{
				"io.containerd.image.name": "evil.example.com/acme/app:v1",
			},
			opts:     ImageLoadOptions{AllowedRegistries: []string{"ghcr.io"}, AllowUntagged: true},
			wantDeny: true,
		},
		{
			name: "allowed containerd name wins over a lower-priority standard name",
			annotations: map[string]string{
				"org.opencontainers.image.ref.name": "evil.example.com/acme/app:v1",
				"io.containerd.image.name":          "ghcr.io/acme/app:v1",
			},
			opts: libpodImageLoadAllowlist(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := mustOCIImageLoadTarWithDescriptorAnnotations(t, tt.annotations)
			req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(payload))

			reason, err := newImageLoadPolicy(tt.opts).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if tt.wantDeny {
				if !strings.Contains(reason, "evil.example.com") {
					t.Fatalf("reason = %q, want the effective Podman name denied", reason)
				}
				return
			}
			if reason != "" {
				t.Fatalf("reason = %q, want the effective Podman name allowed", reason)
			}
			if err := req.Body.Close(); err != nil {
				t.Fatalf("close forwarded body: %v", err)
			}
		})
	}
}

func TestLibpodImageLoadAcceptsAValidOCIIndexArchive(t *testing.T) {
	payload := mustOCIIndexImageLoadTar(t, "ghcr.io/acme/multi:v1")
	req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(payload))

	reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil || reason != "" {
		t.Fatalf("inspect() = (%q, %v), want valid OCI index archive allowed", reason, err)
	}
	if err := req.Body.Close(); err != nil {
		t.Fatalf("close forwarded body: %v", err)
	}
}

func TestLibpodImageLoadUsesPodmanNamesForDockerArchiveTags(t *testing.T) {
	payload := mustImageLoadTar(t, `[{"RepoTags":["busybox:latest"]}]`)
	tests := []struct {
		name        string
		path        string
		opts        ImageLoadOptions
		wantDeny    bool
		wantReasonC string
	}{
		{
			name:        "native load does not mistake Podman localhost for Docker Hub official",
			path:        "/libpod/images/load",
			opts:        ImageLoadOptions{AllowOfficial: true},
			wantDeny:    true,
			wantReasonC: "localhost",
		},
		{
			name: "Docker-compat load retains Docker Hub official semantics",
			path: "/images/load",
			opts: ImageLoadOptions{AllowOfficial: true},
		},
		{
			name: "native load allows the Podman name when localhost is allowlisted",
			path: "/libpod/images/load",
			opts: ImageLoadOptions{AllowedRegistries: []string{"localhost"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewReader(payload))
			reason, err := newImageLoadPolicy(tt.opts).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if tt.wantDeny {
				if !strings.Contains(reason, tt.wantReasonC) {
					t.Fatalf("reason = %q, want it to mention %q", reason, tt.wantReasonC)
				}
				return
			}
			if reason != "" {
				t.Fatalf("reason = %q, want allow", reason)
			}
			if err := req.Body.Close(); err != nil {
				t.Fatalf("close forwarded body: %v", err)
			}
		})
	}
}

func TestImageLoadRejectsAnyUntaggedDockerManifestEntry(t *testing.T) {
	payload := mustImageLoadTar(t, `[
		{"RepoTags":["ghcr.io/acme/named:v1"]},
		{"RepoTags":[]}
	]`)

	for _, endpoint := range []string{"/images/load", "/libpod/images/load"} {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
			reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if !strings.Contains(reason, "untagged images are not allowed") {
				t.Fatalf("reason = %q, want the untagged archive member denied", reason)
			}
		})
	}
}

func TestLibpodImageLoadInspectsEveryMixedArchiveFormat(t *testing.T) {
	t.Run("valid OCI cannot hide an off-policy Docker fallback", func(t *testing.T) {
		payload := mustOCIImageLoadTarWithDockerManifest(t, []string{"ghcr.io/acme/oci:v1"}, `[{"RepoTags":["evil.example.com/acme/docker:v1"]}]`)
		req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(payload))

		reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if !strings.Contains(reason, "evil.example.com") {
			t.Fatalf("reason = %q, want the reachable Docker fallback denied", reason)
		}
	})

	t.Run("valid off-policy OCI cannot hide behind an allowed Docker manifest", func(t *testing.T) {
		payload := mustOCIImageLoadTarWithDockerManifest(t, []string{"evil.example.com/acme/oci:v1"}, `[{"RepoTags":["ghcr.io/acme/docker:v1"]}]`)
		req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(payload))

		reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if !strings.Contains(reason, "evil.example.com") {
			t.Fatalf("reason = %q, want Podman's effective OCI name denied", reason)
		}
	})

	t.Run("malformed OCI beside a valid Docker archive fails closed", func(t *testing.T) {
		payload := mustContainerArchiveTar(t,
			containerArchiveTestEntry{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
			containerArchiveTestEntry{name: "index.json", body: `{`},
			containerArchiveTestEntry{name: "manifest.json", body: `[{"RepoTags":["ghcr.io/acme/docker:v1"]}]`},
		)
		req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(payload))

		reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
		if reason != "" || err == nil || !strings.Contains(err.Error(), "OCI archive invalid") {
			t.Fatalf("inspect() = (%q, %v), want the uninspectable OCI candidate to fail closed", reason, err)
		}
	})

	t.Run("malformed Docker beside a valid OCI archive fails closed", func(t *testing.T) {
		payload := mustOCIImageLoadTarWithDockerManifest(t, []string{"ghcr.io/acme/oci:v1"}, `{`)
		req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(payload))

		reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
		if reason != "" || err == nil || !strings.Contains(err.Error(), "Docker archive invalid") {
			t.Fatalf("inspect() = (%q, %v), want the uninspectable Docker candidate to fail closed", reason, err)
		}
	})

	t.Run("OCI controls without their referenced blobs fail closed beside Docker", func(t *testing.T) {
		missingDigest := strings.Repeat("a", 64)
		payload := mustContainerArchiveTar(t,
			containerArchiveTestEntry{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
			containerArchiveTestEntry{name: "index.json", body: fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":123,"annotations":{"org.opencontainers.image.ref.name":"ghcr.io/acme/decoy:v1"}}]}`, missingDigest)},
			containerArchiveTestEntry{name: "manifest.json", body: `[{"RepoTags":["evil.example.com/acme/docker:v1"]}]`},
		)
		req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(payload))

		reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
		if reason != "" || err == nil || !strings.Contains(err.Error(), "OCI archive invalid") {
			t.Fatalf("inspect() = (%q, %v), want the uninspectable OCI candidate to fail closed", reason, err)
		}
	})
}

func TestLibpodImageLoadEnforcesDockerFallbackAfterLateOCIFailure(t *testing.T) {
	tests := []struct {
		name   string
		config []byte
		layer  []byte
	}{
		{
			name:   "malformed OCI config",
			config: []byte(`{`),
		},
		{
			name:   "unusable OCI layer",
			config: []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`),
			layer:  []byte("not a layer tar stream"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := mustOCIImageLoadEntriesWithPayloads(t, "ghcr.io/acme/decoy:v1", tt.config, tt.layer)
			entries = append(entries, daemonValidDockerImageLoadEntries(t, "evil.example.com/acme/fallback:v1")...)
			req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(mustContainerArchiveTar(t, entries...)))

			reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if !strings.Contains(reason, "evil.example.com") {
				t.Fatalf("reason = %q, want the reachable Docker fallback denied", reason)
			}
		})
	}
}

func TestLibpodImageLoadDoesNotTrimArchiveControlPaths(t *testing.T) {
	entries := mustOCIImageLoadEntries(t, "ghcr.io/acme/oci:v1")
	entries[0].name = " oci-layout"
	entries[1].name = " index.json"
	entries = append(entries, daemonValidDockerImageLoadEntries(t, "evil.example.com/acme/docker:v1")...)
	req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(mustContainerArchiveTar(t, entries...)))

	reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if !strings.Contains(reason, "evil.example.com") {
		t.Fatalf("reason = %q, want Podman's Docker fallback registry denied", reason)
	}
}

func TestLibpodImageLoadFailsClosedOnInvalidOCINameBesideDocker(t *testing.T) {
	entries := append(mustOCIImageLoadEntries(t, " ghcr.io/acme/oci:v1"), daemonValidDockerImageLoadEntries(t, "evil.example.com/acme/docker:v1")...)
	req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(mustContainerArchiveTar(t, entries...)))

	reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
	if reason != "" || err == nil || !strings.Contains(err.Error(), "OCI archive invalid") {
		t.Fatalf("inspect() = (%q, %v), want the invalid OCI name to fail closed", reason, err)
	}
}

func TestLibpodImageLoadTreatsPodmanPermissiveOCIAsLoadable(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]containerArchiveTestEntry) []containerArchiveTestEntry
	}{
		{
			name: "missing oci-layout",
			mutate: func(entries []containerArchiveTestEntry) []containerArchiveTestEntry {
				return entries[1:]
			},
		},
		{
			name: "unknown oci-layout version",
			mutate: func(entries []containerArchiveTestEntry) []containerArchiveTestEntry {
				entries[0].body = `{"imageLayoutVersion":"9.9.9"}`
				return entries
			},
		},
		{
			name: "index schema version is not validated by Podman",
			mutate: func(entries []containerArchiveTestEntry) []containerArchiveTestEntry {
				entries[1].body = strings.Replace(entries[1].body, `"schemaVersion":2`, `"schemaVersion":1`, 1)
				return entries
			},
		},
		{
			name: "empty descriptor media type is inferred by Podman",
			mutate: func(entries []containerArchiveTestEntry) []containerArchiveTestEntry {
				entries[1].body = strings.Replace(entries[1].body, `"mediaType":"application/vnd.oci.image.manifest.v1+json"`, `"mediaType":""`, 1)
				return entries
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := tt.mutate(mustOCIImageLoadEntries(t, "evil.example.com/acme/oci:v1"))
			entries = append(entries, daemonValidDockerImageLoadEntries(t, "ghcr.io/acme/docker:v1")...)
			req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(mustContainerArchiveTar(t, entries...)))

			reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if !strings.Contains(reason, "evil.example.com") {
				t.Fatalf("reason = %q, want Podman's load-effective OCI registry denied", reason)
			}
		})
	}
}

func TestCompatibilityImageLoadRequiresEveryValidMixedArchiveFormatToPassPolicy(t *testing.T) {
	payload := mustOCIImageLoadTarWithDockerManifest(t, []string{"evil.example.com/acme/oci:v1"}, `[{"RepoTags":["ghcr.io/acme/docker:v1"]}]`)
	req := httptest.NewRequest(http.MethodPost, "/images/load", bytes.NewReader(payload))

	reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if !strings.Contains(reason, "evil.example.com") {
		t.Fatalf("reason = %q, want the valid OCI member denied on the flavor-ambiguous compatibility path", reason)
	}
}

func TestLibpodImageLoadDoesNotFallbackAcrossArchiveLinkAlias(t *testing.T) {
	evil := mustOCIImageLoadEntries(t, "evil.example.com/acme/oci:v1")
	entries := []containerArchiveTestEntry{
		{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
		{name: "index.json", body: `{`},
	}
	entries = append(entries, evil[2:]...)
	entries = append(entries,
		containerArchiveTestEntry{name: "shadow", typ: tar.TypeSymlink, link: "."},
		containerArchiveTestEntry{name: "shadow/index.json", body: evil[1].body},
		containerArchiveTestEntry{name: "manifest.json", body: `[{"RepoTags":["ghcr.io/acme/docker:v1"]}]`},
	)
	payload := mustContainerArchiveTar(t, entries...)
	req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(payload))

	reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v, want a policy denial", err)
	}
	if !strings.Contains(reason, "cannot be fully inspected") {
		t.Fatalf("reason = %q, want the link-aliased OCI candidate denied before Docker fallback", reason)
	}
}

func TestLibpodImageLoadDoesNotFallbackWhenLinkSynthesizesOCIControls(t *testing.T) {
	evil := mustOCIImageLoadEntries(t, "evil.example.com/acme/oci:v1")
	entries := []containerArchiveTestEntry{{name: "shadow", typ: tar.TypeSymlink, link: "."}}
	for _, entry := range evil {
		entry.name = "shadow/" + entry.name
		entries = append(entries, entry)
	}
	entries = append(entries, containerArchiveTestEntry{name: "manifest.json", body: `[{"RepoTags":["ghcr.io/acme/docker:v1"]}]`})
	req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(mustContainerArchiveTar(t, entries...)))

	reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v, want a policy denial", err)
	}
	if !strings.Contains(reason, "cannot be fully inspected") {
		t.Fatalf("reason = %q, want link-synthesized OCI controls denied before Docker fallback", reason)
	}
}

func TestLibpodImageLoadDoesNotFallbackWhenOCIInspectionIsUnprovable(t *testing.T) {
	const allowedReference = "ghcr.io/acme/app:v1"
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
	configDigest := sha256.Sum256(config)

	tests := []struct {
		name    string
		archive func(*testing.T) []byte
	}{
		{
			name: "unreferenced extra blob",
			archive: func(t *testing.T) []byte {
				manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%x","size":%d},"layers":[]}`, configDigest, len(config)))
				manifestDigest := sha256.Sum256(manifest)
				index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%x","size":%d,"annotations":{"org.opencontainers.image.ref.name":%q}}]}`, manifestDigest, len(manifest), allowedReference)
				extra := []byte("unreferenced")
				extraDigest := sha256.Sum256(extra)
				return mustMixedOCIImageLoadTar(t, index,
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", configDigest), body: string(config)},
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", manifestDigest), body: string(manifest)},
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", extraDigest), body: string(extra)},
				)
			},
		},
		{
			name: "duplicate unreferenced blob",
			archive: func(t *testing.T) []byte {
				manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%x","size":%d},"layers":[]}`, configDigest, len(config)))
				manifestDigest := sha256.Sum256(manifest)
				index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%x","size":%d,"annotations":{"org.opencontainers.image.ref.name":%q}}]}`, manifestDigest, len(manifest), allowedReference)
				extraDigest := sha256.Sum256([]byte("first"))
				return mustMixedOCIImageLoadTar(t, index,
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", configDigest), body: string(config)},
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", manifestDigest), body: string(manifest)},
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", extraDigest), body: "first"},
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", extraDigest), body: "second"},
				)
			},
		},
		{
			name: "invalid non-selected index member",
			archive: func(t *testing.T) []byte {
				manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%x","size":%d},"layers":[]}`, configDigest, len(config)))
				manifestDigest := sha256.Sum256(manifest)
				missingDigest := strings.Repeat("a", 64)
				nested := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%x","size":%d,"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":1,"platform":{"architecture":"arm64","os":"linux"}}]}`, manifestDigest, len(manifest), missingDigest))
				nestedDigest := sha256.Sum256(nested)
				index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:%x","size":%d,"annotations":{"org.opencontainers.image.ref.name":%q}}]}`, nestedDigest, len(nested), allowedReference)
				return mustMixedOCIImageLoadTar(t, index,
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", configDigest), body: string(config)},
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", manifestDigest), body: string(manifest)},
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", nestedDigest), body: string(nested)},
				)
			},
		},
		{
			name: "external layer URL",
			archive: func(t *testing.T) []byte {
				layer := []byte("layer")
				layerDigest := sha256.Sum256(layer)
				manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%x","size":%d},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:%x","size":%d,"urls":["https://example.com/layer"]}]}`, configDigest, len(config), layerDigest, len(layer)))
				manifestDigest := sha256.Sum256(manifest)
				index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%x","size":%d,"annotations":{"org.opencontainers.image.ref.name":%q}}]}`, manifestDigest, len(manifest), allowedReference)
				return mustMixedOCIImageLoadTar(t, index,
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", configDigest), body: string(config)},
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", manifestDigest), body: string(manifest)},
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", layerDigest), body: string(layer)},
				)
			},
		},
		{
			name: "external manifest URL",
			archive: func(t *testing.T) []byte {
				manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%x","size":%d},"layers":[]}`, configDigest, len(config)))
				manifestDigest := sha256.Sum256(manifest)
				index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%x","size":%d,"urls":["https://example.com/manifest"],"annotations":{"org.opencontainers.image.ref.name":%q}}]}`, manifestDigest, len(manifest), allowedReference)
				return mustMixedOCIImageLoadTar(t, index,
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", configDigest), body: string(config)},
					containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", manifestDigest), body: string(manifest)},
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(tt.archive(t)))
			reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v, want a policy denial", err)
			}
			if reason == "" {
				t.Fatal("inspect() allowed an OCI archive whose contents cannot be fully verified")
			}
		})
	}
}

func TestLibpodImageLoadEnforcesDaemonValidSHA512OCI(t *testing.T) {
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
	configDigest := sha512.Sum512(config)
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha512:%x","size":%d},"layers":[]}`, configDigest, len(config)))
	manifestDigest := sha512.Sum512(manifest)
	index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha512:%x","size":%d,"annotations":{"org.opencontainers.image.ref.name":"evil.example.com/acme/oci:v1"}}]}`, manifestDigest, len(manifest))
	entries := []containerArchiveTestEntry{
		containerArchiveTestEntry{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
		containerArchiveTestEntry{name: "index.json", body: index},
		containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha512/%x", configDigest), body: string(config)},
		containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha512/%x", manifestDigest), body: string(manifest)},
	}
	entries = append(entries, daemonValidDockerImageLoadEntries(t, "ghcr.io/acme/docker:v1")...)
	req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(mustContainerArchiveTar(t, entries...)))

	reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if !strings.Contains(reason, "evil.example.com") {
		t.Fatalf("reason = %q, want the SHA-512 OCI registry denied", reason)
	}
}

func TestLibpodImageLoadEnforcesDaemonValidSHA384OCI(t *testing.T) {
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
	configDigest := sha512.Sum384(config)
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha384:%x","size":%d},"layers":[]}`, configDigest, len(config)))
	manifestDigest := sha512.Sum384(manifest)
	index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha384:%x","size":%d,"annotations":{"org.opencontainers.image.ref.name":"evil.example.com/acme/oci:v1"}}]}`, manifestDigest, len(manifest))
	entries := []containerArchiveTestEntry{
		containerArchiveTestEntry{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
		containerArchiveTestEntry{name: "index.json", body: index},
		containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha384/%x", configDigest), body: string(config)},
		containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha384/%x", manifestDigest), body: string(manifest)},
	}
	entries = append(entries, daemonValidDockerImageLoadEntries(t, "ghcr.io/acme/docker:v1")...)
	req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(mustContainerArchiveTar(t, entries...)))

	reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if !strings.Contains(reason, "evil.example.com") {
		t.Fatalf("reason = %q, want the SHA-384 OCI registry denied", reason)
	}
}

func TestLibpodImageLoadRejectsArchiveLinkAliases(t *testing.T) {
	tests := []struct {
		name    string
		entries func(*testing.T) []containerArchiveTestEntry
	}{
		{
			name: "symlink parent aliases the inspected control path",
			entries: func(t *testing.T) []containerArchiveTestEntry {
				allowed := mustOCIImageLoadEntries(t, "ghcr.io/acme/app:v1")
				evil := mustOCIImageLoadEntries(t, "evil.example.com/acme/app:v1")
				return append(allowed,
					containerArchiveTestEntry{name: "shadow", typ: tar.TypeSymlink, link: "."},
					containerArchiveTestEntry{name: "shadow/index.json", body: evil[1].body},
				)
			},
		},
		{
			name: "hardlink aliases an inspected blob path",
			entries: func(t *testing.T) []containerArchiveTestEntry {
				allowed := mustOCIImageLoadEntries(t, "ghcr.io/acme/app:v1")
				return append(allowed,
					containerArchiveTestEntry{name: "shadow", typ: tar.TypeDir},
					containerArchiveTestEntry{name: "shadow/manifest", typ: tar.TypeLink, link: allowed[3].name},
					containerArchiveTestEntry{name: "shadow/manifest", body: "replacement"},
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(mustContainerArchiveTar(t, tt.entries(t)...)))
			reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v, want a policy denial", err)
			}
			if reason == "" {
				t.Fatal("inspect() allowed an archive containing an outer link alias")
			}
		})
	}
}

func TestOCIManifestGraphBoundsRepeatedDescriptorVisits(t *testing.T) {
	repeatedGraph := func(depth int) (imageLoadOCIIndexDescriptor, map[string]imageLoadOCIBlob) {
		config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
		configDigest := sha256.Sum256(config)
		blobs := map[string]imageLoadOCIBlob{
			fmt.Sprintf("blobs/sha256/%x", configDigest): {size: int64(len(config)), digestMatch: true, body: config},
		}
		manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%x","size":%d},"layers":[]}`, configDigest, len(config)))
		manifestDigest := sha256.Sum256(manifest)
		blobs[fmt.Sprintf("blobs/sha256/%x", manifestDigest)] = imageLoadOCIBlob{size: int64(len(manifest)), digestMatch: true, body: manifest}
		descriptor := imageLoadOCIIndexDescriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: fmt.Sprintf("sha256:%x", manifestDigest), Size: int64(len(manifest))}

		for range depth {
			index, err := json.Marshal(imageLoadOCIIndex{SchemaVersion: 2, Manifests: []imageLoadOCIIndexDescriptor{descriptor, descriptor}})
			if err != nil {
				t.Fatalf("marshal repeated OCI index: %v", err)
			}
			digest := sha256.Sum256(index)
			blobs[fmt.Sprintf("blobs/sha256/%x", digest)] = imageLoadOCIBlob{size: int64(len(index)), digestMatch: true, body: index}
			descriptor = imageLoadOCIIndexDescriptor{MediaType: "application/vnd.oci.image.index.v1+json", Digest: fmt.Sprintf("sha256:%x", digest), Size: int64(len(index))}
		}
		return descriptor, blobs
	}

	t.Run("a small repeated-child DAG remains valid", func(t *testing.T) {
		descriptor, blobs := repeatedGraph(4)
		if err := validateImageLoadOCIManifestGraph(descriptor, blobs); err != nil {
			t.Fatalf("validateImageLoadOCIManifestGraph() error = %v, want valid repeated-child DAG", err)
		}
	})

	t.Run("a large repeated-child DAG stops at the visit budget", func(t *testing.T) {
		descriptor, blobs := repeatedGraph(13)
		err := validateImageLoadOCIManifestGraph(descriptor, blobs)
		if err == nil || !strings.Contains(err.Error(), "descriptor visit limit") {
			t.Fatalf("validateImageLoadOCIManifestGraph() error = %v, want descriptor visit limit", err)
		}
	})
}

func TestLibpodImageLoadRejectsCanonicalControlFileOverwrites(t *testing.T) {
	allowedIndex := `{"schemaVersion":2,"manifests":[{"annotations":{"org.opencontainers.image.ref.name":"ghcr.io/acme/app:v1"}}]}`
	evilIndex := `{"schemaVersion":2,"manifests":[{"annotations":{"org.opencontainers.image.ref.name":"evil.example.com/acme/app:v1"}}]}`
	tests := []struct {
		name    string
		entries []containerArchiveTestEntry
		want    string
	}{
		{
			name: "dot-prefixed OCI index overwrites the inspected path",
			entries: []containerArchiveTestEntry{
				{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
				{name: "index.json", body: allowedIndex},
				{name: "./index.json", body: evilIndex},
			},
			want: "duplicate index.json",
		},
		{
			name: "dot-segment Docker manifest overwrites the inspected path",
			entries: []containerArchiveTestEntry{
				{name: "manifest.json", body: `[{"RepoTags":["ghcr.io/acme/app:v1"]}]`},
				{name: "metadata/../manifest.json", body: `[{"RepoTags":["evil.example.com/acme/app:v1"]}]`},
			},
			want: "duplicate manifest.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := mustContainerArchiveTar(t, tt.entries...)
			req := httptest.NewRequest(http.MethodPost, "/libpod/images/load", bytes.NewReader(payload))

			reason, err := newImageLoadPolicy(libpodImageLoadAllowlist()).inspect(nil, req, NormalizePath(req.URL.Path))
			if reason != "" {
				t.Fatalf("reason = %q, want an inspection error", reason)
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("inspect() error = %v, want %q", err, tt.want)
			}
		})
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
// otherwise. The flag gates both forms; allowed body imports additionally go
// through the bounded spool. The URL cases also pin the source named by a
// denial.
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
			// Podman's scalar decode takes the LAST value of one repeated key.
			name:        "names the last value of a repeated url the way Podman reads it",
			opts:        ImagePullOptions{},
			rawQuery:    "URL=http%3A%2F%2Ffirst.example.com%2Fx.tar&URL=http%3A%2F%2Flast.example.com%2Fx.tar",
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

func TestLibpodImageImportBoundsBodyButNotURLImports(t *testing.T) {
	const maxImportBodyBytes = int64(512 << 20)

	t.Run("oversized body import returns 413", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/libpod/images/import", nil)
		req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}
		req.ContentLength = maxImportBodyBytes + 1

		reason, err := newImagePullPolicy(ImagePullOptions{AllowImports: true}).inspectLibpodImport(nil, req, NormalizePath(req.URL.Path))
		if reason != "" {
			t.Fatalf("reason = %q, want request rejection", reason)
		}
		rejection, ok := requestRejectionFromError(err)
		if !ok {
			t.Fatalf("inspectLibpodImport() error = %v, want request rejection", err)
		}
		if rejection.status != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want %d", rejection.status, http.StatusRequestEntityTooLarge)
		}
		if !strings.Contains(rejection.reason, "request body exceeds") {
			t.Fatalf("reason = %q, want deterministic body-size denial", rejection.reason)
		}
	})

	t.Run("small body import is replayed unchanged", func(t *testing.T) {
		payload := []byte("rootfs archive bytes")
		req := httptest.NewRequest(http.MethodPost, "/libpod/images/import", bytes.NewReader(payload))

		reason, err := newImagePullPolicy(ImagePullOptions{AllowImports: true}).inspectLibpodImport(nil, req, NormalizePath(req.URL.Path))
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpodImport() = (%q, %v), want allow", reason, err)
		}
		forwarded, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read forwarded body: %v", err)
		}
		if !bytes.Equal(forwarded, payload) {
			t.Fatalf("forwarded body = %q, want %q", forwarded, payload)
		}
		if err := req.Body.Close(); err != nil {
			t.Fatalf("close forwarded body: %v", err)
		}
		if req.ContentLength != int64(len(payload)) {
			t.Fatalf("content length = %d, want %d", req.ContentLength, len(payload))
		}
	})

	t.Run("empty body import is forwarded as an empty readable body", func(t *testing.T) {
		original := &trackingReadCloser{reader: bytes.NewReader(nil)}
		req := httptest.NewRequest(http.MethodPost, "/libpod/images/import", nil)
		req.Body = original

		reason, err := newImagePullPolicy(ImagePullOptions{AllowImports: true}).inspectLibpodImport(nil, req, NormalizePath(req.URL.Path))
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpodImport() = (%q, %v), want allow", reason, err)
		}
		if !original.closed {
			t.Fatal("original empty body was not closed")
		}
		if req.Body == original {
			t.Fatal("forwarded request kept the closed original body")
		}
		forwarded, err := io.ReadAll(req.Body)
		if err != nil || len(forwarded) != 0 {
			t.Fatalf("read forwarded body = (%q, %v), want empty", forwarded, err)
		}
	})

	t.Run("URL import retains the coarse allow_imports gate without a body cap", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/libpod/images/import?URL=https%3A%2F%2Fexample.com%2Frootfs.tar", nil)
		req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}
		req.ContentLength = maxImportBodyBytes + 1

		reason, err := newImagePullPolicy(ImagePullOptions{AllowImports: true}).inspectLibpodImport(nil, req, NormalizePath(req.URL.Path))
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpodImport() = (%q, %v), want URL import allowed without reading the body", reason, err)
		}
	})

	t.Run("a nonempty whitespace URL remains the URL form Podman selects", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/libpod/images/import?URL=%20", nil)
		req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}
		req.ContentLength = maxImportBodyBytes + 1

		reason, err := newImagePullPolicy(ImagePullOptions{AllowImports: true}).inspectLibpodImport(nil, req, NormalizePath(req.URL.Path))
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpodImport() = (%q, %v), want Podman's nonempty URL form", reason, err)
		}
	})

	t.Run("the last repeated URL value decides whether Podman reads the body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/libpod/images/import?URL=https%3A%2F%2Fexample.com%2Frootfs.tar&URL=", nil)
		req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}
		req.ContentLength = maxImportBodyBytes + 1

		_, err := newImagePullPolicy(ImagePullOptions{AllowImports: true}).inspectLibpodImport(nil, req, NormalizePath(req.URL.Path))
		rejection, ok := requestRejectionFromError(err)
		if !ok || rejection.status != http.StatusRequestEntityTooLarge {
			t.Fatalf("inspectLibpodImport() error = %v, want 413 for effective body import", err)
		}
	})
}

func mustOCIImageLoadTar(t *testing.T, references []string) []byte {
	t.Helper()

	return mustOCIImageLoadTarWithDockerManifest(t, references, "")
}

func mustOCIImageLoadEntries(t *testing.T, reference string) []containerArchiveTestEntry {
	t.Helper()

	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
	return mustOCIImageLoadEntriesWithPayloads(t, reference, config, nil)
}

func mustOCIImageLoadEntriesWithPayloads(t *testing.T, reference string, config, layer []byte) []containerArchiveTestEntry {
	t.Helper()

	configDigest := sha256.Sum256(config)
	layers := ""
	entries := []containerArchiveTestEntry{
		{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
	}
	if layer != nil {
		layerDigest := sha256.Sum256(layer)
		layers = fmt.Sprintf(`{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:%x","size":%d}`, layerDigest, len(layer))
		entries = append(entries, containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", layerDigest), body: string(layer)})
	}
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%x","size":%d},"layers":[%s]}`, configDigest, len(config), layers))
	manifestDigest := sha256.Sum256(manifest)
	index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%x","size":%d,"annotations":{"org.opencontainers.image.ref.name":%q}}]}`, manifestDigest, len(manifest), reference)
	entries = append(entries,
		containerArchiveTestEntry{name: "index.json", body: index},
		containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", configDigest), body: string(config)},
		containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", manifestDigest), body: string(manifest)},
	)
	return entries
}

func daemonValidDockerImageLoadEntries(t *testing.T, reference string) []containerArchiveTestEntry {
	t.Helper()

	layer := mustContainerArchiveTar(t)
	layerDigest := sha256.Sum256(layer)
	config := fmt.Sprintf(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:%x"]},"config":{}}`, layerDigest)
	manifest := fmt.Sprintf(`[{"Config":"docker-config.json","RepoTags":[%q],"Layers":["docker-layer.tar"]}]`, reference)
	return []containerArchiveTestEntry{
		{name: "manifest.json", body: manifest},
		{name: "docker-config.json", body: config},
		{name: "docker-layer.tar", body: string(layer)},
	}
}

func mustMixedOCIImageLoadTar(t *testing.T, index string, blobs ...containerArchiveTestEntry) []byte {
	t.Helper()

	entries := []containerArchiveTestEntry{
		{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
		{name: "index.json", body: index},
	}
	entries = append(entries, blobs...)
	entries = append(entries, containerArchiveTestEntry{name: "manifest.json", body: `[{"RepoTags":["ghcr.io/acme/fallback:v1"]}]`})
	return mustContainerArchiveTar(t, entries...)
}

func mustOCIImageLoadTarWithDockerManifest(t *testing.T, references []string, dockerManifest string) []byte {
	t.Helper()

	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
	configDigest := sha256.Sum256(config)
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%x","size":%d},"layers":[]}`, configDigest, len(config)))
	manifestDigest := sha256.Sum256(manifest)

	descriptors := make([]map[string]any, 0, len(references))
	for _, reference := range references {
		descriptor := map[string]any{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"digest":    fmt.Sprintf("sha256:%x", manifestDigest),
			"size":      len(manifest),
		}
		if reference != "" {
			descriptor["annotations"] = map[string]string{"org.opencontainers.image.ref.name": reference}
		}
		descriptors = append(descriptors, descriptor)
	}
	index, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": descriptors})
	if err != nil {
		t.Fatalf("marshal OCI index: %v", err)
	}

	entries := []containerArchiveTestEntry{
		{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
		{name: "index.json", body: string(index)},
		{name: fmt.Sprintf("blobs/sha256/%x", configDigest), body: string(config)},
		{name: fmt.Sprintf("blobs/sha256/%x", manifestDigest), body: string(manifest)},
	}
	if dockerManifest != "" {
		entries = append(entries, containerArchiveTestEntry{name: "manifest.json", body: dockerManifest})
	}
	return mustContainerArchiveTar(t, entries...)
}

func mustOCIImageLoadTarWithDescriptorAnnotations(t *testing.T, annotations map[string]string) []byte {
	t.Helper()

	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
	configDigest := sha256.Sum256(config)
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%x","size":%d},"layers":[]}`, configDigest, len(config)))
	manifestDigest := sha256.Sum256(manifest)
	index, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"manifests": []map[string]any{{
			"mediaType":   "application/vnd.oci.image.manifest.v1+json",
			"digest":      fmt.Sprintf("sha256:%x", manifestDigest),
			"size":        len(manifest),
			"annotations": annotations,
		}},
	})
	if err != nil {
		t.Fatalf("marshal OCI index: %v", err)
	}

	return mustContainerArchiveTar(t,
		containerArchiveTestEntry{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
		containerArchiveTestEntry{name: "index.json", body: string(index)},
		containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", configDigest), body: string(config)},
		containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", manifestDigest), body: string(manifest)},
	)
}

func mustOCIIndexImageLoadTar(t *testing.T, reference string) []byte {
	t.Helper()

	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
	configDigest := sha256.Sum256(config)
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%x","size":%d},"layers":[]}`, configDigest, len(config)))
	manifestDigest := sha256.Sum256(manifest)
	nestedIndex := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%x","size":%d,"platform":{"architecture":"amd64","os":"linux"}}]}`, manifestDigest, len(manifest)))
	nestedDigest := sha256.Sum256(nestedIndex)
	index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:%x","size":%d,"annotations":{"org.opencontainers.image.ref.name":%q}}]}`, nestedDigest, len(nestedIndex), reference)

	return mustContainerArchiveTar(t,
		containerArchiveTestEntry{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
		containerArchiveTestEntry{name: "index.json", body: index},
		containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", configDigest), body: string(config)},
		containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", manifestDigest), body: string(manifest)},
		containerArchiveTestEntry{name: fmt.Sprintf("blobs/sha256/%x", nestedDigest), body: string(nestedIndex)},
	)
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
			name:       "libpod image load denies behind a Podman prerelease prefix",
			policy:     PolicyConfig{ImageLoad: libpodImageLoadAllowlist()},
			target:     "/v5.8.1-dev/libpod/images/load",
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
			name:       "libpod image import denies behind a four-component Podman prefix",
			target:     "/v5.8.1.2/libpod/images/import?URL=http%3A%2F%2Fevil.example.com%2Fx.tar",
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
			name:       "libpod local image load denies behind a four-component Podman prefix",
			policy:     PolicyConfig{ImageLoad: ImageLoadOptions{AllowAllRegistries: true}},
			target:     "/v5.8.1.2/libpod/local/images/load?path=%2Fetc",
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
			name:       "libpod local build denies behind a Podman prerelease prefix",
			target:     "/v5.8.1-dev/libpod/local/build?localcontextdir=%2Fetc",
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
