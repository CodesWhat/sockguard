package filter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/imagetrust"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// allowAllRegistryPolicy is the registry scope tests that inject a verifier
// directly use, so they exercise verification rather than the registry gate.
func allowAllRegistryPolicy() imagePullPolicy {
	return newImagePullPolicy(ImagePullOptions{AllowAllRegistries: true})
}

type countingFetcher struct {
	calls atomic.Int32
	inner signatureFetcher
}

func (c *countingFetcher) FetchCandidates(ctx context.Context, logger *slog.Logger, ref string) ([]imagetrust.Candidate, error) {
	c.calls.Add(1)
	return c.inner.FetchCandidates(ctx, logger, ref)
}

func TestVerifyImageTrustScopesRegistryBeforeFetching(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		registry imagePullPolicy
		image    string
		want     string
		calls    int32
	}{
		{"unlisted host denied without fetch", newImagePullPolicy(ImagePullOptions{AllowedRegistries: []string{"ghcr.io"}}), "10.0.0.5:8080/admin/internal:latest", `registry "10.0.0.5:8080" is not allowlisted`, 0},
		{"listed host fetched", newImagePullPolicy(ImagePullOptions{AllowedRegistries: []string{"ghcr.io"}}), "ghcr.io/org/app:1.0", "", 1},
		{"allow all fetched", allowAllRegistryPolicy(), "10.0.0.5:8080/admin/internal:latest", "", 1},
		{"zero policy fails closed", imagePullPolicy{}, "ghcr.io/org/app:1.0", `registry "ghcr.io" is not allowlisted`, 0},
		{"official allowed", newImagePullPolicy(ImagePullOptions{AllowOfficial: true}), "nginx:1", "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fetcher := &countingFetcher{inner: oneCandidateFetcher()}
			fields := imageTrustFields{
				verifier: &mockImageVerifier{},
				fetcher:  fetcher,
				cfg:      imagetrust.Config{Mode: imagetrust.ModeEnforce},
				registry: tt.registry,
			}
			reason, _ := verifyImageTrust(context.Background(), nil, fields, tt.image, "container create")
			if tt.want == "" && reason != "" {
				t.Fatalf("reason = %q, want allow", reason)
			}
			if tt.want != "" && !strings.Contains(reason, tt.want) {
				t.Fatalf("reason = %q, want substring %q", reason, tt.want)
			}
			if got := fetcher.calls.Load(); got != tt.calls {
				t.Fatalf("fetch calls = %d, want %d", got, tt.calls)
			}
		})
	}
}

func TestBuildImageTrustFieldsRegistryScope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		opts          ImageTrustOptions
		allowedImages []string
		ref           string
		allowed       bool
	}{
		{"no scope", ImageTrustOptions{}, nil, "ghcr.io/o/a:1", false},
		{"allowed_images pins registry", ImageTrustOptions{}, []string{"ghcr.io/o/a:1"}, "ghcr.io/o/a:1", true},
		{"allowed_registries hit", ImageTrustOptions{AllowedRegistries: []string{"ghcr.io"}}, nil, "ghcr.io/o/a:1", true},
		{"allowed_registries miss", ImageTrustOptions{AllowedRegistries: []string{"ghcr.io"}}, []string{"ghcr.io/o/a:1"}, "evil.example/o/a:1", false},
		{"allow_all", ImageTrustOptions{AllowAllRegistries: true}, nil, "evil.example/o/a:1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.opts.Mode = "warn"
			tt.opts.AllowedSigningKeys = []SigningKeyOptions{{PEM: generateTestECDSAPEM(t)}}
			f := buildImageTrustFields(tt.opts, tt.allowedImages)
			if f.initErr != nil {
				t.Fatalf("initErr = %v", f.initErr)
			}
			got := f.registry.denyReasonForReference(tt.ref, "x") == ""
			if got != tt.allowed {
				t.Fatalf("allowed = %v, want %v", got, tt.allowed)
			}
		})
	}
}

func TestClientSafeTrustFailureHidesRegistryBody(t *testing.T) {
	t.Parallel()
	terr := &transport.Error{StatusCode: http.StatusForbidden, Errors: []transport.Diagnostic{{Code: "DENIED", Message: "internal-secret-body"}}}
	got := clientSafeTrustFailure(fmt.Errorf("fetch: %w", terr), "raw message with internal-secret-body")
	if !strings.Contains(got, "registry returned HTTP 403") || strings.Contains(got, "internal-secret-body") {
		t.Fatalf("got %q", got)
	}
	if got := clientSafeTrustFailure(errors.New("boom"), "kept message"); got != "kept message" {
		t.Fatalf("non-transport error rewrote message: %q", got)
	}
	if got := clientSafeTrustFailure(nil, "kept message"); got != "kept message" {
		t.Fatalf("nil error rewrote message: %q", got)
	}
}
