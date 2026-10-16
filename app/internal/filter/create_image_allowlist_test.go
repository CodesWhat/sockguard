package filter

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/imagetrust"
	"github.com/codeswhat/sockguard/v2/app/internal/logging"
)

func TestCreateImageAllowlistProfilesAndRollout(t *testing.T) {
	rule, err := CompileRule(Rule{Methods: []string{"POST"}, Pattern: "/**", Action: ActionAllow})
	if err != nil {
		t.Fatal(err)
	}
	for _, surface := range []struct {
		path string
		body string
	}{
		{"/containers/create", `{"Image":"docker.io/library/busybox:1.37"}`},
		{"/libpod/containers/create", `{"image":"docker.io/library/busybox:1.37","systemd":"false"}`},
		{"/services/app/update?version=1", `{"TaskTemplate":{"ContainerSpec":{"Image":"docker.io/library/busybox:1.37"}}}`},
	} {
		for _, mode := range []string{"enforce", "warn", "audit"} {
			t.Run(surface.path+"/"+mode, func(t *testing.T) {
				images := []string{"docker.io/library/alpine:3.22"}
				policy := PolicyConfig{
					ContainerCreate:       ContainerCreateOptions{AllowedImages: images},
					LibpodContainerCreate: LibpodContainerCreateOptions{AllowedImages: images},
					Service:               ServiceOptions{AllowedImages: images, AllowAllRegistries: true},
				}
				handler := MiddlewareWithOptions([]*CompiledRule{rule}, testLogger(), Options{
					PolicyConfig:   PolicyConfig{Service: ServiceOptions{AllowAllRegistries: true}},
					Profiles:       map[string]Policy{"restricted": {Rules: []*CompiledRule{rule}, PolicyConfig: policy}},
					ResolveProfile: func(r *http.Request) (string, bool) { name := r.Header.Get("X-Test-Profile"); return name, name != "" },
				})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Fatal(err)
					}
					_, _ = w.Write(body)
				}))
				for _, profile := range []string{"restricted", ""} {
					req := httptest.NewRequest(http.MethodPost, surface.path, strings.NewReader(surface.body))
					req.Header.Set("X-Test-Profile", profile)
					meta := &logging.RequestMeta{RolloutMode: mode}
					req = req.WithContext(logging.WithMeta(req.Context(), meta))
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, req)
					if profile == "restricted" && mode == "enforce" {
						if response.Code != http.StatusForbidden {
							t.Fatalf("status %d, want 403", response.Code)
						}
					} else {
						if response.Code != http.StatusOK || response.Body.String() != surface.body {
							t.Fatalf("pass-through changed: %d %s", response.Code, response.Body.String())
						}
						if profile == "restricted" && (meta.Decision != logging.DecisionWouldDeny || !strings.Contains(meta.Reason, "not allowlisted")) {
							t.Fatalf("missing allowlist rollout verdict: %+v", meta)
						}
					}
				}
			})
		}
	}
}

func TestCreateImageAllowlistWithImageTrust(t *testing.T) {
	const image = "registry.example.com/app:v1"
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, surface := range []string{"container", "libpod", "service"} {
		t.Run(surface, func(t *testing.T) {
			verifier := &mockImageVerifier{}
			fetcher := &mockSignatureFetcher{candidates: []imagetrust.Candidate{{DigestHex: "00", ImageDigest: digest}}}
			trust := imagetrust.Config{Mode: imagetrust.ModeEnforce}
			var inspect func(*slog.Logger, *http.Request, string) (string, error)
			path, body := "/containers/create", `{"Image":"`+image+`"}`
			switch surface {
			case "container":
				p := newContainerCreatePolicy(ContainerCreateOptions{AllowedImages: []string{image}})
				p.imageTrustVerifier, p.imageFetcher, p.imageTrustCfg = verifier, fetcher, trust
				inspect = p.inspect
			case "libpod":
				p := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedImages: []string{image}})
				p.imageTrustVerifier, p.imageFetcher, p.imageTrustCfg = verifier, fetcher, trust
				inspect, path, body = p.inspect, "/libpod/containers/create", `{"image":"`+image+`","systemd":"false"}`
			case "service":
				p := newServicePolicy(ServiceOptions{AllowedImages: []string{image}, AllowAllRegistries: true})
				p.imageTrust = imageTrustFields{verifier: verifier, fetcher: fetcher, cfg: trust}
				inspect, path, body = p.inspect, "/services/create", `{"TaskTemplate":{"ContainerSpec":{"Image":"`+image+`"}}}`
			}
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			reason, err := inspect(testLogger(), req, path)
			if err != nil || reason != "" {
				t.Fatalf("inspect = %q, %v", reason, err)
			}
			pinned, err := io.ReadAll(req.Body)
			if err != nil || !strings.Contains(string(pinned), "registry.example.com/app@"+digest) {
				t.Fatalf("missing verified digest: %s, %v", pinned, err)
			}
			req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(strings.ReplaceAll(body, image, "registry.example.com/evil:v1")))
			reason, err = inspect(testLogger(), req, path)
			if err != nil || !strings.Contains(reason, "not allowlisted") {
				t.Fatalf("inspect non-allowed image = %q, %v", reason, err)
			}
			if verifier.lastCalled != image {
				t.Fatalf("signature verifier received non-allowed image %q", verifier.lastCalled)
			}
		})
	}
}
