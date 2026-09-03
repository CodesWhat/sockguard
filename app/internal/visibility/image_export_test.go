package visibility

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

func TestVisibilityImageExportRouteClassification(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   imageExportRoute
	}{
		{name: "Docker batch export", method: http.MethodGet, path: "/images/get", want: imageExportRouteDockerBatch},
		{name: "Docker per-image export", method: http.MethodGet, path: "/images/app/get", want: imageExportRouteDockerSingle},
		{name: "Docker namespaced per-image export", method: http.MethodGet, path: "/images/registry.example/team/app/get", want: imageExportRouteDockerSingle},
		{name: "libpod batch export", method: http.MethodGet, path: "/libpod/images/export", want: imageExportRouteLibpodBatch},
		{name: "Docker image list collection", method: http.MethodGet, path: "/images/json"},
		{name: "Docker batch export HEAD", method: http.MethodHead, path: "/images/get"},
		{name: "Docker per-image export POST", method: http.MethodPost, path: "/images/app/get"},
		{name: "libpod batch export POST", method: http.MethodPost, path: "/libpod/images/export"},
		{name: "native libpod per-image export", method: http.MethodGet, path: "/libpod/images/app/get"},
		{name: "unrelated subresource", method: http.MethodGet, path: "/containers/app/get"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyImageExportRoute(tt.method, tt.path); got != tt.want {
				t.Fatalf("classifyImageExportRoute(%q, %q) = %d, want %d", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestVisibilityRefusesDockerImageExportsWithUnenumerablePlatformEffects(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "query-selected batch export", target: "/v1.53/images/get?names=visible%3A1"},
		{name: "per-image export with omitted platform", target: "/v1.53/images/visible%3A1/get"},
		{name: "per-image export with explicit platform", target: "/v1.53/images/visible%3A1/get?platform=linux%2Farm64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspectCalls := 0
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{
				inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
					inspectCalls++
					return map[string]string{"com.sockguard.visible": "true"}, true, nil
				},
			})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("Docker image export with unenumerable platform effects reached the upstream")
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.target, nil))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if inspectCalls != 0 {
				t.Fatalf("inspect calls = %d, want none before refusing an effect set that cannot be enumerated", inspectCalls)
			}
		})
	}
}

func TestVisibilityLibpodImageReadsApplyPatternPolicy(t *testing.T) {
	for _, path := range []string{
		"/libpod/images/app/json",
		"/libpod/images/app/history",
		"/libpod/images/app/get",
		"/libpod/images/app/tree",
		"/libpod/images/app/changes",
		"/libpod/images/app/exists",
	} {
		t.Run(path, func(t *testing.T) {
			reached := false
			var inspected string
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				ImagePatterns: []string{"registry.allowed/**"},
			}, visibilityDeps{
				inspectResourceMeta: func(_ context.Context, kind dockerresource.Kind, id string) (*resourceMeta, bool, error) {
					if kind != dockerresource.KindImage {
						t.Fatalf("inspect kind = %q, want %q", kind, dockerresource.KindImage)
					}
					inspected = id
					return &resourceMeta{repoTags: []string{"registry.denied/team/app:1"}}, true, nil
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

			if rec.Code != http.StatusNotFound || reached {
				t.Fatalf("status = %d reached = %v, want %d and false; body: %s", rec.Code, reached, http.StatusNotFound, rec.Body.String())
			}
			if inspected != "app" {
				t.Fatalf("inspected image = %q, want app", inspected)
			}
		})
	}
}

func TestVisibilityLibpodPerImageExportRequiresSelectorAndPatternConjunction(t *testing.T) {
	tests := []struct {
		name       string
		labels     map[string]string
		repoTags   []string
		wantStatus int
		wantReach  bool
	}{
		{
			name:       "selector matches but pattern does not",
			labels:     map[string]string{"com.sockguard.visible": "true"},
			repoTags:   []string{"registry.denied/team/app:1"},
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "pattern matches but selector does not",
			labels:     map[string]string{"com.sockguard.visible": "false"},
			repoTags:   []string{"registry.allowed/team/app:1"},
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "selector and pattern both match",
			labels:     map[string]string{"com.sockguard.visible": "true"},
			repoTags:   []string{"registry.allowed/team/app:1"},
			wantStatus: http.StatusNoContent,
			wantReach:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
				ImagePatterns:         []string{"registry.allowed/**"},
			}, visibilityDeps{
				inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
					return tt.labels, true, nil
				},
				inspectResourceDetails: func(_ context.Context, kind dockerresource.Kind, id string) (*resourceDetails, bool, error) {
					if kind != dockerresource.KindImage || id != "app" {
						t.Fatalf("inspect = %s/%q, want %s/app", kind, id, dockerresource.KindImage)
					}
					return &resourceDetails{
						labels: tt.labels,
						meta:   &resourceMeta{repoTags: tt.repoTags},
					}, true, nil
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/libpod/images/app/get", nil))

			if rec.Code != tt.wantStatus || reached != tt.wantReach {
				t.Fatalf("status = %d reached = %v, want %d and %v; body: %s", rec.Code, reached, tt.wantStatus, tt.wantReach, rec.Body.String())
			}
		})
	}
}

func TestVisibilityPreflightsEveryLibpodBatchExportReference(t *testing.T) {
	var gotIDs []string
	reached := false
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindImage {
				t.Fatalf("inspect kind = %q, want %q", kind, dockerresource.KindImage)
			}
			gotIDs = append(gotIDs, id)
			return map[string]string{"com.sockguard.visible": "true"}, true, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v5.8.1/libpod/images/export?references=one%3A1&references=two%3A1", nil))

	if rec.Code != http.StatusNoContent || !reached {
		t.Fatalf("status = %d reached = %v, want %d and true; body: %s", rec.Code, reached, http.StatusNoContent, rec.Body.String())
	}
	if strings.Join(gotIDs, ",") != "one:1,two:1" {
		t.Fatalf("inspected images = %#v, want both selected references in order", gotIDs)
	}
}

func TestVisibilityDeniesWholeLibpodBatchExportWhenAnyReferenceIsHidden(t *testing.T) {
	reached := false
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{
		inspectResource: func(_ context.Context, _ dockerresource.Kind, id string) (map[string]string, bool, error) {
			visible := "true"
			if id == "hidden:1" {
				visible = "false"
			}
			return map[string]string{"com.sockguard.visible": visible}, true, nil
		},
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/libpod/images/export?references=visible%3A1&references=hidden%3A1", nil))

	if rec.Code != http.StatusNotFound || reached {
		t.Fatalf("status = %d reached = %v, want %d and false; body: %s", rec.Code, reached, http.StatusNotFound, rec.Body.String())
	}
}

// TestVisibilityLibpodBatchExportUnauthorizedReferenceHonorsRollout pins the
// two verdicts the native batch preflight can reach — a member the policy
// resolves and hides, and a member it cannot resolve at all — to the same
// rollout contract. Both are answers about the request rather than failures of
// the lookup, so warn and audit record would_deny and forward. Refusing the
// unresolvable one unconditionally while forwarding the definitely-hidden one
// would make warn mode block a request enforce mode would block, which is the
// one thing warn mode exists not to do.
func TestVisibilityLibpodBatchExportUnauthorizedReferenceHonorsRollout(t *testing.T) {
	tests := []struct {
		name     string
		rawQuery string
		labels   map[string]string
		found    bool
	}{
		{name: "hidden member", rawQuery: "references=hidden%3A1", labels: map[string]string{"com.sockguard.visible": "false"}, found: true},
		{name: "missing member", rawQuery: "references=missing%3A1"},
	}

	for _, tt := range tests {
		for _, mode := range []string{"warn", "audit"} {
			t.Run(tt.name+" in "+mode, func(t *testing.T) {
				reached := false
				handler := middlewareWithDeps(testVisibilityLogger(), Options{
					VisibleResourceLabels: []string{"com.sockguard.visible=true"},
				}, visibilityDeps{
					inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
						return tt.labels, tt.found, nil
					},
				})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reached = true
					if r.URL.RawQuery != tt.rawQuery {
						t.Fatalf("forwarded query = %q, want original query %q", r.URL.RawQuery, tt.rawQuery)
					}
					w.WriteHeader(http.StatusNoContent)
				}))

				meta := &logging.RequestMeta{RolloutMode: mode}
				req := httptest.NewRequest(http.MethodGet, "/libpod/images/export?"+tt.rawQuery, nil)
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != http.StatusNoContent || !reached {
					t.Fatalf("status = %d reached = %v, want %d and true; body: %s", rec.Code, reached, http.StatusNoContent, rec.Body.String())
				}
				if meta.Decision != logging.DecisionWouldDeny {
					t.Fatalf("decision = %q, want %q", meta.Decision, logging.DecisionWouldDeny)
				}
				if meta.ReasonCode != reasonCodeVisibilityPolicyHidResource {
					t.Fatalf("reason code = %q, want %q", meta.ReasonCode, reasonCodeVisibilityPolicyHidResource)
				}
			})
		}
	}
}

// TestVisibilityDockerImageExportRefusalHonorsRollout pins the Docker-compat
// refusal to the same contract the ownership middleware's refusal of these two
// routes already follows. The chain runs filter, visibility, ownership, so a
// visibility layer that refused unconditionally would answer a warn-mode
// request before ownership could record its own would_deny.
func TestVisibilityDockerImageExportRefusalHonorsRollout(t *testing.T) {
	targets := []string{"/v1.53/images/get?names=visible%3A1", "/v1.53/images/visible%3A1/get"}

	for _, target := range targets {
		for _, mode := range []string{"warn", "audit"} {
			t.Run(target+" in "+mode, func(t *testing.T) {
				reached := false
				inspectCalls := 0
				handler := middlewareWithDeps(testVisibilityLogger(), Options{
					VisibleResourceLabels: []string{"com.sockguard.visible=true"},
				}, visibilityDeps{
					inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
						inspectCalls++
						return map[string]string{"com.sockguard.visible": "true"}, true, nil
					},
				})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached = true
					w.WriteHeader(http.StatusNoContent)
				}))

				meta := &logging.RequestMeta{RolloutMode: mode}
				req := httptest.NewRequest(http.MethodGet, target, nil)
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != http.StatusNoContent || !reached {
					t.Fatalf("status = %d reached = %v, want %d and true; body: %s", rec.Code, reached, http.StatusNoContent, rec.Body.String())
				}
				if meta.Decision != logging.DecisionWouldDeny {
					t.Fatalf("decision = %q, want %q", meta.Decision, logging.DecisionWouldDeny)
				}
				if meta.ReasonCode != reasonCodeVisibilityImageExport {
					t.Fatalf("reason code = %q, want %q", meta.ReasonCode, reasonCodeVisibilityImageExport)
				}
				if inspectCalls != 0 {
					t.Fatalf("inspect calls = %d, want none even when the verdict passes through", inspectCalls)
				}
			})
		}
	}
}

func TestVisibilityLibpodBatchExportHardFailuresIgnoreRollout(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		rawQuery   string
		lookupErr  error
		wantStatus int
	}{
		{name: "malformed query in warn", mode: "warn", rawQuery: "references=%zz", wantStatus: http.StatusBadRequest},
		{name: "lookup failure in audit", mode: "audit", rawQuery: "references=broken%3A1", lookupErr: errors.New("inspect failed"), wantStatus: http.StatusBadGateway},
		{name: "hidden member does not mask later lookup failure in warn", mode: "warn", rawQuery: "references=hidden%3A1&references=broken%3A1", lookupErr: errors.New("inspect failed"), wantStatus: http.StatusBadGateway},
		{name: "missing member does not mask later lookup failure in warn", mode: "warn", rawQuery: "references=missing%3A1&references=broken%3A1", lookupErr: errors.New("inspect failed"), wantStatus: http.StatusBadGateway},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{
				inspectResource: func(_ context.Context, _ dockerresource.Kind, id string) (map[string]string, bool, error) {
					switch id {
					case "hidden:1":
						return map[string]string{"com.sockguard.visible": "false"}, true, nil
					case "missing:1":
						return nil, false, nil
					}
					return nil, false, tt.lookupErr
				},
			})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				reached = true
			}))

			meta := &logging.RequestMeta{RolloutMode: tt.mode}
			req := httptest.NewRequest(http.MethodGet, "/libpod/images/export", nil)
			req.URL.RawQuery = tt.rawQuery
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus || reached {
				t.Fatalf("status = %d reached = %v, want %d and false; body: %s", rec.Code, reached, tt.wantStatus, rec.Body.String())
			}
			if meta.Decision == logging.DecisionWouldDeny {
				t.Fatalf("decision = %q, want hard denial", meta.Decision)
			}
		})
	}
}

func TestVisibilityDeniesLibpodBatchExportWhenReferenceIsMissing(t *testing.T) {
	reached := false
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindImage {
				t.Fatalf("inspect kind = %q, want %q", kind, dockerresource.KindImage)
			}
			if id != "missing:1" {
				t.Fatalf("inspect id = %q, want %q", id, "missing:1")
			}
			return nil, false, nil
		},
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/libpod/images/export?references=missing%3A1", nil))

	if rec.Code != http.StatusNotFound || reached {
		t.Fatalf("status = %d reached = %v, want %d and false; body: %s", rec.Code, reached, http.StatusNotFound, rec.Body.String())
	}
}

func TestVisibilityLibpodBatchExportLookupFailureStopsBeforeUpstream(t *testing.T) {
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{
		inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
			return nil, false, errors.New("inspect failed")
		},
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("batch export with a failed visibility lookup reached the upstream")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/libpod/images/export?references=broken%3A1", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
}

func TestVisibilityLibpodBatchExportReferenceLimit(t *testing.T) {
	const maxSelectedReferences = 256

	t.Run("exact limit is allowed and duplicate lookups are coalesced", func(t *testing.T) {
		inspectCalls := 0
		reached := false
		handler := middlewareWithDeps(testVisibilityLogger(), Options{
			VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		}, visibilityDeps{
			inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
				inspectCalls++
				return map[string]string{"com.sockguard.visible": "true"}, true, nil
			},
		})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusNoContent)
		}))

		target := "/libpod/images/export?" + strings.Repeat("references=visible%3A1&", maxSelectedReferences)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

		if rec.Code != http.StatusNoContent || !reached {
			t.Fatalf("status = %d reached = %v, want %d and true; body: %s", rec.Code, reached, http.StatusNoContent, rec.Body.String())
		}
		if inspectCalls != 1 {
			t.Fatalf("inspect calls = %d, want one coalesced lookup", inspectCalls)
		}
	})

	t.Run("one over limit is rejected before lookup", func(t *testing.T) {
		inspectCalls := 0
		handler := middlewareWithDeps(testVisibilityLogger(), Options{
			VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		}, visibilityDeps{
			inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
				inspectCalls++
				return map[string]string{"com.sockguard.visible": "true"}, true, nil
			},
		})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("oversized image batch reached the upstream")
		}))

		target := "/libpod/images/export?" + strings.Repeat("references=visible%3A1&", maxSelectedReferences+1)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
		if inspectCalls != 0 {
			t.Fatalf("inspect calls = %d, want none", inspectCalls)
		}
	})
}
