package ownership

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func binds(n int, distinct bool) string {
	parts := make([]string, n)
	for i := range parts {
		name := "v"
		if distinct {
			name = fmt.Sprintf("v%d", i)
		}
		parts[i] = fmt.Sprintf("%q", name+":/d")
	}
	return strings.Join(parts, ",")
}

func TestContainerCreateEmbeddedReferencesAreCapped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		binds    string
		wantDeny bool
		wantRefs int
	}{
		{"at the cap", binds(embeddedReferencesMax, true), false, embeddedReferencesMax},
		{"one past the cap", binds(embeddedReferencesMax+1, true), true, embeddedReferencesMax},
		{"88299 duplicate binds collapse to one", binds(88299, false), false, 1},
		{"duplicates then distinct past the cap", binds(5000, false) + "," + binds(embeddedReferencesMax+1, true), true, embeddedReferencesMax},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := `{"HostConfig":{"Binds":[` + tt.binds + `]}}`
			req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(body))
			refs, err := mutateContainerCreateOwnershipBody(req, DefaultLabelKey, "job-123")
			if err != nil {
				t.Fatal(err)
			}
			if (refs.denyReason != "") != tt.wantDeny {
				t.Fatalf("denyReason = %q, wantDeny %v", refs.denyReason, tt.wantDeny)
			}
			if len(refs.embeddedResources) != tt.wantRefs {
				t.Fatalf("refs = %d, want %d", len(refs.embeddedResources), tt.wantRefs)
			}
		})
	}
}

func TestServiceEmbeddedReferencesAreCapped(t *testing.T) {
	t.Parallel()
	mounts := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf(`{"Type":"volume","Source":"v%d"}`, i)
		}
		return strings.Join(parts, ",")
	}
	for n, wantDeny := range map[int]bool{embeddedReferencesMax: false, embeddedReferencesMax + 1: true} {
		body := `{"TaskTemplate":{"ContainerSpec":{"Mounts":[` + mounts(n) + `]}}}`
		req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(body))
		refs, err := mutateServiceOwnershipBody(req, DefaultLabelKey, "job-123")
		if err != nil {
			t.Fatal(err)
		}
		if (refs.denyReason != "") != wantDeny {
			t.Fatalf("n=%d denyReason = %q, wantDeny %v", n, refs.denyReason, wantDeny)
		}
	}
}
