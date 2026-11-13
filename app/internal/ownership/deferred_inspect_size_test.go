package ownership

import (
	"io"
	"strings"
	"testing"
)

func TestDeferredInspectResponseSizeBoundaries(t *testing.T) {
	t.Parallel()
	id := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, identifier, body string
		decode                 func(io.Reader, string) (map[string]string, bool, error)
	}{
		{"network", "mine", `{"Name":"mine","Labels":{"` + DefaultLabelKey + `":"team-a"}}`, decodeNetworkDeleteName},
		{"image volume", id, `{"Id":"` + id + `","Config":{"Labels":{"` + DefaultLabelKey + `":"team-a"}}}`, decodeImageVolumeID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, boundary := range []struct {
				name  string
				delta int
			}{
				{"below", -1},
				{"exact", 0},
				{"above", 1},
			} {
				t.Run(boundary.name, func(t *testing.T) {
					body := tc.body + strings.Repeat(" ", maxOwnershipBodyBytes+boundary.delta-len(tc.body))
					labels, found, err := tc.decode(strings.NewReader(body), tc.identifier)
					if boundary.delta > 0 {
						if err == nil || found || labels != nil {
							t.Fatalf("oversized inspect = (%v, %v, %v), want error without labels", labels, found, err)
						}
						return
					}
					if err != nil || !found || labels[DefaultLabelKey] != "team-a" {
						t.Fatalf("inspect size %d = (%v, %v, %v), want owned resource", len(body), labels, found, err)
					}
				})
			}
		})
	}
}
