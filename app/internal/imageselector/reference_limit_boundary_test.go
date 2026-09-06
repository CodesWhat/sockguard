package imageselector

import (
	"fmt"
	"testing"
)

// TestQueryReferencesAllowsExactlyMaxReferences pins the `len(identifiers) >
// maxReferences` boundary in Query.References: exactly maxReferences matching
// fields must succeed, and one more must be rejected. The existing tests only
// cover well past the limit; this pins the exact edge the comparison operator
// decides.
func TestQueryReferencesAllowsExactlyMaxReferences(t *testing.T) {
	buildQuery := func(n int) Query {
		query := make(Query, 0, n)
		for i := 0; i < n; i++ {
			query = append(query, Field{Key: "names", Value: fmt.Sprintf("image%d:1", i)})
		}
		return query
	}

	t.Run("exactly maxReferences succeeds", func(t *testing.T) {
		query := buildQuery(maxReferences)
		got, err := query.References("names")
		if err != nil {
			t.Fatalf("References() with exactly %d fields error = %v, want nil", maxReferences, err)
		}
		if len(got) != maxReferences {
			t.Fatalf("References() with exactly %d fields returned %d references, want %d", maxReferences, len(got), maxReferences)
		}
	})

	t.Run("one past maxReferences errors", func(t *testing.T) {
		query := buildQuery(maxReferences + 1)
		if _, err := query.References("names"); err == nil {
			t.Fatalf("References() with %d fields = nil error, want the %d image reference limit error", maxReferences+1, maxReferences)
		}
	})
}
