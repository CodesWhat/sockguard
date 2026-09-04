package imageselector

import (
	"slices"
	"strings"
	"testing"
)

func TestParsePreservesFieldOrderAndKeySpelling(t *testing.T) {
	query, err := Parse("References=one%3A1&REFERENCES=two%3A1&references=three%3A1")
	if err != nil {
		t.Fatal(err)
	}

	want := Query{
		{Key: "References", Value: "one:1"},
		{Key: "REFERENCES", Value: "two:1"},
		{Key: "references", Value: "three:1"},
	}
	if !slices.Equal(query, want) {
		t.Fatalf("Parse() = %#v, want %#v", query, want)
	}
}

func TestQueryReferencesFoldsKeysAndDeduplicatesExactValues(t *testing.T) {
	query, err := Parse("names=one%3A1&name%C5%BF=two%3A1&NAMES=one%3A1&names=One%3A1")
	if err != nil {
		t.Fatal(err)
	}

	got, err := query.References("names")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"one:1", "two:1", "One:1"}
	if !slices.Equal(got, want) {
		t.Fatalf("References() = %#v, want %#v", got, want)
	}
}

func TestQueryReferencesRejectsEmptyAndOversizedSelections(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		query, err := Parse("references=")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := query.References("references"); err == nil || !strings.Contains(err.Error(), "empty image reference") {
			t.Fatalf("References() error = %v, want empty image reference", err)
		}
	})

	t.Run("bound applies before deduplication", func(t *testing.T) {
		query, err := Parse(strings.Repeat("references=one%3A1&", maxReferences+1))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := query.References("references"); err == nil || !strings.Contains(err.Error(), "exceeds 256 image reference limit") {
			t.Fatalf("References() error = %v, want pre-deduplication limit", err)
		}
	})
}

func TestParseRejectsMalformedQueries(t *testing.T) {
	for _, rawQuery := range []string{"names=%zz", "na%zzmes=one", "names=one;names=two"} {
		t.Run(rawQuery, func(t *testing.T) {
			if _, err := Parse(rawQuery); err == nil {
				t.Fatalf("Parse(%q) succeeded, want error", rawQuery)
			}
		})
	}
}
