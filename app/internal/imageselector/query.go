package imageselector

import (
	"fmt"
	"net/url"
	"strings"
)

const maxReferences = 256

type Field struct {
	Key   string
	Value string
}

type Query []Field

// Parse retains field order and exact key spelling while following
// net/url.ParseQuery's decoding and validation rules.
func Parse(rawQuery string) (Query, error) {
	query := make(Query, 0)
	for rawQuery != "" {
		field := rawQuery
		if before, after, found := strings.Cut(rawQuery, "&"); found {
			field = before
			rawQuery = after
		} else {
			rawQuery = ""
		}
		if strings.Contains(field, ";") {
			return nil, fmt.Errorf("invalid semicolon separator in query")
		}
		if field == "" {
			continue
		}

		rawKey, rawValue, _ := strings.Cut(field, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return nil, err
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			return nil, err
		}
		query = append(query, Field{Key: key, Value: value})
	}
	return query, nil
}

// References returns the non-empty values for key in arrival order. Matching
// follows the case-insensitive decoder used by Podman's image batch handlers.
// The work bound applies before exact duplicate values are coalesced.
func (q Query) References(key string) ([]string, error) {
	identifiers := make([]string, 0)
	for _, field := range q {
		if strings.EqualFold(field.Key, key) {
			identifiers = append(identifiers, field.Value)
		}
	}
	if len(identifiers) > maxReferences {
		return nil, fmt.Errorf("selected images exceeds %d image reference limit", maxReferences)
	}

	unique := make([]string, 0, len(identifiers))
	seen := make(map[string]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		if identifier == "" {
			return nil, fmt.Errorf("%s contains an empty image reference", key)
		}
		if _, duplicate := seen[identifier]; duplicate {
			continue
		}
		seen[identifier] = struct{}{}
		unique = append(unique, identifier)
	}
	return unique, nil
}
