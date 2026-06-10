// Package dockerfilters decodes Docker's `filters` query parameter into one
// normalized shape so every middleware that rewrites filters (ownership's
// owner-label injection, visibility's label selectors) shares a single,
// audited decoder.
package dockerfilters

import (
	"encoding/json"
	"fmt"
	"slices"
)

// Decode parses Docker's `filters` query parameter into a normalized
// map[string][]string. Docker's wire format for filters has two shapes in
// use:
//
//  1. map[string][]string — the modern encoding, e.g.
//     `{"label":["com.sockguard.owner=alice","status=running"]}`.
//     Negation (`label!=foo`) lives inside the string value, so it's
//     transparent to us — we don't need to parse the `!=` sentinel.
//
//  2. map[string]map[string]bool — the legacy encoding still accepted by
//     the Docker daemon, e.g.
//     `{"label":{"com.sockguard.owner=alice":true}}`. We flatten the
//     object's keys into a sorted []string so downstream code sees one
//     deterministic shape.
//
// Any other encoding returns an error: a filter type we don't know how to
// render safely is a fail-fast, not a silent drop, so a future Docker API
// extension surfaces here instead of silently skipping ownership or
// visibility checks.
func Decode(encoded string) (map[string][]string, error) {
	filters := make(map[string][]string)
	if encoded == "" {
		return filters, nil
	}

	var raw map[string]any
	if err := json.Unmarshal([]byte(encoded), &raw); err != nil {
		return nil, fmt.Errorf("decode filters: %w", err)
	}

	for key, value := range raw {
		switch typed := value.(type) {
		case []any:
			values := make([]string, 0, len(typed))
			for _, item := range typed {
				str, ok := item.(string)
				if !ok {
					return nil, fmt.Errorf("decode filters: unexpected %s filter element type %T", key, item)
				}
				values = append(values, str)
			}
			filters[key] = values
		case map[string]any:
			values := make([]string, 0, len(typed))
			for item := range typed {
				values = append(values, item)
			}
			slices.Sort(values)
			filters[key] = values
		default:
			return nil, fmt.Errorf("decode filters: unexpected %s filter type %T", key, value)
		}
	}

	return filters, nil
}
