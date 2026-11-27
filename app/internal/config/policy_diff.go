package config

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// PolicyChange identifies a structural change without disclosing either value.
// Collection positions are indices; user-controlled map keys are never paths.
type PolicyChange struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

// PolicyChanges compares configurations after defaults and validation. Ordered
// lists retain their positions; maps are compared without exposing keys or
// values. Private parser provenance is not configuration.
func PolicyChanges(active, candidate *Config) []PolicyChange {
	changes := make([]PolicyChange, 0)
	var walk func(string, reflect.Value, reflect.Value)
	walk = func(prefix string, before, after reflect.Value) {
		if before.Kind() == reflect.Pointer {
			if before.IsNil() || after.IsNil() {
				if before.IsNil() != after.IsNil() {
					kind := "added"
					if after.IsNil() {
						kind = "removed"
					}
					changes = append(changes, PolicyChange{prefix, kind})
				}
				return
			}
			walk(prefix, before.Elem(), after.Elem())
			return
		}
		switch before.Kind() {
		case reflect.Struct:
			for i := 0; i < before.NumField(); i++ {
				field := before.Type().Field(i)
				if !field.IsExported() {
					continue
				}
				name, squash := mapstructureTag(field)
				if name == "-" {
					continue
				}
				fieldPath := prefix
				if !squash {
					if name == "" {
						name = strings.ToLower(field.Name)
					}
					if fieldPath != "" {
						fieldPath += "."
					}
					fieldPath += name
				}
				walk(fieldPath, before.Field(i), after.Field(i))
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < max(before.Len(), after.Len()); i++ {
				itemPath := fmt.Sprintf("%s[%d]", prefix, i)
				if i >= before.Len() {
					changes = append(changes, PolicyChange{itemPath, "added"})
				} else if i >= after.Len() {
					changes = append(changes, PolicyChange{itemPath, "removed"})
				} else {
					walk(itemPath, before.Index(i), after.Index(i))
				}
			}
		case reflect.Map:
			if before.Len() == 0 && after.Len() == 0 {
				return
			}
			if !reflect.DeepEqual(before.Interface(), after.Interface()) {
				changes = append(changes, PolicyChange{prefix, "modified"})
			}
		default:
			if !reflect.DeepEqual(before.Interface(), after.Interface()) {
				changes = append(changes, PolicyChange{prefix, "modified"})
			}
		}
	}
	walk("", reflect.ValueOf(active), reflect.ValueOf(candidate))
	slices.SortFunc(changes, func(a, b PolicyChange) int { return strings.Compare(a.Path, b.Path) })
	return changes
}
