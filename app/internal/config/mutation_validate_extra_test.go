package config

import "testing"

func TestValidateMutationRuleDuplicateIDAndEmptyLabels(t *testing.T) {
	t.Run("duplicate rule id", func(t *testing.T) {
		cfg := Defaults()
		cfg.Mutations.Rules = []MutationRuleConfig{
			validInjectRule("same", "container_create", map[string]string{"a": "1"}),
			validInjectRule("same", "container_create", map[string]string{"b": "2"}),
		}
		assertValidationErrorContains(t, &cfg, "mutations.rules[1].id")
	})

	t.Run("inject_labels with no labels", func(t *testing.T) {
		cfg := Defaults()
		cfg.Mutations.Rules = []MutationRuleConfig{validInjectRule("empty", "container_create", map[string]string{})}
		assertValidationErrorContains(t, &cfg, "inject_labels.labels")
	})

	t.Run("remap_image with an unknown match mode", func(t *testing.T) {
		cfg := Defaults()
		remap := validRemapConfig()
		remap.Match = "regex"
		cfg.Mutations.Rules = []MutationRuleConfig{{ID: "remap", Mode: "enforce", Surfaces: []string{"container_create"}, RemapImage: remap}}
		assertValidationErrorContains(t, &cfg, "remap_image.match")
	})
}
