package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/filter"
)

const validMutationYAML = `
mutations:
  rules:
    - id: inject-team
      mode: enforce
      surfaces: [container_create]
      inject_labels:
        labels:
          com.example.team: platform
`

func TestLoadMutationsStrictRejectsUnknownKeys(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "mutations root",
			yaml: "mutations:\n  rules: []\n  webhook: https://attacker.invalid\n",
			want: "webhook",
		},
		{
			name: "rule",
			yaml: strings.Replace(validMutationYAML, "      mode: enforce\n", "      mode: enforce\n      patch: privileged\n", 1),
			want: "patch",
		},
		{
			name: "arbitrary path",
			yaml: strings.Replace(validMutationYAML, "      mode: enforce\n", "      mode: enforce\n      path: /HostConfig/Privileged\n", 1),
			want: "path",
		},
		{
			name: "inject labels operation",
			yaml: strings.Replace(validMutationYAML, "      inject_labels:\n", "      inject_labels:\n        set_json: {}\n", 1),
			want: "set_json",
		},
		{
			name: "remap image operation",
			yaml: `mutations:
  rules:
    - id: remap
      surfaces: [container_create]
      remap_image:
        match: exact
        from: alpine:3.21
        to: mirror.example/alpine:3.21
        exec: [sh]
`,
			want: "exec",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" LoadBytes", func(t *testing.T) {
			_, err := LoadBytes([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadBytes() error = %v, want strict-decode error containing %q", err, tt.want)
			}
		})
		t.Run(tt.name+" Load", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sockguard.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want strict-decode error containing %q", err, tt.want)
			}
		})
	}
}

func TestLoadMutationsStrictRejectsYAMLTypingAttacks(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{name: "mutations scalar", yaml: "mutations: enabled\n"},
		{name: "rules object", yaml: "mutations:\n  rules: {id: x}\n"},
		{name: "id number", yaml: strings.Replace(validMutationYAML, "id: inject-team", "id: 7", 1)},
		{name: "mode boolean", yaml: strings.Replace(validMutationYAML, "mode: enforce", "mode: true", 1)},
		{name: "surfaces scalar", yaml: strings.Replace(validMutationYAML, "surfaces: [container_create]", "surfaces: container_create", 1)},
		{name: "surface number", yaml: strings.Replace(validMutationYAML, "surfaces: [container_create]", "surfaces: [1]", 1)},
		{name: "inject labels boolean", yaml: strings.Replace(validMutationYAML, "inject_labels:\n        labels:\n          com.example.team: platform", "inject_labels: true", 1)},
		{name: "labels list", yaml: strings.Replace(validMutationYAML, "labels:\n          com.example.team: platform", "labels: [com.example.team, platform]", 1)},
		{name: "label value boolean", yaml: strings.Replace(validMutationYAML, "com.example.team: platform", "com.example.team: true", 1)},
		{name: "remap image scalar", yaml: validRemapYAML("bad")},
		{name: "remap match boolean", yaml: validRemapYAML("match: true\n        from: alpine:3.21\n        to: mirror.example/alpine:3.21")},
		{name: "remap from number", yaml: validRemapYAML("match: exact\n        from: 7\n        to: mirror.example/alpine:3.21")},
		{name: "remap to boolean", yaml: validRemapYAML("match: exact\n        from: alpine:3.21\n        to: false")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadBytes([]byte(tt.yaml)); err == nil {
				t.Fatalf("LoadBytes() error = nil for YAML typing attack:\n%s", tt.yaml)
			}
		})
	}
}

func validRemapYAML(block string) string {
	if !strings.Contains(block, "\n") {
		return "mutations:\n  rules:\n    - id: remap\n      surfaces: [container_create]\n      remap_image: " + block + "\n"
	}
	return "mutations:\n  rules:\n    - id: remap\n      surfaces: [container_create]\n      remap_image:\n        " + strings.ReplaceAll(block, "\n", "\n        ") + "\n"
}

func TestLoadMutationsStrictAcceptsTypedSchema(t *testing.T) {
	cfg, err := LoadBytes([]byte(validMutationYAML))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}
	if len(cfg.Mutations.Rules) != 1 {
		t.Fatalf("mutations.rules length = %d, want 1", len(cfg.Mutations.Rules))
	}
	rule := cfg.Mutations.Rules[0]
	if rule.ID != "inject-team" || rule.InjectLabels == nil || rule.InjectLabels.Labels["com.example.team"] != "platform" {
		t.Fatalf("decoded rule = %#v, want typed inject_labels rule", rule)
	}
}

func TestValidateMutationRuleShape(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*MutationRuleConfig)
		want   string
	}{
		{name: "empty id", mutate: func(r *MutationRuleConfig) { r.ID = "" }, want: ".id must match"},
		{name: "leading punctuation id", mutate: func(r *MutationRuleConfig) { r.ID = "_bad" }, want: ".id must match"},
		{name: "id over 64 bytes", mutate: func(r *MutationRuleConfig) { r.ID = strings.Repeat("a", 65) }, want: ".id must match"},
		{name: "id slash", mutate: func(r *MutationRuleConfig) { r.ID = "bad/id" }, want: ".id must match"},
		{name: "bad mode", mutate: func(r *MutationRuleConfig) { r.Mode = "observe" }, want: ".mode must be one of"},
		{name: "no surfaces", mutate: func(r *MutationRuleConfig) { r.Surfaces = nil }, want: ".surfaces must contain"},
		{name: "bad surface", mutate: func(r *MutationRuleConfig) { r.Surfaces = []string{"network_create"} }, want: ".surfaces must be container_create"},
		{name: "duplicate surface", mutate: func(r *MutationRuleConfig) { r.Surfaces = []string{"container_create", "container_create"} }, want: "must not contain duplicate"},
		{name: "both operations", mutate: func(r *MutationRuleConfig) { r.RemapImage = validRemapConfig() }, want: "got both"},
		{name: "neither operation", mutate: func(r *MutationRuleConfig) { r.InjectLabels = nil }, want: "got neither"},
		{name: "labels on service update", mutate: func(r *MutationRuleConfig) { r.Surfaces = []string{"service_update"} }, want: "service_update has no label field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			rule := validInjectRule("rule-1", "container_create", map[string]string{"team": "platform"})
			tt.mutate(&rule)
			cfg.Mutations.Rules = []MutationRuleConfig{rule}
			assertValidationErrorContains(t, &cfg, tt.want)
		})
	}
}

func TestValidateMutationBounds(t *testing.T) {
	t.Run("more than 64 rules", func(t *testing.T) {
		cfg := Defaults()
		for i := 0; i < maxMutationRules+1; i++ {
			cfg.Mutations.Rules = append(cfg.Mutations.Rules, validInjectRule(fmt.Sprintf("rule-%d", i), "container_create", map[string]string{fmt.Sprintf("key-%d", i): "v"}))
		}
		assertValidationErrorContains(t, &cfg, "at most 64 entries, got 65")
	})

	t.Run("more than 32 labels in one rule", func(t *testing.T) {
		cfg := Defaults()
		cfg.Mutations.Rules = []MutationRuleConfig{validInjectRule("too-many", "container_create", mutationLabels(0, maxMutationLabelsPerRule+1))}
		assertValidationErrorContains(t, &cfg, "at most 32 entries, got 33")
	})

	t.Run("more than 256 total labels", func(t *testing.T) {
		cfg := Defaults()
		for i := 0; i < 9; i++ {
			cfg.Mutations.Rules = append(cfg.Mutations.Rules, validInjectRule(fmt.Sprintf("rule-%d", i), "container_create", mutationLabels(i*29, 29)))
		}
		assertValidationErrorContains(t, &cfg, "must not exceed 256, got 261")
	})

	t.Run("label and image byte caps", func(t *testing.T) {
		tests := []struct {
			name string
			rule MutationRuleConfig
			want string
		}{
			{name: "label key", rule: validInjectRule("key", "container_create", map[string]string{strings.Repeat("k", maxMutationLabelKeyBytes+1): "v"}), want: "exceeds 128 bytes"},
			{name: "label value", rule: validInjectRule("value", "container_create", map[string]string{"k": strings.Repeat("v", maxMutationLabelValueBytes+1)}), want: "exceeds 4096 bytes"},
			{name: "image from", rule: validImageRule("from", "container_create", "prefix", strings.Repeat("f", maxMutationImageFieldBytes+1), "mirror/"), want: "remap_image.from exceeds 4096 bytes"},
			{name: "image to", rule: validImageRule("to", "container_create", "prefix", "source/", strings.Repeat("t", maxMutationImageFieldBytes+1)), want: "remap_image.to exceeds 4096 bytes"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				cfg := Defaults()
				cfg.Mutations.Rules = []MutationRuleConfig{tt.rule}
				assertValidationErrorContains(t, &cfg, tt.want)
			})
		}
	})
}

func TestValidateMutationLabelShape(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{name: "empty key", labels: map[string]string{" ": "value"}, want: "keys must be non-empty"},
		{name: "empty value", labels: map[string]string{"team": ""}, want: "value must be non-empty"},
		{name: "control in key", labels: map[string]string{"team\nname": "value"}, want: "must not contain control characters"},
		{name: "control in value", labels: map[string]string{"team": "platform\x00admin"}, want: "must not contain control characters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Mutations.Rules = []MutationRuleConfig{validInjectRule("labels", "container_create", tt.labels)}
			assertValidationErrorContains(t, &cfg, tt.want)
		})
	}
}

func TestValidateMutationOwnerLabelReservation(t *testing.T) {
	cfg := Defaults()
	cfg.Ownership.Owner = "tenant-a"
	cfg.Mutations.Rules = []MutationRuleConfig{
		validInjectRule("forge-owner", "container_create", map[string]string{cfg.Ownership.LabelKey: "tenant-b"}),
	}
	assertValidationErrorContains(t, &cfg, "must not set reserved owner label key")

	cfg.Ownership.Owner = ""
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() with ownership disabled = %v, want owner label key available", err)
	}
}

func TestValidateMutationOverlapRejection(t *testing.T) {
	tests := []struct {
		name  string
		rules []MutationRuleConfig
		want  string
	}{
		{
			name: "same label on shared surface",
			rules: []MutationRuleConfig{
				validInjectRule("a", "container_create", map[string]string{"team": "a"}),
				validInjectRule("b", "container_create", map[string]string{"team": "b"}),
			},
			want: "two mutation rules must not inject the same label key",
		},
		{
			name: "exact in prefix",
			rules: []MutationRuleConfig{
				validImageRule("prefix", "container_create", "prefix", "registry.example/", "mirror.example/"),
				validImageRule("exact", "container_create", "exact", "registry.example/app:v1", "mirror.example/app:v1"),
			},
			want: "overlap on surface(s) container_create",
		},
		{
			name: "prefix in prefix",
			rules: []MutationRuleConfig{
				validImageRule("broad", "service_create", "prefix", "registry.example/", "mirror.example/"),
				validImageRule("narrow", "service_create", "prefix", "registry.example/team/", "mirror.example/team/"),
			},
			want: "overlap on surface(s) service_create",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Mutations.Rules = tt.rules
			assertValidationErrorContains(t, &cfg, tt.want)
		})
	}
}

func TestValidateMutationNonOverlappingRulesAreAccepted(t *testing.T) {
	cfg := Defaults()
	cfg.Mutations.Rules = []MutationRuleConfig{
		validInjectRule("container-label", "container_create", map[string]string{"team": "a"}),
		validInjectRule("service-label", "service_create", map[string]string{"team": "b"}),
		validImageRule("container-image", "container_create", "prefix", "source.example/", "mirror.example/"),
		validImageRule("service-image", "service_create", "prefix", "source.example/", "mirror.example/"),
		validImageRule("other-image", "container_create", "prefix", "other.example/", "mirror.example/other/"),
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() = %v, want non-overlapping mutations accepted", err)
	}
}

func TestMutationsToFilterOptionsPreservesTypedRules(t *testing.T) {
	cfg := MutationsConfig{Rules: []MutationRuleConfig{
		validInjectRule("labels", "container_create", map[string]string{"team": "platform"}),
		validImageRule("image", "service_update", "prefix", "source.example/", "mirror.example/"),
	}}

	got := cfg.ToFilterOptions()
	want := filter.MutationOptions{Rules: []filter.MutationRuleOptions{
		{ID: "labels", Mode: "enforce", Surfaces: []string{"container_create"}, InjectLabels: &filter.InjectLabelsMutationOptions{Labels: map[string]string{"team": "platform"}}},
		{ID: "image", Mode: "enforce", Surfaces: []string{"service_update"}, RemapImage: &filter.ImageRemapMutationOptions{Match: "prefix", From: "source.example/", To: "mirror.example/"}},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ToFilterOptions() = %#v, want %#v", got, want)
	}
}

func TestMutationsToFilterOptionsNormalizesRemapImageMatchCase(t *testing.T) {
	// Validation accepts remap_image.match case-insensitively (it lowercases
	// before comparing against "exact"/"prefix") without writing the
	// canonical form back onto the config value, so a rule with e.g.
	// "Exact" or padded whitespace passes Validate() unchanged. Confirm
	// ToFilterOptions itself normalizes match to the canonical lowercase
	// form the filter engine's compiled rules key off of, rather than
	// depending solely on filter.newMutationEngine's own normalization of
	// this same field.
	cfg := MutationsConfig{Rules: []MutationRuleConfig{
		validImageRule("exact-mixed-case", "container_create", "Exact", "alpine:3.21", "mirror.example/alpine:3.21"),
		validImageRule("prefix-padded", "container_create", "  Prefix  ", "source.example/", "mirror.example/"),
	}}

	got := cfg.ToFilterOptions()

	if got.Rules[0].RemapImage.Match != "exact" {
		t.Fatalf("Rules[0].RemapImage.Match = %q, want canonical \"exact\"", got.Rules[0].RemapImage.Match)
	}
	if got.Rules[1].RemapImage.Match != "prefix" {
		t.Fatalf("Rules[1].RemapImage.Match = %q, want canonical \"prefix\"", got.Rules[1].RemapImage.Match)
	}
}

func TestMutationDefaultsRemainZeroValue(t *testing.T) {
	if got := Defaults().Mutations; !reflect.DeepEqual(got, MutationsConfig{}) {
		t.Fatalf("Defaults().Mutations = %#v, want zero value (mutations need no Defaults entry)", got)
	}
}

func validInjectRule(id, surface string, labels map[string]string) MutationRuleConfig {
	return MutationRuleConfig{
		ID:       id,
		Mode:     "enforce",
		Surfaces: []string{surface},
		InjectLabels: &InjectLabelsMutationConfig{
			Labels: labels,
		},
	}
}

func validImageRule(id, surface, match, from, to string) MutationRuleConfig {
	return MutationRuleConfig{
		ID:       id,
		Mode:     "enforce",
		Surfaces: []string{surface},
		RemapImage: &ImageRemapMutationConfig{
			Match: match,
			From:  from,
			To:    to,
		},
	}
}

func validRemapConfig() *ImageRemapMutationConfig {
	return &ImageRemapMutationConfig{Match: "exact", From: "alpine:3.21", To: "mirror.example/alpine:3.21"}
}

func mutationLabels(offset, count int) map[string]string {
	labels := make(map[string]string, count)
	for i := 0; i < count; i++ {
		labels[fmt.Sprintf("label-%03d", offset+i)] = "value"
	}
	return labels
}

func assertValidationErrorContains(t *testing.T, cfg *Config, want string) {
	t.Helper()
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate() error = %v, want error containing %q", err, want)
	}
}
