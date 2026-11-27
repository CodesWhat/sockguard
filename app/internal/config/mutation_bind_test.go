package config

import "testing"

func bindRule(id, from, to string, surfaces ...string) MutationRuleConfig {
	return MutationRuleConfig{ID: id, Mode: "enforce", Surfaces: surfaces, RemapBindSource: &BindSourceRemapMutationConfig{From: from, To: to}}
}

func TestValidateMutationRemapBindSource(t *testing.T) {
	valid := Defaults()
	valid.Mutations.Rules = []MutationRuleConfig{
		bindRule("workspace", "/builds", "/srv/runner/builds", "container_create", "libpod_container_create"),
		bindRule("cache", "/cache", "/srv/runner/cache", "container_create"),
	}
	if errs := validateMutationsConfig(&valid); len(errs) != 0 {
		t.Fatalf("valid bind rules rejected: %v", errs)
	}

	tests := []struct {
		name string
		rule MutationRuleConfig
		want string
	}{
		{"relative from", bindRule("r", "builds", "/srv/b", "container_create"), "remap_bind_source.from must be an absolute path"},
		{"relative to", bindRule("r", "/builds", "srv/b", "container_create"), "remap_bind_source.to must be an absolute path"},
		{"root from", bindRule("r", "/", "/srv/b", "container_create"), "must not be the filesystem root"},
		{"root to", bindRule("r", "/builds", "/", "container_create"), "must not be the filesystem root"},
		{"unclean from", bindRule("r", "/builds/", "/srv/b", "container_create"), "must be a clean path"},
		{"dotdot to", bindRule("r", "/builds", "/srv/../etc", "container_create"), "must be a clean path"},
		{"colon in to", bindRule("r", "/builds", "/srv/b:/x", "container_create"), "must not contain ':' or ','"},
		{"comma in to", bindRule("r", "/builds", "/srv/b,bind-propagation=shared", "container_create"), "must not contain ':' or ','"},
		{"control char", bindRule("r", "/builds", "/srv/b\x01", "container_create"), "control characters"},
		{"empty to", bindRule("r", "/builds", "", "container_create"), "to is required"},
		{"service surface", bindRule("r", "/builds", "/srv/b", "service_create"), "bind sources exist only on container_create"},
		{"no surface", bindRule("r", "/builds", "/srv/b"), "surfaces"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Mutations.Rules = []MutationRuleConfig{tt.rule}
			assertValidationErrorContains(t, &cfg, tt.want)
		})
	}
}

func TestValidateMutationRemapBindSourceOverlaps(t *testing.T) {
	tests := []struct {
		name  string
		rules []MutationRuleConfig
		want  string
	}{
		{"equal from", []MutationRuleConfig{
			bindRule("a", "/builds", "/srv/a", "container_create"),
			bindRule("b", "/builds", "/srv/b", "container_create"),
		}, "remap_bind_source.from and mutations.rules[1].remap_bind_source.from overlap"},
		{"nested from", []MutationRuleConfig{
			bindRule("a", "/builds", "/srv/a", "container_create"),
			bindRule("b", "/builds/cache", "/srv/b", "container_create"),
		}, "overlap"},
		{"chaining to under another from", []MutationRuleConfig{
			bindRule("a", "/builds", "/srv/a", "container_create"),
			bindRule("b", "/srv", "/mnt/srv", "container_create"),
		}, "could be rewritten again"},
		{"to under own from", []MutationRuleConfig{
			bindRule("a", "/data", "/data/real", "container_create"),
		}, "could be rewritten again"},
		{"to equals own from", []MutationRuleConfig{
			bindRule("a", "/data", "/data", "container_create"),
		}, "could be rewritten again"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Mutations.Rules = tt.rules
			assertValidationErrorContains(t, &cfg, tt.want)
		})
	}

	t.Run("prefix confusion is not overlap", func(t *testing.T) {
		cfg := Defaults()
		cfg.Mutations.Rules = []MutationRuleConfig{
			bindRule("a", "/builds", "/srv/a", "container_create"),
			bindRule("b", "/builds2", "/srv/b", "container_create"),
		}
		if errs := validateMutationsConfig(&cfg); len(errs) != 0 {
			t.Fatalf("/builds and /builds2 flagged as overlapping: %v", errs)
		}
	})
}

func TestValidateMutationBlockExclusivityAndSurfaceCompat(t *testing.T) {
	t.Run("bind plus image", func(t *testing.T) {
		cfg := Defaults()
		rule := bindRule("a", "/builds", "/srv/a", "container_create")
		rule.RemapImage = validRemapConfig()
		cfg.Mutations.Rules = []MutationRuleConfig{rule}
		assertValidationErrorContains(t, &cfg, "exactly one of inject_labels, remap_image or remap_bind_source")
	})
	t.Run("inject_labels on libpod", func(t *testing.T) {
		cfg := Defaults()
		cfg.Mutations.Rules = []MutationRuleConfig{validInjectRule("a", "libpod_container_create", map[string]string{"k": "v"})}
		assertValidationErrorContains(t, &cfg, "only remap_bind_source applies")
	})
	t.Run("remap_image on libpod", func(t *testing.T) {
		cfg := Defaults()
		cfg.Mutations.Rules = []MutationRuleConfig{{ID: "a", Mode: "enforce", Surfaces: []string{"libpod_container_create"}, RemapImage: validRemapConfig()}}
		assertValidationErrorContains(t, &cfg, "only remap_bind_source applies")
	})
}

func TestMutationsToFilterOptionsCarriesBindRemap(t *testing.T) {
	opts := MutationsConfig{Rules: []MutationRuleConfig{bindRule("a", "/builds", "/srv/a", "container_create")}}.ToFilterOptions()
	got := opts.Rules[0].RemapBindSource
	if got == nil || got.From != "/builds" || got.To != "/srv/a" {
		t.Fatalf("RemapBindSource = %#v", got)
	}
}
