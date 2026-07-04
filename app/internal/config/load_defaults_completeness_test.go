package config

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// This file makes the "a new config field silently loses its Viper default
// (and with it, its SOCKGUARD_* env var override)" failure mode structurally
// impossible to ship undetected, instead of case-by-case patched — that bug
// class already shipped three times (allow_sysctls, the service-hardening
// rails, the SELinux/deny_unconfined_system_paths trio; see
// load_env_defaults_test.go for the original one-off regression tests).
//
// The walkers below deliberately do NOT call registerDefaults or reuse its
// traversal — they re-derive the same "recurse into plain structs, treat
// everything else as a leaf, skip the top-level Rules field and nil pointer
// leaves" rule independently, so these tests exercise Load()'s actual output
// rather than assuming setLoadDefaults' own logic is correct.

// TestLoadDefaultsCoversEveryMapstructureLeaf asserts Load() with no file
// and no env overrides reproduces Defaults() field-by-field. Any leaf that
// registerDefaults dropped (or mis-keyed) surfaces here as a mismatch at its
// exact dotted path, rather than as a silently-wrong zero value.
func TestLoadDefaultsCoversEveryMapstructureLeaf(t *testing.T) {
	cfg, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	want := Defaults()
	compareLeaves(t, "", reflect.ValueOf(*cfg), reflect.ValueOf(want))
}

// TestLoadDefaultsEnvOverrideSweep is the generalized replacement for the
// one-off regression tests in load_env_defaults_test.go: it walks every leaf
// field reachable from Config, mutates the expected value and sets the
// matching SOCKGUARD_<PATH> env var for every leaf whose type has an
// unambiguous string encoding (bool, string, int64, []string), then asserts
// a single Load() call picks up every one of them — with every other field
// left at its default (no cross-contamination).
func TestLoadDefaultsEnvOverrideSweep(t *testing.T) {
	want := Defaults()
	wantVal := reflect.ValueOf(&want).Elem()

	probed := 0
	walkLeaves("", wantVal, func(path string, fv reflect.Value) {
		probe, ok := probeFor(fv)
		if !ok {
			return
		}
		envVar := "SOCKGUARD_" + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
		t.Setenv(envVar, probe.envValue)
		fv.Set(reflect.ValueOf(probe.want))
		probed++
	})
	if probed == 0 {
		t.Fatal("no probeable leaves found — walkLeaves or probeFor regressed")
	}

	cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	compareLeaves(t, "", reflect.ValueOf(*cfg), wantVal)
}

// TestConfigFieldsHaveMapstructureTags asserts every field anywhere in
// Config's type graph — including inside slice and pointer element types
// that the leaf walkers above never descend into — carries a mapstructure
// tag. A field with no tag is invisible to registerDefaults AND to Viper's
// env/file unmarshal at any depth, which is the one residual failure mode
// this refactor does not otherwise close.
func TestConfigFieldsHaveMapstructureTags(t *testing.T) {
	var untagged []string
	collectUntaggedFields(reflect.TypeOf(Config{}), "Config", map[reflect.Type]bool{}, &untagged)

	if len(untagged) > 0 {
		t.Fatalf("fields missing a mapstructure tag: %s", strings.Join(untagged, ", "))
	}
}

// compareLeaves recursively walks got and want in tandem — both must be the
// same Config-shaped type — and reports a mismatch at the exact dotted
// mapstructure path of any leaf that differs. It mirrors registerDefaults'
// traversal rule: recurse into plain (non-pointer, non-slice) struct
// fields; skip the top-level Rules field (populated post-unmarshal by the
// `if len(cfg.Rules) == 0` fallback in Load/LoadBytes, not by a Viper
// default) and any nil-pointer leaf (e.g. clients.global_concurrency, which
// is deliberately not env-var-configurable today).
func compareLeaves(t *testing.T, prefix string, got, want reflect.Value) {
	t.Helper()

	typ := got.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name, squash := mapstructureTag(field)
		if prefix == "" && name == "rules" {
			continue
		}

		key := prefix
		if !squash {
			if prefix == "" {
				key = name
			} else {
				key = prefix + "." + name
			}
		}

		gf, wf := got.Field(i), want.Field(i)
		if gf.Kind() == reflect.Struct {
			compareLeaves(t, key, gf, wf)
			continue
		}
		if wf.Kind() == reflect.Pointer && wf.IsNil() {
			continue
		}

		if !reflect.DeepEqual(gf.Interface(), wf.Interface()) {
			t.Errorf("%s: got %#v, want %#v", key, gf.Interface(), wf.Interface())
		}
	}
}

// walkLeaves applies the same traversal rule as registerDefaults/
// compareLeaves to a single Config-shaped value, invoking fn with the
// dotted mapstructure path and settable reflect.Value of every leaf (top-
// level Rules and nil-pointer leaves excluded, matching registerDefaults).
// val must be addressable so fn can mutate leaves in place.
func walkLeaves(prefix string, val reflect.Value, fn func(path string, fv reflect.Value)) {
	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name, squash := mapstructureTag(field)
		if prefix == "" && name == "rules" {
			continue
		}

		key := prefix
		if !squash {
			if prefix == "" {
				key = name
			} else {
				key = prefix + "." + name
			}
		}

		fv := val.Field(i)
		if fv.Kind() == reflect.Struct {
			walkLeaves(key, fv, fn)
			continue
		}
		if fv.Kind() == reflect.Pointer && fv.IsNil() {
			continue
		}

		fn(key, fv)
	}
}

// probe is a non-default value paired with its SOCKGUARD_<PATH> string
// encoding.
type probe struct {
	envValue string
	want     any
}

// probeFor derives a probe for leaf kinds with an unambiguous single-string
// env encoding (bool, string, int64, []string — matching Viper's default
// weakly-typed decode plus its comma-split []string hook). Slice-of-struct
// leaves (e.g. clients.profiles, policy_bundle.allowed_signing_keys),
// [][]string (exec.allowed_commands), and pointer leaves have no such
// encoding — ok is false and the leaf is skipped by the sweep, exactly
// mirroring which leaves are actually env-overridable today.
func probeFor(fv reflect.Value) (p probe, ok bool) {
	switch fv.Kind() {
	case reflect.Bool:
		want := !fv.Bool()
		return probe{envValue: strconv.FormatBool(want), want: want}, true
	case reflect.String:
		want := "sockguard-probe-value"
		return probe{envValue: want, want: want}, true
	case reflect.Int64:
		want := fv.Int() + 999
		return probe{envValue: strconv.FormatInt(want, 10), want: want}, true
	case reflect.Slice:
		if fv.Type().Elem().Kind() == reflect.String {
			want := []string{"sockguard-probe-a", "sockguard-probe-b"}
			return probe{envValue: strings.Join(want, ","), want: want}, true
		}
		return probe{}, false
	default:
		return probe{}, false
	}
}

// collectUntaggedFields recursively walks every field reachable from t —
// through plain struct, slice-of-struct, and pointer-to-struct alike — and
// appends the Go field path of any field with no mapstructure tag at all.
// Unlike walkLeaves/compareLeaves (which stop at slice/pointer boundaries
// because those are exactly the leaves Viper registers), this must look
// inside them: a missing tag several levels deep (e.g. on
// ClientProfileConfig.Limits.Rate.TokensPerSecond) is just as invisible to
// Viper as one on a top-level field.
func collectUntaggedFields(t reflect.Type, path string, visited map[reflect.Type]bool, out *[]string) {
	if visited[t] {
		return
	}
	visited[t] = true

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldPath := path + "." + field.Name

		if field.Tag.Get("mapstructure") == "" {
			*out = append(*out, fieldPath)
		}

		elemType := field.Type
		for elemType.Kind() == reflect.Pointer || elemType.Kind() == reflect.Slice {
			elemType = elemType.Elem()
		}
		if elemType.Kind() == reflect.Struct {
			collectUntaggedFields(elemType, fieldPath, visited, out)
		}
	}
}
