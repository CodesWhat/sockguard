package config

import (
	"os"
	"reflect"
	"slices"

	mapstructure "github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// UnknownKeys reports every key in the YAML file at configPath that no field
// of Config binds, as dotted paths (list elements as name[index], for example
// "clients.profiles[0].response.redact_container_env"), sorted. A missing file
// or empty path reports nothing, matching Load.
//
// Only the file is inspected. Environment variables and built-in defaults are
// deliberately left out: both are keyed off the schema itself, so neither can
// introduce a key the schema does not know, and an env-only setting must never
// read as a typo. Tecnativa compatibility variables are likewise unprefixed
// environment, never YAML, so they are not candidates either.
//
// This is advisory. Load keeps tolerating unknown keys (except under
// mutations, which is strict) so no configuration that loads today stops
// loading; callers warn, or fail only when the operator asked for --strict.
func UnknownKeys(configPath string) ([]string, error) {
	if configPath == "" {
		return nil, nil
	}
	data, err := ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return UnknownKeysBytes(data)
}

// UnknownKeysBytes is UnknownKeys for an in-memory YAML body, the counterpart
// of LoadBytes for the signed-bundle and hot-reload-from-bundle paths.
func UnknownKeysBytes(data []byte) ([]string, error) {
	if len(data) == 0 {
		return nil, nil
	}
	codec, err := viper.NewCodecRegistry().Decoder("yaml")
	if err != nil {
		return nil, err
	}
	raw := make(map[string]any)
	if err := codec.Decode(data, raw); err != nil {
		return nil, err
	}
	// Viper's settings normalization drops nulls and empty maps. Retain their
	// keys for diagnostics, then restore a typed zero during schema decoding.
	for key, value := range raw {
		raw[key] = preserveEmptyConfigValue(value)
	}
	v := viper.New()
	if err := v.MergeConfigMap(raw); err != nil {
		return nil, err
	}

	var md mapstructure.Metadata
	var cfg Config
	if err := v.Unmarshal(&cfg, func(c *mapstructure.DecoderConfig) {
		c.Metadata = &md
		hook := c.DecodeHook
		c.DecodeHook = func(from, to reflect.Value) (any, error) {
			if from.Type() == reflect.TypeFor[emptyConfigValue]() {
				return reflect.Zero(to.Type()).Interface(), nil
			}
			return mapstructure.DecodeHookExec(hook, from, to)
		}
	}); err != nil {
		return nil, err
	}

	unused := slices.Clone(md.Unused)
	slices.Sort(unused)
	return slices.Compact(unused), nil
}

type emptyConfigValue struct{}

func preserveEmptyConfigValue(value any) any {
	switch object := value.(type) {
	case nil:
		return emptyConfigValue{}
	case map[string]any:
		if len(object) == 0 {
			return emptyConfigValue{}
		}
		for key, child := range object {
			object[key] = preserveEmptyConfigValue(child)
		}
	case map[any]any:
		if len(object) == 0 {
			return emptyConfigValue{}
		}
		for key, child := range object {
			object[key] = preserveEmptyConfigValue(child)
		}
	}
	return value
}
