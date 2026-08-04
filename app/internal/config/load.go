package config

import (
	"bytes"
	"os"
	"reflect"
	"strings"

	"github.com/spf13/viper"
)

// Load reads config from the given YAML file path, applies env var overrides,
// and returns the merged Config. A missing file is OK; parse errors are not.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Full config precedence across the serve path is:
	// 1. CLI flags (applied later in internal/cmd/serve.go via applyFlagOverrides)
	// 2. SOCKGUARD_* environment variables (handled below by Viper)
	// 3. YAML config file values
	// 4. Built-in defaults
	defaults := Defaults()
	setLoadDefaults(v, defaults)

	// Read YAML file if it exists
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			if _, statErr := os.Stat(configPath); statErr != nil && os.IsNotExist(statErr) {
				// File doesn't exist — that's fine, use defaults
			} else {
				return nil, err
			}
		}
	}

	v.SetEnvPrefix("SOCKGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	applyCompatEnvAliases(&cfg)

	if len(cfg.Rules) == 0 {
		cfg.Rules = defaults.Rules
	}

	cfg.explicitLegacyListen = explicitLegacyListenFile(configPath)

	return &cfg, nil
}

// legacyListenKeys are the dotted config paths under listen: whose presence
// (via YAML, a SOCKGUARD_LISTEN_* env var, or — separately, via
// Config.MarkLegacyListenExplicit — the --listen-socket CLI flag) marks the
// legacy singular listener as explicitly configured rather than left at its
// zero-value default. Used only for the listen/listeners mutual-exclusivity
// check (#149); listed exhaustively rather than derived by reflection
// because the check must distinguish "present with any value, including a
// zero value" from "absent", which registerDefaults' walk does not track.
var legacyListenKeys = []string{
	"listen.socket",
	"listen.address",
	"listen.socket_mode",
	"listen.socket_uid",
	"listen.socket_gid",
	"listen.insecure_allow_plain_tcp",
	"listen.insecure_allow_unauthenticated_clients",
	"listen.tls.cert_file",
	"listen.tls.key_file",
	"listen.tls.client_ca_file",
	"listen.tls.common_names",
	"listen.tls.dns_names",
	"listen.tls.ip_addresses",
	"listen.tls.uri_sans",
	"listen.tls.public_key_sha256_pins",
}

// explicitLegacyListenFile reports whether any legacyListenKeys entry was
// set via the YAML file at configPath or a SOCKGUARD_LISTEN_* environment
// variable. It uses a second, defaults-free Viper instance so
// registerDefaults' leaf registrations (which would make every key
// unconditionally "set") cannot mask the answer.
func explicitLegacyListenFile(configPath string) bool {
	pv := viper.New()
	if configPath != "" {
		pv.SetConfigFile(configPath)
		_ = pv.ReadInConfig() // missing file is fine, same tolerance as Load
	}
	pv.SetEnvPrefix("SOCKGUARD")
	pv.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	pv.AutomaticEnv()
	return explicitLegacyListenSet(pv)
}

// explicitLegacyListenBytes is explicitLegacyListenFile's LoadBytes
// counterpart: no environment overlay, matching LoadBytes' own contract
// (env vars never affect a candidate/signed YAML body).
func explicitLegacyListenBytes(data []byte) bool {
	pv := viper.New()
	pv.SetConfigType("yaml")
	if len(data) > 0 {
		if err := pv.ReadConfig(bytes.NewReader(data)); err != nil {
			return false
		}
	}
	return explicitLegacyListenSet(pv)
}

func explicitLegacyListenSet(pv *viper.Viper) bool {
	for _, key := range legacyListenKeys {
		if pv.IsSet(key) {
			return true
		}
	}
	return false
}

// setLoadDefaults registers every default value with the Viper instance.
// Shared by Load (file-based, with env overlay) and LoadBytes (in-memory,
// no env overlay) so the two paths cannot drift as the schema grows.
//
// Defaults are derived by reflection off Config's mapstructure tags (see
// registerDefaults) rather than a hand-maintained list of v.SetDefault
// calls, so a newly added field can no longer silently lose its Viper
// registration — and with it, its SOCKGUARD_* environment-variable override
// — by omission. That exact failure mode has shipped three times
// (allow_sysctls, the service-hardening rails, the SELinux/
// deny_unconfined_system_paths trio); see load_defaults_completeness_test.go.
func setLoadDefaults(v *viper.Viper, defaults Config) {
	registerDefaults(v, "", reflect.ValueOf(defaults))
}

// registerDefaults recursively walks val — a struct value reflecting some
// (sub)tree of Config — and registers every leaf field as a Viper default
// under the dotted key built from its mapstructure tags.
//
// A field is recursed into only when it is a plain (non-pointer, non-slice)
// struct; every other kind — bool, string, numeric, []string, []T, and
// pointer-to-struct fields alike — is a leaf, registered whole via
// v.SetDefault. A ",squash" mapstructure tag (AdminListenConfig's embedded
// ListenConfig) recurses at the same key prefix instead of nesting one
// level deeper, matching how the mapstructure decoder treats it.
//
// Two exclusions preserve pre-existing behavior exactly rather than
// "fixing" it as a side effect of the walk:
//   - The top-level Rules field is skipped: it is populated post-unmarshal
//     by the `if len(cfg.Rules) == 0` fallback in Load/LoadBytes below, not
//     by a Viper default.
//   - A nil pointer leaf (clients.global_concurrency; limits.rate and
//     limits.concurrency inside clients.profiles[], which never reach this
//     branch because Profiles is itself a slice leaf) is skipped rather
//     than registered with a zero value, because those blocks are not
//     env-var-configurable today — registering one would silently make
//     every deploy see a present-but-empty block instead of an absent one.
func registerDefaults(v *viper.Viper, prefix string, val reflect.Value) {
	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		name, squash := mapstructureTag(field)

		// Rules is populated post-unmarshal (see the doc comment above), not
		// via a Viper default.
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
			registerDefaults(v, key, fv)
			continue
		}
		if fv.Kind() == reflect.Pointer && fv.IsNil() {
			continue
		}

		v.SetDefault(key, fv.Interface())
	}
}

// mapstructureTag splits a struct field's mapstructure tag into its key
// name and whether it carries the ",squash" option.
func mapstructureTag(field reflect.StructField) (name string, squash bool) {
	tag := field.Tag.Get("mapstructure")
	parts := strings.Split(tag, ",")
	name = parts[0]
	for _, opt := range parts[1:] {
		if opt == "squash" {
			squash = true
		}
	}
	return name, squash
}

// LoadBytes parses YAML config from the provided bytes and returns the merged
// Config with defaults applied. Unlike Load, env-var overrides are NOT applied,
// which makes it the loader for two distinct callers:
//   - the admin /admin/validate endpoint, which validates a candidate YAML body
//     in isolation, so the result depends only on what the caller submitted; and
//   - the signed-policy-bundle path, where the on-disk YAML is authoritative.
//     Parsing the verified bytes here (rather than re-reading the file with the
//     SOCKGUARD_* overlay) guarantees the applied config equals the signed
//     config: environment variables cannot silently override signed policy (#16).
//
// An empty body returns the built-in defaults — useful for CI pipelines that
// want to confirm the proxy's defaults still validate. Malformed YAML returns
// an error.
func LoadBytes(data []byte) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	defaults := Defaults()
	setLoadDefaults(v, defaults)

	if len(data) > 0 {
		if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
			return nil, err
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	if len(cfg.Rules) == 0 {
		cfg.Rules = defaults.Rules
	}

	cfg.explicitLegacyListen = explicitLegacyListenBytes(data)

	return &cfg, nil
}
