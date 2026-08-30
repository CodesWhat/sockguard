package config

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strings"

	mapstructure "github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"

	"github.com/codeswhat/sockguard/app/internal/boundedio"
)

// MaxConfigFileBytes caps every YAML configuration file read from disk.
const MaxConfigFileBytes int64 = 16 << 20

// ReadFile loads a YAML configuration source under MaxConfigFileBytes.
func ReadFile(path string) ([]byte, error) {
	return boundedio.ReadFile(path, MaxConfigFileBytes)
}

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

	// Read YAML file if it exists.
	if configPath != "" {
		data, err := ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				// File doesn't exist — that's fine, use defaults
			} else {
				return nil, err
			}
		} else {
			v.SetConfigType("yaml")
			if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
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

	if err := decodeMutationsStrict(v, &cfg); err != nil {
		return nil, err
	}

	if len(cfg.Rules) == 0 {
		cfg.Rules = defaults.Rules
	}

	cfg.explicitLegacyListen = explicitLegacyListenFile(configPath)
	applyEndpointConfigProvenance(&cfg, explicitEndpointConfigFile(configPath))

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
		if data, err := ReadFile(configPath); err == nil {
			pv.SetConfigType("yaml")
			_ = pv.ReadConfig(bytes.NewReader(data))
		}
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
	return explicitKeysSet(pv, legacyListenKeys)
}

// endpointConfigLeafKeys are the leaf names inside an endpoint_config block
// (#186's granular per-field gates). Kept as leaves and expanded per group by
// endpointConfigKeysUnder so a future granular field is picked up for every
// group at once — a hand-maintained per-group list is exactly how
// request_body.libpod_network.endpoint_config came to be silently exempt from
// the mutual-exclusion check that request_body.network.endpoint_config had.
var endpointConfigLeafKeys = []string{
	"allow_static_addressing",
	"allow_link_local_ips",
	"allow_mac_pinning",
	"allow_gw_priority",
	"allow_aliases",
}

// endpointConfigKeysUnder returns the dotted config paths under
// request_body.<group>.endpoint_config whose presence (via YAML or a matching
// SOCKGUARD_REQUEST_BODY_<GROUP>_ENDPOINT_CONFIG_* environment variable)
// marks that group's granular endpoint-config block as explicitly configured.
// See explicitEndpointConfigFile/Bytes and legacyListenKeys' doc comment for
// why zero-value comparison cannot answer this question on its own.
func endpointConfigKeysUnder(group string) []string {
	keys := make([]string, 0, len(endpointConfigLeafKeys))
	for _, leaf := range endpointConfigLeafKeys {
		keys = append(keys, "request_body."+group+".endpoint_config."+leaf)
	}
	return keys
}

// networkEndpointConfigKeys and libpodNetworkEndpointConfigKeys are the two
// groups that carry an endpoint_config block. Both are consulted: network
// gates POST /networks/*/connect and container-create's EndpointsConfig,
// libpod_network gates POST /libpod/networks/{name}/connect.
var (
	networkEndpointConfigKeys       = endpointConfigKeysUnder("network")
	libpodNetworkEndpointConfigKeys = endpointConfigKeysUnder("libpod_network")
)

type clientProfileEndpointConfigProvenance struct {
	network                   bool
	libpodNetwork             bool
	networkAllowAliases       bool
	libpodNetworkAllowAliases bool
}

type endpointConfigProvenance struct {
	network       bool
	libpodNetwork bool
	profiles      []clientProfileEndpointConfigProvenance
}

type endpointConfigPresenceBlock struct {
	EndpointConfig map[string]any `mapstructure:"endpoint_config"`
}

type endpointConfigPresenceDocument struct {
	Clients struct {
		Profiles []struct {
			RequestBody struct {
				Network       endpointConfigPresenceBlock `mapstructure:"network"`
				LibpodNetwork endpointConfigPresenceBlock `mapstructure:"libpod_network"`
			} `mapstructure:"request_body"`
		} `mapstructure:"profiles"`
	} `mapstructure:"clients"`
}

// explicitEndpointConfigFile is explicitLegacyListenFile's #186 counterpart:
// reports, for each endpoint_config group, whether any of its keys was set
// via the YAML file at configPath or a matching SOCKGUARD_* environment
// variable, using a second, defaults-free Viper instance so registerDefaults'
// leaf registrations cannot mask the answer. Both groups are answered from
// one pass so the file is read once.
func explicitEndpointConfigFile(configPath string) endpointConfigProvenance {
	pv := viper.New()
	if configPath != "" {
		if data, err := ReadFile(configPath); err == nil {
			pv.SetConfigType("yaml")
			_ = pv.ReadConfig(bytes.NewReader(data))
		}
	}
	pv.SetEnvPrefix("SOCKGUARD")
	pv.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	pv.AutomaticEnv()
	return endpointConfigProvenanceFor(pv)
}

// explicitEndpointConfigBytes is explicitEndpointConfigFile's LoadBytes
// counterpart: no environment overlay, matching LoadBytes' own contract (env
// vars never affect a candidate/signed YAML body).
func explicitEndpointConfigBytes(data []byte) endpointConfigProvenance {
	pv := viper.New()
	pv.SetConfigType("yaml")
	if len(data) > 0 {
		if err := pv.ReadConfig(bytes.NewReader(data)); err != nil {
			return endpointConfigProvenance{}
		}
	}
	return endpointConfigProvenanceFor(pv)
}

func endpointConfigProvenanceFor(pv *viper.Viper) endpointConfigProvenance {
	provenance := endpointConfigProvenance{
		network:       explicitKeysSet(pv, networkEndpointConfigKeys),
		libpodNetwork: explicitKeysSet(pv, libpodNetworkEndpointConfigKeys),
	}

	var presence endpointConfigPresenceDocument
	if err := pv.Unmarshal(&presence); err != nil {
		return provenance
	}
	provenance.profiles = make([]clientProfileEndpointConfigProvenance, len(presence.Clients.Profiles))
	for i, profile := range presence.Clients.Profiles {
		network := profile.RequestBody.Network.EndpointConfig
		libpodNetwork := profile.RequestBody.LibpodNetwork.EndpointConfig
		provenance.profiles[i] = clientProfileEndpointConfigProvenance{
			network:                   endpointConfigMapExplicit(network),
			libpodNetwork:             endpointConfigMapExplicit(libpodNetwork),
			networkAllowAliases:       endpointConfigMapHas(network, "allow_aliases"),
			libpodNetworkAllowAliases: endpointConfigMapHas(libpodNetwork, "allow_aliases"),
		}
	}
	return provenance
}

func endpointConfigMapExplicit(values map[string]any) bool {
	for _, leaf := range endpointConfigLeafKeys {
		if endpointConfigMapHas(values, leaf) {
			return true
		}
	}
	return false
}

func endpointConfigMapHas(values map[string]any, leaf string) bool {
	for key := range values {
		if strings.EqualFold(key, leaf) {
			return true
		}
	}
	return false
}

func applyEndpointConfigProvenance(cfg *Config, provenance endpointConfigProvenance) {
	cfg.explicitNetworkEndpointConfig = provenance.network
	cfg.explicitLibpodNetworkEndpointConfig = provenance.libpodNetwork
	for i := range cfg.Clients.Profiles {
		profile := &cfg.Clients.Profiles[i]
		var raw clientProfileEndpointConfigProvenance
		if i < len(provenance.profiles) {
			raw = provenance.profiles[i]
		}
		profile.explicitNetworkEndpointConfig = raw.network
		profile.explicitLibpodNetworkEndpointConfig = raw.libpodNetwork
		if !raw.networkAllowAliases {
			profile.RequestBody.Network.EndpointConfig.AllowAliases = true
		}
		if !raw.libpodNetworkAllowAliases {
			profile.RequestBody.LibpodNetwork.EndpointConfig.AllowAliases = true
		}
	}
}

// explicitKeysSet reports whether any of keys is set on pv — shared by the
// legacy-listen and network-endpoint-config provenance checks above.
func explicitKeysSet(pv *viper.Viper, keys []string) bool {
	for _, key := range keys {
		if pv.IsSet(key) {
			return true
		}
	}
	return false
}

// decodeMutationsStrict re-decodes the mutations subtree with a strict
// mapstructure.DecoderConfig — ErrorUnused true, WeaklyTypedInput false, no
// decode hook — overwriting the lenient Config-wide decode's cfg.Mutations.
// Every other block in this schema tolerates unknown keys and weak/YAML
// type coercion for backward compatibility; mutations does not, because a
// declarative admission-mutation rule that silently ignores a typo'd key or
// coerces "id: 0" (a YAML integer) into the string "0" is a fail-open
// footgun this feature specifically exists to avoid. See MutationsConfig's
// doc comment.
func decodeMutationsStrict(v *viper.Viper, cfg *Config) error {
	strict := func(c *mapstructure.DecoderConfig) {
		c.ErrorUnused = true
		c.WeaklyTypedInput = false
		c.DecodeHook = nil
	}

	var mutations MutationsConfig
	if err := v.UnmarshalKey("mutations", &mutations, strict); err != nil {
		return fmt.Errorf("decode mutations config: %w", err)
	}
	cfg.Mutations = mutations
	return nil
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

	if err := decodeMutationsStrict(v, &cfg); err != nil {
		return nil, err
	}

	if len(cfg.Rules) == 0 {
		cfg.Rules = defaults.Rules
	}

	cfg.explicitLegacyListen = explicitLegacyListenBytes(data)
	applyEndpointConfigProvenance(&cfg, explicitEndpointConfigBytes(data))

	return &cfg, nil
}
