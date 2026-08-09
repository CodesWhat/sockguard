package config

import "testing"

// network_endpoint_config_test.go covers #186's granular
// request_body.network.endpoint_config block: defaults, env-var mapping,
// filter-options translation edge cases, and the
// allow_endpoint_config/endpoint_config mutual-exclusion validation.
// filter_options_test.go covers the ToFilterOptions cross-wire itself.

// TestDefaultsEndpointConfigAllowAliasesTrue proves the granular form's
// default reproduces allow_endpoint_config's historical unconditional-allow
// behavior for Aliases: AllowAliases defaults true for both network and
// libpod_network (the latter is never consulted, but keeps the same default
// posture for consistency — see config.Defaults()'s doc comment), while
// every other granular field defaults false (deny), matching the rest of
// the codebase's fail-closed convention.
func TestDefaultsEndpointConfigAllowAliasesTrue(t *testing.T) {
	d := Defaults()
	if !d.RequestBody.Network.EndpointConfig.AllowAliases {
		t.Error("RequestBody.Network.EndpointConfig.AllowAliases = false, want true")
	}
	if !d.RequestBody.LibpodNetwork.EndpointConfig.AllowAliases {
		t.Error("RequestBody.LibpodNetwork.EndpointConfig.AllowAliases = false, want true")
	}
	ec := d.RequestBody.Network.EndpointConfig
	if ec.AllowStaticAddressing || ec.AllowLinkLocalIPs || ec.AllowMACPinning || ec.AllowGwPriority {
		t.Errorf("EndpointConfig granular fields other than AllowAliases must default false, got %#v", ec)
	}
}

// TestLoadHonorsEndpointConfigEnvVars is the targeted regression matching
// load_env_defaults_test.go's convention: guards each of the 5 new
// SOCKGUARD_REQUEST_BODY_NETWORK_ENDPOINT_CONFIG_* env vars individually, on
// top of the generic sweep in load_defaults_completeness_test.go.
func TestLoadHonorsEndpointConfigEnvVars(t *testing.T) {
	t.Setenv("SOCKGUARD_REQUEST_BODY_NETWORK_ENDPOINT_CONFIG_ALLOW_STATIC_ADDRESSING", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_NETWORK_ENDPOINT_CONFIG_ALLOW_LINK_LOCAL_IPS", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_NETWORK_ENDPOINT_CONFIG_ALLOW_MAC_PINNING", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_NETWORK_ENDPOINT_CONFIG_ALLOW_GW_PRIORITY", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_NETWORK_ENDPOINT_CONFIG_ALLOW_ALIASES", "false")

	cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	ec := cfg.RequestBody.Network.EndpointConfig
	if !ec.AllowStaticAddressing {
		t.Error("AllowStaticAddressing = false, want true from env")
	}
	if !ec.AllowLinkLocalIPs {
		t.Error("AllowLinkLocalIPs = false, want true from env")
	}
	if !ec.AllowMACPinning {
		t.Error("AllowMACPinning = false, want true from env")
	}
	if !ec.AllowGwPriority {
		t.Error("AllowGwPriority = false, want true from env")
	}
	if ec.AllowAliases {
		t.Error("AllowAliases = true, want false from env override")
	}
}

// TestValidateRejectsAllowEndpointConfigWithExplicitGranularBlock proves the
// #186 mutual-exclusion rule: setting both
// request_body.network.allow_endpoint_config: true and an explicit
// endpoint_config block is a load-time validation error, whether the
// granular block is set via YAML or a SOCKGUARD_* environment variable.
func TestValidateRejectsAllowEndpointConfigWithExplicitGranularBlock(t *testing.T) {
	t.Run("via YAML", func(t *testing.T) {
		cfg, err := LoadBytes([]byte(`
request_body:
  network:
    allow_endpoint_config: true
    endpoint_config:
      allow_static_addressing: true
rules:
  - match: { method: GET, path: /_ping }
    action: allow
`))
		if err != nil {
			t.Fatalf("LoadBytes: %v", err)
		}
		if !cfg.ExplicitNetworkEndpointConfig() {
			t.Fatal("ExplicitNetworkEndpointConfig() = false, want true")
		}
		requireValidationContains(t, cfg, "request_body.network.allow_endpoint_config and request_body.network.endpoint_config are mutually exclusive")
	})

	t.Run("via environment variable", func(t *testing.T) {
		t.Setenv("SOCKGUARD_REQUEST_BODY_NETWORK_ALLOW_ENDPOINT_CONFIG", "true")
		t.Setenv("SOCKGUARD_REQUEST_BODY_NETWORK_ENDPOINT_CONFIG_ALLOW_MAC_PINNING", "true")

		cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !cfg.ExplicitNetworkEndpointConfig() {
			t.Fatal("ExplicitNetworkEndpointConfig() = false, want true")
		}
		requireValidationContains(t, cfg, "request_body.network.allow_endpoint_config and request_body.network.endpoint_config are mutually exclusive")
	})
}

// TestValidateAllowsAllowEndpointConfigAlone proves the legacy flag alone,
// with no explicit endpoint_config block, is unaffected by the new
// validation — the overwhelming majority of existing configs that already
// use allow_endpoint_config: true must keep validating cleanly.
func TestValidateAllowsAllowEndpointConfigAlone(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
request_body:
  network:
    allow_endpoint_config: true
rules:
  - match: { method: GET, path: /_ping }
    action: allow
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.ExplicitNetworkEndpointConfig() {
		t.Fatal("ExplicitNetworkEndpointConfig() = true, want false (endpoint_config block was never set)")
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

// TestValidateAllowsGranularEndpointConfigAlone proves the granular block
// alone, with allow_endpoint_config left at its false default, is the
// intended normal usage and validates cleanly.
func TestValidateAllowsGranularEndpointConfigAlone(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
request_body:
  network:
    endpoint_config:
      allow_static_addressing: true
      allow_mac_pinning: true
rules:
  - match: { method: GET, path: /_ping }
    action: allow
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if !cfg.ExplicitNetworkEndpointConfig() {
		t.Fatal("ExplicitNetworkEndpointConfig() = false, want true")
	}
	if cfg.RequestBody.Network.AllowEndpointConfig {
		t.Fatal("AllowEndpointConfig = true, want false (default)")
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if !cfg.RequestBody.Network.EndpointConfig.AllowStaticAddressing {
		t.Error("AllowStaticAddressing = false, want true")
	}
	if !cfg.RequestBody.Network.EndpointConfig.AllowMACPinning {
		t.Error("AllowMACPinning = false, want true")
	}
	// Untouched granular fields keep their documented defaults.
	if !cfg.RequestBody.Network.EndpointConfig.AllowAliases {
		t.Error("AllowAliases = false, want true (default)")
	}
	if cfg.RequestBody.Network.EndpointConfig.AllowGwPriority {
		t.Error("AllowGwPriority = true, want false (default)")
	}
}

// TestValidateDefaultsHasNoExplicitEndpointConfigBlock proves the baseline
// Defaults() config — with no file or env input at all — is not flagged as
// having an explicit endpoint_config block, even though
// EndpointConfig.AllowAliases defaults to true. This is the case
// validateNetworkEndpointConfig's doc comment calls out: the merged struct
// is never the Go zero value, so provenance tracking (not zero-value
// comparison) is what keeps ordinary defaulted configs from false-positively
// tripping the mutual-exclusion check.
func TestValidateDefaultsHasNoExplicitEndpointConfigBlock(t *testing.T) {
	cfg, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ExplicitNetworkEndpointConfig() {
		t.Fatal("ExplicitNetworkEndpointConfig() = true, want false for a pure-defaults config")
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

// FuzzLoadBytesEndpointConfig fuzzes LoadBytes/Validate against YAML bodies
// centered on the #186 request_body.network.endpoint_config block: an empty
// block (defaults only), a single granular field set, and the
// allow_endpoint_config/endpoint_config mutual-exclusion combination this
// file's table tests above cover explicitly. Mirrors FuzzLoadYAML's
// LoadBytes counterpart — LoadBytes/Validate must never panic on arbitrary
// YAML, and Validate is only exercised when LoadBytes itself succeeds,
// matching how every real caller (admin /admin/validate, signed policy
// bundles) chains the two.
func FuzzLoadBytesEndpointConfig(f *testing.F) {
	f.Add([]byte(`
request_body:
  network:
    endpoint_config: {}
rules:
  - match: { method: GET, path: /_ping }
    action: allow
`))
	f.Add([]byte(`
request_body:
  network:
    endpoint_config:
      allow_mac_pinning: true
rules:
  - match: { method: GET, path: /_ping }
    action: allow
`))
	f.Add([]byte(`
request_body:
  network:
    allow_endpoint_config: true
    endpoint_config:
      allow_static_addressing: true
rules:
  - match: { method: GET, path: /_ping }
    action: allow
`))
	f.Add([]byte(`
request_body:
  network:
    endpoint_config:
      allow_static_addressing: true
      allow_link_local_ips: true
      allow_mac_pinning: true
      allow_gw_priority: true
      allow_aliases: false
rules:
  - match: { method: GET, path: /_ping }
    action: allow
`))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := LoadBytes(data)
		if err != nil {
			return
		}
		_ = Validate(cfg)
	})
}
