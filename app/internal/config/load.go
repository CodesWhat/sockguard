package config

import (
	"os"
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
	// Set defaults from Defaults()
	defaults := Defaults()
	v.SetDefault("listen.socket", defaults.Listen.Socket)
	v.SetDefault("listen.socket_mode", defaults.Listen.SocketMode)
	v.SetDefault("listen.address", defaults.Listen.Address)
	v.SetDefault("listen.insecure_allow_plain_tcp", defaults.Listen.InsecureAllowPlainTCP)
	v.SetDefault("listen.tls.cert_file", defaults.Listen.TLS.CertFile)
	v.SetDefault("listen.tls.key_file", defaults.Listen.TLS.KeyFile)
	v.SetDefault("listen.tls.client_ca_file", defaults.Listen.TLS.ClientCAFile)
	v.SetDefault("upstream.socket", defaults.Upstream.Socket)
	v.SetDefault("log.level", defaults.Log.Level)
	v.SetDefault("log.format", defaults.Log.Format)
	v.SetDefault("log.output", defaults.Log.Output)
	v.SetDefault("log.access_log", defaults.Log.AccessLog)
	v.SetDefault("response.deny_verbosity", defaults.Response.DenyVerbosity)
	v.SetDefault("request_body.container_create.allow_privileged", defaults.RequestBody.ContainerCreate.AllowPrivileged)
	v.SetDefault("request_body.container_create.allow_host_network", defaults.RequestBody.ContainerCreate.AllowHostNetwork)
	v.SetDefault("request_body.container_create.allowed_bind_mounts", defaults.RequestBody.ContainerCreate.AllowedBindMounts)
	v.SetDefault("clients.allowed_cidrs", defaults.Clients.AllowedCIDRs)
	v.SetDefault("clients.container_labels.enabled", defaults.Clients.ContainerLabels.Enabled)
	v.SetDefault("clients.container_labels.label_prefix", defaults.Clients.ContainerLabels.LabelPrefix)
	v.SetDefault("ownership.owner", defaults.Ownership.Owner)
	v.SetDefault("ownership.label_key", defaults.Ownership.LabelKey)
	v.SetDefault("ownership.allow_unowned_images", defaults.Ownership.AllowUnownedImages)
	v.SetDefault("health.enabled", defaults.Health.Enabled)
	v.SetDefault("health.path", defaults.Health.Path)
	v.SetDefault("insecure_allow_body_blind_writes", defaults.InsecureAllowBodyBlindWrites)

	// Read YAML file if it exists
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			// Missing file is OK; parse errors are not
			if _, statErr := os.Stat(configPath); statErr != nil && os.IsNotExist(statErr) {
				// File doesn't exist — that's fine, use defaults
			} else {
				// Any other error means the config path exists but couldn't be read or parsed.
				return nil, err
			}
		}
	}

	// Env var overrides: SOCKGUARD_LISTEN_SOCKET, etc.
	v.SetEnvPrefix("SOCKGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	cfg.rulesExplicitlyConfigured = v.IsSet("rules")

	// If no rules came from YAML, use defaults
	if len(cfg.Rules) == 0 {
		cfg.Rules = defaults.Rules
	}

	return &cfg, nil
}
