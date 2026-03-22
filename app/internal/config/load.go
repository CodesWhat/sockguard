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

	// Set defaults from Defaults()
	defaults := Defaults()
	v.SetDefault("listen.socket", defaults.Listen.Socket)
	v.SetDefault("listen.socket_mode", defaults.Listen.SocketMode)
	v.SetDefault("listen.address", defaults.Listen.Address)
	v.SetDefault("upstream.socket", defaults.Upstream.Socket)
	v.SetDefault("log.level", defaults.Log.Level)
	v.SetDefault("log.format", defaults.Log.Format)
	v.SetDefault("log.output", defaults.Log.Output)
	v.SetDefault("log.access_log", defaults.Log.AccessLog)
	v.SetDefault("health.enabled", defaults.Health.Enabled)
	v.SetDefault("health.path", defaults.Health.Path)

	// Read YAML file if it exists
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			// Missing file is OK; parse errors are not
			if _, statErr := os.Stat(configPath); statErr != nil {
				// File doesn't exist — that's fine, use defaults
			} else {
				// File exists but failed to parse
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

	// If no rules came from YAML, use defaults
	if len(cfg.Rules) == 0 {
		cfg.Rules = defaults.Rules
	}

	return &cfg, nil
}
