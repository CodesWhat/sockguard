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
	v.SetDefault("listen.tls.allowed_common_names", defaults.Listen.TLS.AllowedCommonNames)
	v.SetDefault("listen.tls.allowed_dns_names", defaults.Listen.TLS.AllowedDNSNames)
	v.SetDefault("listen.tls.allowed_ip_addresses", defaults.Listen.TLS.AllowedIPAddresses)
	v.SetDefault("listen.tls.allowed_uri_sans", defaults.Listen.TLS.AllowedURISANs)
	v.SetDefault("listen.tls.allowed_public_key_sha256_pins", defaults.Listen.TLS.AllowedPublicKeySHA256Pins)
	v.SetDefault("upstream.socket", defaults.Upstream.Socket)
	v.SetDefault("log.level", defaults.Log.Level)
	v.SetDefault("log.format", defaults.Log.Format)
	v.SetDefault("log.output", defaults.Log.Output)
	v.SetDefault("log.access_log", defaults.Log.AccessLog)
	v.SetDefault("response.deny_verbosity", defaults.Response.DenyVerbosity)
	v.SetDefault("response.redact_container_env", defaults.Response.RedactContainerEnv)
	v.SetDefault("response.redact_mount_paths", defaults.Response.RedactMountPaths)
	v.SetDefault("response.redact_network_topology", defaults.Response.RedactNetworkTopology)
	v.SetDefault("response.redact_sensitive_data", defaults.Response.RedactSensitiveData)
	v.SetDefault("response.visible_resource_labels", defaults.Response.VisibleResourceLabels)
	v.SetDefault("request_body.container_create.allow_privileged", defaults.RequestBody.ContainerCreate.AllowPrivileged)
	v.SetDefault("request_body.container_create.allow_host_network", defaults.RequestBody.ContainerCreate.AllowHostNetwork)
	v.SetDefault("request_body.container_create.allowed_bind_mounts", defaults.RequestBody.ContainerCreate.AllowedBindMounts)
	v.SetDefault("request_body.exec.allow_privileged", defaults.RequestBody.Exec.AllowPrivileged)
	v.SetDefault("request_body.exec.allow_root_user", defaults.RequestBody.Exec.AllowRootUser)
	v.SetDefault("request_body.exec.allowed_commands", defaults.RequestBody.Exec.AllowedCommands)
	v.SetDefault("request_body.image_pull.allow_imports", defaults.RequestBody.ImagePull.AllowImports)
	v.SetDefault("request_body.image_pull.allow_all_registries", defaults.RequestBody.ImagePull.AllowAllRegistries)
	v.SetDefault("request_body.image_pull.allow_official", defaults.RequestBody.ImagePull.AllowOfficial)
	v.SetDefault("request_body.image_pull.allowed_registries", defaults.RequestBody.ImagePull.AllowedRegistries)
	v.SetDefault("request_body.build.allow_remote_context", defaults.RequestBody.Build.AllowRemoteContext)
	v.SetDefault("request_body.build.allow_host_network", defaults.RequestBody.Build.AllowHostNetwork)
	v.SetDefault("request_body.build.allow_run_instructions", defaults.RequestBody.Build.AllowRunInstructions)
	v.SetDefault("request_body.volume.allow_custom_drivers", defaults.RequestBody.Volume.AllowCustomDrivers)
	v.SetDefault("request_body.volume.allow_driver_opts", defaults.RequestBody.Volume.AllowDriverOpts)
	v.SetDefault("request_body.secret.allow_custom_drivers", defaults.RequestBody.Secret.AllowCustomDrivers)
	v.SetDefault("request_body.secret.allow_template_drivers", defaults.RequestBody.Secret.AllowTemplateDrivers)
	v.SetDefault("request_body.config.allow_custom_drivers", defaults.RequestBody.Config.AllowCustomDrivers)
	v.SetDefault("request_body.config.allow_template_drivers", defaults.RequestBody.Config.AllowTemplateDrivers)
	v.SetDefault("request_body.service.allow_host_network", defaults.RequestBody.Service.AllowHostNetwork)
	v.SetDefault("request_body.service.allowed_bind_mounts", defaults.RequestBody.Service.AllowedBindMounts)
	v.SetDefault("request_body.service.allow_all_registries", defaults.RequestBody.Service.AllowAllRegistries)
	v.SetDefault("request_body.service.allow_official", defaults.RequestBody.Service.AllowOfficial)
	v.SetDefault("request_body.service.allowed_registries", defaults.RequestBody.Service.AllowedRegistries)
	v.SetDefault("request_body.swarm.allow_force_new_cluster", defaults.RequestBody.Swarm.AllowForceNewCluster)
	v.SetDefault("request_body.swarm.allow_external_ca", defaults.RequestBody.Swarm.AllowExternalCA)
	v.SetDefault("request_body.swarm.allowed_join_remote_addrs", defaults.RequestBody.Swarm.AllowedJoinRemoteAddrs)
	v.SetDefault("request_body.swarm.allow_token_rotation", defaults.RequestBody.Swarm.AllowTokenRotation)
	v.SetDefault("request_body.swarm.allow_manager_unlock_key_rotation", defaults.RequestBody.Swarm.AllowManagerUnlockKeyRotation)
	v.SetDefault("request_body.swarm.allow_auto_lock_managers", defaults.RequestBody.Swarm.AllowAutoLockManagers)
	v.SetDefault("request_body.swarm.allow_signing_ca_update", defaults.RequestBody.Swarm.AllowSigningCAUpdate)
	v.SetDefault("request_body.plugin.allow_host_network", defaults.RequestBody.Plugin.AllowHostNetwork)
	v.SetDefault("request_body.plugin.allow_ipc_host", defaults.RequestBody.Plugin.AllowIPCHost)
	v.SetDefault("request_body.plugin.allow_pid_host", defaults.RequestBody.Plugin.AllowPIDHost)
	v.SetDefault("request_body.plugin.allow_all_devices", defaults.RequestBody.Plugin.AllowAllDevices)
	v.SetDefault("request_body.plugin.allowed_bind_mounts", defaults.RequestBody.Plugin.AllowedBindMounts)
	v.SetDefault("request_body.plugin.allowed_devices", defaults.RequestBody.Plugin.AllowedDevices)
	v.SetDefault("request_body.plugin.allow_all_capabilities", defaults.RequestBody.Plugin.AllowAllCapabilities)
	v.SetDefault("request_body.plugin.allowed_capabilities", defaults.RequestBody.Plugin.AllowedCapabilities)
	v.SetDefault("request_body.plugin.allow_all_registries", defaults.RequestBody.Plugin.AllowAllRegistries)
	v.SetDefault("request_body.plugin.allow_official", defaults.RequestBody.Plugin.AllowOfficial)
	v.SetDefault("request_body.plugin.allowed_registries", defaults.RequestBody.Plugin.AllowedRegistries)
	v.SetDefault("request_body.plugin.allowed_set_env_prefixes", defaults.RequestBody.Plugin.AllowedSetEnvPrefixes)
	v.SetDefault("clients.allowed_cidrs", defaults.Clients.AllowedCIDRs)
	v.SetDefault("clients.container_labels.enabled", defaults.Clients.ContainerLabels.Enabled)
	v.SetDefault("clients.container_labels.label_prefix", defaults.Clients.ContainerLabels.LabelPrefix)
	v.SetDefault("clients.default_profile", defaults.Clients.DefaultProfile)
	v.SetDefault("clients.source_ip_profiles", defaults.Clients.SourceIPProfiles)
	v.SetDefault("clients.client_certificate_profiles", defaults.Clients.ClientCertificateProfiles)
	v.SetDefault("clients.unix_peer_profiles", defaults.Clients.UnixPeerProfiles)
	v.SetDefault("clients.profiles", defaults.Clients.Profiles)
	v.SetDefault("ownership.owner", defaults.Ownership.Owner)
	v.SetDefault("ownership.label_key", defaults.Ownership.LabelKey)
	v.SetDefault("ownership.allow_unowned_images", defaults.Ownership.AllowUnownedImages)
	v.SetDefault("health.enabled", defaults.Health.Enabled)
	v.SetDefault("health.path", defaults.Health.Path)
	v.SetDefault("insecure_allow_body_blind_writes", defaults.InsecureAllowBodyBlindWrites)
	v.SetDefault("insecure_allow_read_exfiltration", defaults.InsecureAllowReadExfiltration)

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

	applyCompatEnvAliases(&cfg)

	// If no rules came from YAML, use defaults
	if len(cfg.Rules) == 0 {
		cfg.Rules = defaults.Rules
	}

	return &cfg, nil
}
