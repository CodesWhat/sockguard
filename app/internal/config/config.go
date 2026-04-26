package config

// HardenedListenSocketMode is the only supported unix-socket permission mode.
const HardenedListenSocketMode = "0600"

// Config represents the sockguard configuration.
type Config struct {
	Listen                        ListenConfig      `mapstructure:"listen"`
	Upstream                      UpstreamConfig    `mapstructure:"upstream"`
	Log                           LogConfig         `mapstructure:"log"`
	Response                      ResponseConfig    `mapstructure:"response"`
	RequestBody                   RequestBodyConfig `mapstructure:"request_body"`
	Clients                       ClientsConfig     `mapstructure:"clients"`
	Ownership                     OwnershipConfig   `mapstructure:"ownership"`
	Health                        HealthConfig      `mapstructure:"health"`
	Rules                         []RuleConfig      `mapstructure:"rules"`
	InsecureAllowBodyBlindWrites  bool              `mapstructure:"insecure_allow_body_blind_writes"`
	InsecureAllowReadExfiltration bool              `mapstructure:"insecure_allow_read_exfiltration"`
}

// ListenConfig configures the proxy listener.
type ListenConfig struct {
	Socket                string          `mapstructure:"socket"`
	SocketMode            string          `mapstructure:"socket_mode"`
	Address               string          `mapstructure:"address"`
	InsecureAllowPlainTCP bool            `mapstructure:"insecure_allow_plain_tcp"`
	TLS                   ListenTLSConfig `mapstructure:"tls"`
}

// ListenTLSConfig configures mutual TLS for TCP listeners.
type ListenTLSConfig struct {
	CertFile                   string   `mapstructure:"cert_file"`
	KeyFile                    string   `mapstructure:"key_file"`
	ClientCAFile               string   `mapstructure:"client_ca_file"`
	AllowedCommonNames         []string `mapstructure:"allowed_common_names"`
	AllowedDNSNames            []string `mapstructure:"allowed_dns_names"`
	AllowedIPAddresses         []string `mapstructure:"allowed_ip_addresses"`
	AllowedURISANs             []string `mapstructure:"allowed_uri_sans"`
	AllowedPublicKeySHA256Pins []string `mapstructure:"allowed_public_key_sha256_pins"`
}

// UpstreamConfig configures the upstream Docker socket.
type UpstreamConfig struct {
	Socket string `mapstructure:"socket"`
}

// LogConfig configures logging.
type LogConfig struct {
	Level     string `mapstructure:"level"`
	Format    string `mapstructure:"format"`
	Output    string `mapstructure:"output"`
	AccessLog bool   `mapstructure:"access_log"`
	Audit     AuditLogConfig `mapstructure:"audit"`
}

// AuditLogConfig configures the dedicated audit-event pipeline.
type AuditLogConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Format  string `mapstructure:"format"`
	Output  string `mapstructure:"output"`
}

// ResponseConfig configures HTTP responses returned by sockguard itself.
type ResponseConfig struct {
	DenyVerbosity         string   `mapstructure:"deny_verbosity"`
	RedactContainerEnv    bool     `mapstructure:"redact_container_env"`
	RedactMountPaths      bool     `mapstructure:"redact_mount_paths"`
	RedactNetworkTopology bool     `mapstructure:"redact_network_topology"`
	RedactSensitiveData   bool     `mapstructure:"redact_sensitive_data"`
	VisibleResourceLabels []string `mapstructure:"visible_resource_labels"`
}

// RequestBodyConfig configures request-body inspection policies.
type RequestBodyConfig struct {
	ContainerCreate ContainerCreateRequestBodyConfig `mapstructure:"container_create"`
	Exec            ExecRequestBodyConfig            `mapstructure:"exec"`
	ImagePull       ImagePullRequestBodyConfig       `mapstructure:"image_pull"`
	Build           BuildRequestBodyConfig           `mapstructure:"build"`
	Volume          VolumeRequestBodyConfig          `mapstructure:"volume"`
	Secret          SecretRequestBodyConfig          `mapstructure:"secret"`
	Config          ConfigRequestBodyConfig          `mapstructure:"config"`
	Service         ServiceRequestBodyConfig         `mapstructure:"service"`
	Swarm           SwarmRequestBodyConfig           `mapstructure:"swarm"`
	Plugin          PluginRequestBodyConfig          `mapstructure:"plugin"`
}

// ContainerCreateRequestBodyConfig configures body inspection for
// POST /containers/create requests.
type ContainerCreateRequestBodyConfig struct {
	AllowPrivileged   bool     `mapstructure:"allow_privileged"`
	AllowHostNetwork  bool     `mapstructure:"allow_host_network"`
	AllowedBindMounts []string `mapstructure:"allowed_bind_mounts"`
}

// ExecRequestBodyConfig configures body inspection for exec creation/start.
type ExecRequestBodyConfig struct {
	AllowPrivileged bool       `mapstructure:"allow_privileged"`
	AllowRootUser   bool       `mapstructure:"allow_root_user"`
	AllowedCommands [][]string `mapstructure:"allowed_commands"`
}

// ImagePullRequestBodyConfig configures inspection for POST /images/create.
type ImagePullRequestBodyConfig struct {
	AllowImports       bool     `mapstructure:"allow_imports"`
	AllowAllRegistries bool     `mapstructure:"allow_all_registries"`
	AllowOfficial      bool     `mapstructure:"allow_official"`
	AllowedRegistries  []string `mapstructure:"allowed_registries"`
}

// BuildRequestBodyConfig configures inspection for POST /build.
type BuildRequestBodyConfig struct {
	AllowRemoteContext   bool `mapstructure:"allow_remote_context"`
	AllowHostNetwork     bool `mapstructure:"allow_host_network"`
	AllowRunInstructions bool `mapstructure:"allow_run_instructions"`
}

// VolumeRequestBodyConfig configures inspection for POST /volumes/create.
type VolumeRequestBodyConfig struct {
	AllowCustomDrivers bool `mapstructure:"allow_custom_drivers"`
	AllowDriverOpts    bool `mapstructure:"allow_driver_opts"`
}

// SecretRequestBodyConfig configures inspection for POST /secrets/create.
type SecretRequestBodyConfig struct {
	AllowCustomDrivers   bool `mapstructure:"allow_custom_drivers"`
	AllowTemplateDrivers bool `mapstructure:"allow_template_drivers"`
}

// ConfigRequestBodyConfig configures inspection for POST /configs/create.
type ConfigRequestBodyConfig struct {
	AllowCustomDrivers   bool `mapstructure:"allow_custom_drivers"`
	AllowTemplateDrivers bool `mapstructure:"allow_template_drivers"`
}

// ServiceRequestBodyConfig configures inspection for service create/update.
type ServiceRequestBodyConfig struct {
	AllowHostNetwork   bool     `mapstructure:"allow_host_network"`
	AllowedBindMounts  []string `mapstructure:"allowed_bind_mounts"`
	AllowAllRegistries bool     `mapstructure:"allow_all_registries"`
	AllowOfficial      bool     `mapstructure:"allow_official"`
	AllowedRegistries  []string `mapstructure:"allowed_registries"`
}

// SwarmRequestBodyConfig configures inspection for swarm init.
type SwarmRequestBodyConfig struct {
	AllowForceNewCluster          bool     `mapstructure:"allow_force_new_cluster"`
	AllowExternalCA               bool     `mapstructure:"allow_external_ca"`
	AllowedJoinRemoteAddrs        []string `mapstructure:"allowed_join_remote_addrs"`
	AllowTokenRotation            bool     `mapstructure:"allow_token_rotation"`
	AllowManagerUnlockKeyRotation bool     `mapstructure:"allow_manager_unlock_key_rotation"`
	AllowAutoLockManagers         bool     `mapstructure:"allow_auto_lock_managers"`
	AllowSigningCAUpdate          bool     `mapstructure:"allow_signing_ca_update"`
}

// PluginRequestBodyConfig configures inspection for plugin write endpoints.
type PluginRequestBodyConfig struct {
	AllowHostNetwork      bool     `mapstructure:"allow_host_network"`
	AllowIPCHost          bool     `mapstructure:"allow_ipc_host"`
	AllowPIDHost          bool     `mapstructure:"allow_pid_host"`
	AllowAllDevices       bool     `mapstructure:"allow_all_devices"`
	AllowedBindMounts     []string `mapstructure:"allowed_bind_mounts"`
	AllowedDevices        []string `mapstructure:"allowed_devices"`
	AllowAllCapabilities  bool     `mapstructure:"allow_all_capabilities"`
	AllowedCapabilities   []string `mapstructure:"allowed_capabilities"`
	AllowAllRegistries    bool     `mapstructure:"allow_all_registries"`
	AllowOfficial         bool     `mapstructure:"allow_official"`
	AllowedRegistries     []string `mapstructure:"allowed_registries"`
	AllowedSetEnvPrefixes []string `mapstructure:"allowed_set_env_prefixes"`
}

// ClientsConfig configures coarse per-client access controls.
type ClientsConfig struct {
	AllowedCIDRs              []string                                   `mapstructure:"allowed_cidrs"`
	ContainerLabels           ClientContainerLabelsConfig                `mapstructure:"container_labels"`
	DefaultProfile            string                                     `mapstructure:"default_profile"`
	SourceIPProfiles          []ClientSourceIPProfileAssignmentConfig    `mapstructure:"source_ip_profiles"`
	ClientCertificateProfiles []ClientCertificateProfileAssignmentConfig `mapstructure:"client_certificate_profiles"`
	UnixPeerProfiles          []ClientUnixPeerProfileAssignmentConfig    `mapstructure:"unix_peer_profiles"`
	Profiles                  []ClientProfileConfig                      `mapstructure:"profiles"`
}

// ClientContainerLabelsConfig configures opt-in per-client ACLs loaded from
// the calling container's labels after resolving the caller by source IP.
type ClientContainerLabelsConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	LabelPrefix string `mapstructure:"label_prefix"`
}

// ClientSourceIPProfileAssignmentConfig maps one or more source CIDRs to a
// named client profile.
type ClientSourceIPProfileAssignmentConfig struct {
	Profile string   `mapstructure:"profile"`
	CIDRs   []string `mapstructure:"cidrs"`
}

// ClientCertificateProfileAssignmentConfig maps one or more mTLS client
// certificate common names to a named client profile.
type ClientCertificateProfileAssignmentConfig struct {
	Profile     string   `mapstructure:"profile"`
	CommonNames []string `mapstructure:"common_names"`
	DNSNames    []string `mapstructure:"dns_names"`
	IPAddresses []string `mapstructure:"ip_addresses"`
	URISANs     []string `mapstructure:"uri_sans"`
	SPIFFEIDs   []string `mapstructure:"spiffe_ids"`
}

// ClientUnixPeerProfileAssignmentConfig maps one or more unix peer
// credential selectors to a named client profile.
type ClientUnixPeerProfileAssignmentConfig struct {
	Profile string   `mapstructure:"profile"`
	UIDs    []uint32 `mapstructure:"uids"`
	GIDs    []uint32 `mapstructure:"gids"`
	PIDs    []int32  `mapstructure:"pids"`
}

// ClientProfileConfig defines a named per-client request policy profile.
type ClientProfileConfig struct {
	Name        string                      `mapstructure:"name"`
	Response    ClientProfileResponseConfig `mapstructure:"response"`
	RequestBody RequestBodyConfig           `mapstructure:"request_body"`
	Rules       []RuleConfig                `mapstructure:"rules"`
}

// ClientProfileResponseConfig configures per-profile visibility control on
// Docker read endpoints.
type ClientProfileResponseConfig struct {
	VisibleResourceLabels []string `mapstructure:"visible_resource_labels"`
}

// OwnershipConfig configures per-proxy resource ownership labeling and
// enforcement.
type OwnershipConfig struct {
	Owner              string `mapstructure:"owner"`
	LabelKey           string `mapstructure:"label_key"`
	AllowUnownedImages bool   `mapstructure:"allow_unowned_images"`
}

// HealthConfig configures the health check endpoint.
type HealthConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

// RuleConfig represents a single access control rule in config.
type RuleConfig struct {
	Match  MatchConfig `mapstructure:"match"`
	Action string      `mapstructure:"action"`
	Reason string      `mapstructure:"reason"`
}

// MatchConfig represents the match criteria for a rule.
type MatchConfig struct {
	Method string `mapstructure:"method"`
	Path   string `mapstructure:"path"`
}

// Defaults returns a Config with sensible defaults.
//
// The default listener is loopback TCP 127.0.0.1:2375 so local development
// stays simple without exposing the Docker API proxy on the network. To expose
// Sockguard on non-loopback TCP you must either configure listen.tls for mTLS
// or explicitly opt into legacy plaintext mode with
// listen.insecure_allow_plain_tcp=true.
func Defaults() Config {
	return Config{
		Listen: ListenConfig{
			Address:    "127.0.0.1:2375",
			SocketMode: HardenedListenSocketMode, // used only when the user opts into a unix socket listener
		},
		Upstream: UpstreamConfig{
			Socket: "/var/run/docker.sock",
		},
		Log: LogConfig{
			Level:     "info",
			Format:    "json",
			Output:    "stderr",
			AccessLog: true,
			Audit: AuditLogConfig{
				Enabled: false,
				Format:  "json",
				Output:  "stderr",
			},
		},
		Response: ResponseConfig{
			// Default to minimal deny responses: the generic message only,
			// no method, path, or reason echoed back. Verbose mode is still
			// supported for rule-authoring and dev work, but it is never a
			// production default because it can leak request path details
			// (even with `/secrets/*` and `/swarm/unlockkey` redacted) that
			// a honest security product should not hand a denied caller.
			DenyVerbosity:         "minimal",
			RedactContainerEnv:    true,
			RedactMountPaths:      true,
			RedactNetworkTopology: true,
			RedactSensitiveData:   true,
		},
		RequestBody: RequestBodyConfig{
			ContainerCreate: ContainerCreateRequestBodyConfig{},
			ImagePull: ImagePullRequestBodyConfig{
				AllowOfficial: true,
			},
			Service: ServiceRequestBodyConfig{
				AllowOfficial: true,
			},
			Plugin: PluginRequestBodyConfig{
				AllowOfficial: true,
			},
		},
		Clients: ClientsConfig{
			ContainerLabels: ClientContainerLabelsConfig{
				LabelPrefix: "com.sockguard.allow.",
			},
		},
		Ownership: OwnershipConfig{
			LabelKey:           "com.sockguard.owner",
			AllowUnownedImages: true,
		},
		Health: HealthConfig{
			Enabled: true,
			Path:    "/health",
		},
		Rules: []RuleConfig{
			{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"},
			{Match: MatchConfig{Method: "HEAD", Path: "/_ping"}, Action: "allow"},
			{Match: MatchConfig{Method: "GET", Path: "/version"}, Action: "allow"},
			{Match: MatchConfig{Method: "GET", Path: "/events"}, Action: "allow"},
			{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
		},
		InsecureAllowReadExfiltration: false,
	}
}
