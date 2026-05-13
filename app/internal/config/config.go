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
	Metrics                       MetricsConfig     `mapstructure:"metrics"`
	Admin                         AdminConfig       `mapstructure:"admin"`
	Reload                        ReloadConfig      `mapstructure:"reload"`
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
	Level     string         `mapstructure:"level"`
	Format    string         `mapstructure:"format"`
	Output    string         `mapstructure:"output"`
	AccessLog bool           `mapstructure:"access_log"`
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
	// NamePatterns is a list of glob patterns matched against container Names[0]
	// (leading "/" stripped) and image RepoTags short names. Resources whose
	// name does not match at least one pattern are hidden. Empty means no
	// name-based filtering.
	NamePatterns []string `mapstructure:"name_patterns"`
	// ImagePatterns is a list of glob patterns matched against container Image
	// field and image RepoTags full references. Resources whose image reference
	// does not match at least one pattern are hidden. Empty means no image-based
	// filtering.
	ImagePatterns []string `mapstructure:"image_patterns"`
}

// RequestBodyConfig configures request-body inspection policies.
type RequestBodyConfig struct {
	ContainerCreate  ContainerCreateRequestBodyConfig  `mapstructure:"container_create"`
	Exec             ExecRequestBodyConfig             `mapstructure:"exec"`
	ImagePull        ImagePullRequestBodyConfig        `mapstructure:"image_pull"`
	Build            BuildRequestBodyConfig            `mapstructure:"build"`
	ContainerUpdate  ContainerUpdateRequestBodyConfig  `mapstructure:"container_update"`
	ContainerArchive ContainerArchiveRequestBodyConfig `mapstructure:"container_archive"`
	ImageLoad        ImageLoadRequestBodyConfig        `mapstructure:"image_load"`
	Volume           VolumeRequestBodyConfig           `mapstructure:"volume"`
	Network          NetworkRequestBodyConfig          `mapstructure:"network"`
	Secret           SecretRequestBodyConfig           `mapstructure:"secret"`
	Config           ConfigRequestBodyConfig           `mapstructure:"config"`
	Service          ServiceRequestBodyConfig          `mapstructure:"service"`
	Swarm            SwarmRequestBodyConfig            `mapstructure:"swarm"`
	Node             NodeRequestBodyConfig             `mapstructure:"node"`
	Plugin           PluginRequestBodyConfig           `mapstructure:"plugin"`
}

// ContainerCreateRequestBodyConfig configures body inspection for
// POST /containers/create requests.
type ContainerCreateRequestBodyConfig struct {
	AllowPrivileged        bool     `mapstructure:"allow_privileged"`
	AllowHostNetwork       bool     `mapstructure:"allow_host_network"`
	AllowHostPID           bool     `mapstructure:"allow_host_pid"`
	AllowHostIPC           bool     `mapstructure:"allow_host_ipc"`
	AllowedBindMounts      []string `mapstructure:"allowed_bind_mounts"`
	AllowAllDevices        bool     `mapstructure:"allow_all_devices"`
	AllowedDevices         []string `mapstructure:"allowed_devices"`
	AllowDeviceRequests         bool                   `mapstructure:"allow_device_requests"`
	AllowedDeviceRequests       []AllowedDeviceRequest `mapstructure:"allowed_device_requests"`
	AllowDeviceCgroupRules      bool                   `mapstructure:"allow_device_cgroup_rules"`
	AllowedDeviceCgroupRules    []string               `mapstructure:"allowed_device_cgroup_rules"`

	RequireNoNewPrivileges     bool     `mapstructure:"require_no_new_privileges"`
	RequireNonRootUser         bool     `mapstructure:"require_non_root_user"`
	RequireReadonlyRootfs      bool     `mapstructure:"require_readonly_rootfs"`
	RequireDropAllCapabilities bool     `mapstructure:"require_drop_all_capabilities"`
	AllowAllCapabilities       bool     `mapstructure:"allow_all_capabilities"`
	AllowedCapabilities        []string `mapstructure:"allowed_capabilities"`
	RequireMemoryLimit         bool     `mapstructure:"require_memory_limit"`
	RequireCPULimit            bool     `mapstructure:"require_cpu_limit"`
	RequirePidsLimit           bool     `mapstructure:"require_pids_limit"`
	AllowedSeccompProfiles     []string `mapstructure:"allowed_seccomp_profiles"`
	DenyUnconfinedSeccomp      bool     `mapstructure:"deny_unconfined_seccomp"`
	AllowedAppArmorProfiles    []string `mapstructure:"allowed_apparmor_profiles"`
	DenyUnconfinedAppArmor     bool     `mapstructure:"deny_unconfined_apparmor"`
	AllowHostUserNS            bool     `mapstructure:"allow_host_userns"`
	RequiredLabels             []string `mapstructure:"required_labels"`
	ImageTrust                 ImageTrustConfig `mapstructure:"image_trust"`
}

// ImageTrustConfig configures cosign signature verification for images
// referenced in POST /containers/create.
type ImageTrustConfig struct {
	// Mode controls enforcement: off | warn | enforce. Default: off.
	Mode string `mapstructure:"mode"`
	// AllowedSigningKeys lists PEM-encoded public keys that are trusted to
	// sign images. Keyed verification is attempted before keyless.
	AllowedSigningKeys []SigningKeyConfig `mapstructure:"allowed_signing_keys"`
	// AllowedKeyless lists Fulcio-issued OIDC identity patterns. Each entry
	// must specify an exact issuer URL and a regex against the cert's SAN.
	AllowedKeyless []KeylessConfig `mapstructure:"allowed_keyless"`
	// RequireRekorInclusion requires a Rekor tlog inclusion proof for keyless
	// verification. Default true.
	RequireRekorInclusion bool `mapstructure:"require_rekor_inclusion"`
	// VerifyTimeout overrides the default 10s per-verification timeout.
	VerifyTimeout string `mapstructure:"verify_timeout"`
}

// SigningKeyConfig is one entry in image_trust.allowed_signing_keys.
type SigningKeyConfig struct {
	// PEM is the PEM-encoded public key (ECDSA, RSA, or ed25519).
	PEM string `mapstructure:"pem"`
}

// KeylessConfig is one entry in image_trust.allowed_keyless.
type KeylessConfig struct {
	// Issuer is the exact OIDC issuer URL to match against the Fulcio cert.
	Issuer string `mapstructure:"issuer"`
	// SubjectPattern is a Go regexp matched against the cert's SAN.
	SubjectPattern string `mapstructure:"subject_pattern"`
}

// AllowedDeviceRequest is a single entry in the allowed_device_requests allowlist.
// Driver is required and must exactly match the request's Driver field (after
// lowercasing). AllowedCapabilities is a list of capability-sets; the request's
// capability sets must each be a subset of at least one allowlisted set.
// MaxCount, when non-nil, bounds the request Count; -1 means "all" and is only
// permitted when MaxCount is also -1.
type AllowedDeviceRequest struct {
	Driver              string     `mapstructure:"driver"`
	AllowedCapabilities [][]string `mapstructure:"allowed_capabilities"`
	MaxCount            *int       `mapstructure:"max_count"`
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

// ContainerUpdateRequestBodyConfig configures inspection for
// POST /containers/*/update.
type ContainerUpdateRequestBodyConfig struct {
	AllowPrivileged      bool `mapstructure:"allow_privileged"`
	AllowDevices         bool `mapstructure:"allow_devices"`
	AllowCapabilities    bool `mapstructure:"allow_capabilities"`
	AllowResourceUpdates bool `mapstructure:"allow_resource_updates"`
	AllowRestartPolicy   bool `mapstructure:"allow_restart_policy"`
}

// ContainerArchiveRequestBodyConfig configures inspection for
// PUT /containers/*/archive.
type ContainerArchiveRequestBodyConfig struct {
	AllowedPaths       []string `mapstructure:"allowed_paths"`
	AllowSetID         bool     `mapstructure:"allow_setid"`
	AllowDeviceNodes   bool     `mapstructure:"allow_device_nodes"`
	AllowEscapingLinks bool     `mapstructure:"allow_escaping_links"`
}

// ImageLoadRequestBodyConfig configures inspection for POST /images/load.
type ImageLoadRequestBodyConfig struct {
	AllowAllRegistries bool     `mapstructure:"allow_all_registries"`
	AllowOfficial      bool     `mapstructure:"allow_official"`
	AllowedRegistries  []string `mapstructure:"allowed_registries"`
	AllowUntagged      bool     `mapstructure:"allow_untagged"`
}

// VolumeRequestBodyConfig configures inspection for POST /volumes/create.
type VolumeRequestBodyConfig struct {
	AllowCustomDrivers bool `mapstructure:"allow_custom_drivers"`
	AllowDriverOpts    bool `mapstructure:"allow_driver_opts"`
}

// NetworkRequestBodyConfig configures inspection for network write endpoints.
type NetworkRequestBodyConfig struct {
	AllowCustomDrivers     bool `mapstructure:"allow_custom_drivers"`
	AllowSwarmScope        bool `mapstructure:"allow_swarm_scope"`
	AllowIngress           bool `mapstructure:"allow_ingress"`
	AllowAttachable        bool `mapstructure:"allow_attachable"`
	AllowConfigOnly        bool `mapstructure:"allow_config_only"`
	AllowConfigFrom        bool `mapstructure:"allow_config_from"`
	AllowCustomIPAMDrivers bool `mapstructure:"allow_custom_ipam_drivers"`
	AllowCustomIPAMConfig  bool `mapstructure:"allow_custom_ipam_config"`
	AllowIPAMOptions       bool `mapstructure:"allow_ipam_options"`
	AllowDriverOptions     bool `mapstructure:"allow_driver_options"`
	AllowEndpointConfig    bool `mapstructure:"allow_endpoint_config"`
	AllowDisconnectForce   bool `mapstructure:"allow_disconnect_force"`
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

// SwarmRequestBodyConfig configures inspection for swarm writes.
type SwarmRequestBodyConfig struct {
	AllowForceNewCluster          bool     `mapstructure:"allow_force_new_cluster"`
	AllowExternalCA               bool     `mapstructure:"allow_external_ca"`
	AllowedJoinRemoteAddrs        []string `mapstructure:"allowed_join_remote_addrs"`
	AllowTokenRotation            bool     `mapstructure:"allow_token_rotation"`
	AllowManagerUnlockKeyRotation bool     `mapstructure:"allow_manager_unlock_key_rotation"`
	AllowAutoLockManagers         bool     `mapstructure:"allow_auto_lock_managers"`
	AllowSigningCAUpdate          bool     `mapstructure:"allow_signing_ca_update"`
	AllowUnlock                   bool     `mapstructure:"allow_unlock"`
}

// NodeRequestBodyConfig configures inspection for POST /nodes/*/update.
type NodeRequestBodyConfig struct {
	AllowNameChange         bool     `mapstructure:"allow_name_change"`
	AllowRoleChange         bool     `mapstructure:"allow_role_change"`
	AllowAvailabilityChange bool     `mapstructure:"allow_availability_change"`
	AllowLabelMutation      bool     `mapstructure:"allow_label_mutation"`
	AllowedLabelKeys        []string `mapstructure:"allowed_label_keys"`
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
	// GlobalConcurrency configures a system-wide priority-aware concurrency
	// gate shared across all profiles. Nil disables it.
	GlobalConcurrency *GlobalConcurrencyConfig `mapstructure:"global_concurrency"`
}

// GlobalConcurrencyConfig configures the system-wide concurrency cap that
// gates admission via per-profile priority shares (low=50%, normal=80%,
// high=100% of MaxInflight). Profiles below their priority's threshold are
// admitted; above it they receive 429 with reason `priority_floor`. The
// per-profile concurrency cap still applies on top of this gate.
type GlobalConcurrencyConfig struct {
	// MaxInflight is the system-wide ceiling on simultaneous in-flight
	// requests. Must be > 0.
	MaxInflight int64 `mapstructure:"max_inflight"`
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
	Profile             string   `mapstructure:"profile"`
	CommonNames         []string `mapstructure:"common_names"`
	DNSNames            []string `mapstructure:"dns_names"`
	IPAddresses         []string `mapstructure:"ip_addresses"`
	URISANs             []string `mapstructure:"uri_sans"`
	SPIFFEIDs           []string `mapstructure:"spiffe_ids"`
	PublicKeySHA256Pins []string `mapstructure:"public_key_sha256_pins"`
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
//
// Mode is the rollout posture for the profile's deny decisions. One of
// "enforce" (default), "warn", or "audit". See RolloutMode for semantics.
type ClientProfileConfig struct {
	Name        string                      `mapstructure:"name"`
	Mode        string                      `mapstructure:"mode"`
	Response    ClientProfileResponseConfig `mapstructure:"response"`
	RequestBody RequestBodyConfig           `mapstructure:"request_body"`
	Rules       []RuleConfig                `mapstructure:"rules"`
	Limits      LimitsConfig                `mapstructure:"limits"`
}

// LimitsConfig groups per-profile rate-limit and concurrency-cap settings.
// Both sub-blocks are optional; omitting both disables all limiting for the
// profile, preserving backward compatibility with pre-v0.7.0 configurations.
type LimitsConfig struct {
	// Rate configures token-bucket rate limiting. Omit to disable.
	Rate *RateLimitConfig `mapstructure:"rate"`
	// Concurrency configures the simultaneous-request cap. Omit to disable.
	Concurrency *ConcurrencyConfig `mapstructure:"concurrency"`
	// Priority is the profile's tier for the system-wide priority-aware
	// fairness gate (see clients.global_concurrency). One of "low", "normal",
	// or "high"; empty defaults to "normal". The field is honored only when
	// clients.global_concurrency is configured.
	Priority string `mapstructure:"priority"`
}

// RateLimitConfig configures a token-bucket rate limiter.
//
// TokensPerSecond is the continuous refill rate. Burst is the bucket capacity
// (maximum tokens that may accumulate). If Burst is zero it defaults to
// TokensPerSecond (smooth rate with no burst allowance). If Burst is less than
// TokensPerSecond after the zero-default replacement it is invalid — startup
// fails with a clear error.
//
// EndpointCosts optionally weights specific endpoints higher than the default
// 1 token per request. Use it to apply tighter budgets to expensive Docker
// operations such as build, image pull, and exec without lowering the base
// rate for every endpoint.
type RateLimitConfig struct {
	TokensPerSecond float64              `mapstructure:"tokens_per_second"`
	Burst           float64              `mapstructure:"burst"`
	EndpointCosts   []EndpointCostConfig `mapstructure:"endpoint_costs"`
}

// EndpointCostConfig assigns a per-request token cost to endpoints matching
// the given path glob (and optional HTTP method set).
//
// Path uses the same glob dialect as filter rules and is matched against the
// normalized request path (Docker API version prefix stripped). Methods is
// optional; an empty slice matches all methods. Cost must be >= 1 and may
// not exceed the effective burst capacity. First match in declaration order
// wins; unmatched requests cost 1 token.
type EndpointCostConfig struct {
	Path    string   `mapstructure:"path"`
	Methods []string `mapstructure:"methods"`
	Cost    float64  `mapstructure:"cost"`
}

// ConcurrencyConfig configures the per-client concurrent-request cap.
type ConcurrencyConfig struct {
	// MaxInflight is the maximum number of simultaneous in-flight requests
	// allowed for a single client. Must be > 0.
	MaxInflight int64 `mapstructure:"max_inflight"`
}

// ClientProfileResponseConfig configures per-profile visibility control on
// Docker read endpoints.
type ClientProfileResponseConfig struct {
	VisibleResourceLabels []string `mapstructure:"visible_resource_labels"`
	// NamePatterns is a per-profile glob pattern list matched against container
	// names and image short names. See ResponseConfig.NamePatterns.
	NamePatterns []string `mapstructure:"name_patterns"`
	// ImagePatterns is a per-profile glob pattern list matched against container
	// Image fields and image RepoTags. See ResponseConfig.ImagePatterns.
	ImagePatterns []string `mapstructure:"image_patterns"`
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
	Enabled  bool                 `mapstructure:"enabled"`
	Path     string               `mapstructure:"path"`
	Watchdog HealthWatchdogConfig `mapstructure:"watchdog"`
}

// HealthWatchdogConfig configures active upstream socket monitoring.
type HealthWatchdogConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Interval string `mapstructure:"interval"`
}

// MetricsConfig configures the Prometheus metrics endpoint.
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

// AdminConfig configures the admin HTTP endpoints (POST <path> for
// candidate-config validation, GET <policy_version_path> for the active
// policy generation counter).
//
// By default the admin endpoints ride the main listener and therefore
// inherit its CIDR allowlist, mTLS, and rate-limit posture. When Listen is
// configured (Listen.Socket OR Listen.Address set), sockguard starts a
// dedicated http.Server on that address that serves ONLY the admin
// endpoints. The main Docker-API listener never sees admin traffic in that
// mode, and admin traffic never sees the Docker-API filter chain. Operators
// running production traffic alongside an automation/CI control plane
// should prefer the dedicated listener so the two surfaces are isolated
// at the OS/socket layer.
//
// Enabled is opt-in because a misconfigured admin path on a
// network-reachable listener would otherwise let any client submit YAML for
// parsing.
type AdminConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	Path         string `mapstructure:"path"`
	MaxBodyBytes int64  `mapstructure:"max_body_bytes"`
	// PolicyVersionPath is the GET endpoint that reports the active policy
	// generation counter and metadata (rules / profiles / compat-active /
	// content hash). It shares the admin layer with Path, so it inherits the
	// listener CIDR allowlist, mTLS, and rate-limit posture. Default
	// /admin/policy/version. Must differ from Path, health.path, and
	// metrics.path when those endpoints are enabled.
	PolicyVersionPath string `mapstructure:"policy_version_path"`
	// Listen optionally moves the admin endpoints to a dedicated listener
	// instead of sharing the main proxy listener. Configure either Socket
	// (unix) or Address (TCP, optionally wrapped in TLS). When unset, the
	// admin endpoints continue to ride the main listener.
	Listen AdminListenConfig `mapstructure:"listen"`
}

// AdminListenConfig configures the dedicated admin listener. Its shape
// mirrors ListenConfig so operators have a single mental model for the
// two listeners; the behavioral differences are limited to defaults and
// the fact that the admin listener never carries Docker-API traffic.
//
// Configured reports whether a dedicated admin listener has been requested.
// When false the admin endpoints fall back to riding the main listener.
type AdminListenConfig struct {
	Socket                string          `mapstructure:"socket"`
	SocketMode            string          `mapstructure:"socket_mode"`
	Address               string          `mapstructure:"address"`
	InsecureAllowPlainTCP bool            `mapstructure:"insecure_allow_plain_tcp"`
	TLS                   ListenTLSConfig `mapstructure:"tls"`
}

// Configured reports whether an admin listener address has been requested.
// It is the single source of truth used by both validation and serve wiring
// to decide whether to spin up the dedicated admin http.Server.
func (cfg AdminListenConfig) Configured() bool {
	return cfg.Socket != "" || cfg.Address != ""
}

// ReloadConfig configures the hot-reload pipeline.
//
// When Enabled, sockguard watches the config file via fsnotify and reloads
// on SIGHUP. A reload that mutates any immutable field — listen.*,
// upstream.socket, log.*, health.*, metrics.*, admin.* — is rejected; the
// running config is preserved and the operator must restart sockguard to
// pick the new values up.
//
// DebounceMs collapses bursts of filesystem events (editors commonly emit
// chmod + write + rename + create per save) into a single reload trigger.
// Default 250ms.
//
// Reload is opt-in because enabling it changes the meaning of SIGHUP:
// historically SIGHUP terminated sockguard; with reload enabled, SIGHUP
// triggers a config reload and never terminates the process. Operators
// that script around the old behavior must update their tooling before
// flipping this on.
type ReloadConfig struct {
	Enabled    bool `mapstructure:"enabled"`
	DebounceMs int  `mapstructure:"debounce_ms"`
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
			ImageLoad: ImageLoadRequestBodyConfig{
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
			Watchdog: HealthWatchdogConfig{
				Enabled:  false,
				Interval: "5s",
			},
		},
		Metrics: MetricsConfig{
			Enabled: false,
			Path:    "/metrics",
		},
		Admin: AdminConfig{
			Enabled:           false,
			Path:              "/admin/validate",
			MaxBodyBytes:      524288,
			PolicyVersionPath: "/admin/policy/version",
			Listen: AdminListenConfig{
				// Socket and Address both default to "" so the admin endpoints
				// ride the main listener until the operator opts in. SocketMode
				// still defaults to the hardened mode so that an operator who
				// only sets admin.listen.socket gets owner-only permissions
				// without needing to repeat the boilerplate.
				SocketMode: HardenedListenSocketMode,
			},
		},
		Reload: ReloadConfig{
			Enabled:    false,
			DebounceMs: 250,
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
