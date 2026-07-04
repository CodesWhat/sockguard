package config

import "os"

// HardenedListenSocketMode is the only supported unix-socket permission mode
// (string form, as it appears in YAML).
const HardenedListenSocketMode = "0600"

// HardenedListenSocketFileMode is the os.FileMode equivalent of
// HardenedListenSocketMode, exported so listener creation paths derive the
// umask from a single source of truth.
const HardenedListenSocketFileMode = os.FileMode(0o600)

// Config represents the sockguard configuration.
type Config struct {
	Listen                        ListenConfig       `mapstructure:"listen"`
	Upstream                      UpstreamConfig     `mapstructure:"upstream"`
	Log                           LogConfig          `mapstructure:"log"`
	Response                      ResponseConfig     `mapstructure:"response"`
	RequestBody                   RequestBodyConfig  `mapstructure:"request_body"`
	Clients                       ClientsConfig      `mapstructure:"clients"`
	Ownership                     OwnershipConfig    `mapstructure:"ownership"`
	Health                        HealthConfig       `mapstructure:"health"`
	Metrics                       MetricsConfig      `mapstructure:"metrics"`
	Admin                         AdminConfig        `mapstructure:"admin"`
	Reload                        ReloadConfig       `mapstructure:"reload"`
	PolicyBundle                  PolicyBundleConfig `mapstructure:"policy_bundle"`
	Rules                         []RuleConfig       `mapstructure:"rules"`
	InsecureAllowBodyBlindWrites  bool               `mapstructure:"insecure_allow_body_blind_writes"`
	InsecureAllowReadExfiltration bool               `mapstructure:"insecure_allow_read_exfiltration"`
}

// ListenConfig configures the proxy listener.
type ListenConfig struct {
	Socket     string `mapstructure:"socket"`
	SocketMode string `mapstructure:"socket_mode"`
	Address    string `mapstructure:"address"`
	// InsecureAllowPlainTCP opts a non-loopback TCP listener into unencrypted
	// transport. A non-loopback plaintext listener requires this AND
	// InsecureAllowUnauthenticatedClients — two deliberate acknowledgments so
	// the dangerous mode cannot be reached by a single fat-fingered flag.
	InsecureAllowPlainTCP bool `mapstructure:"insecure_allow_plain_tcp"`
	// InsecureAllowUnauthenticatedClients is the second acknowledgment a
	// non-loopback plaintext listener requires: without mutual TLS any host
	// that can reach the port can impersonate a client.
	InsecureAllowUnauthenticatedClients bool            `mapstructure:"insecure_allow_unauthenticated_clients"`
	TLS                                 ListenTLSConfig `mapstructure:"tls"`
}

// ListenTLSConfig configures mutual TLS for TCP listeners.
type ListenTLSConfig struct {
	CertFile            string   `mapstructure:"cert_file"`
	KeyFile             string   `mapstructure:"key_file"`
	ClientCAFile        string   `mapstructure:"client_ca_file"`
	CommonNames         []string `mapstructure:"common_names"`
	DNSNames            []string `mapstructure:"dns_names"`
	IPAddresses         []string `mapstructure:"ip_addresses"`
	URISANs             []string `mapstructure:"uri_sans"`
	PublicKeySHA256Pins []string `mapstructure:"public_key_sha256_pins"`
}

// UpstreamConfig configures the upstream Docker daemon(s) sockguard proxies to.
//
// The legacy single-daemon shorthand is upstream.socket (a local unix socket).
// upstream.endpoints adds an ordered list of remote (TCP+TLS) or local daemons
// for the SAME logical daemon/swarm, health-checked with automatic failover to
// the first reachable endpoint. When endpoints is empty, socket is used. When
// endpoints is non-empty, it takes precedence and socket is ignored.
type UpstreamConfig struct {
	Socket string `mapstructure:"socket"`
	// RequestTimeout bounds the total lifetime of a single proxied upstream
	// request as a Go duration string (e.g. "30s"). ResponseHeaderTimeout only
	// caps the wait for response headers; a daemon that sends headers and then
	// hangs the body can still pin a request indefinitely. A non-disabled value
	// converts that hang into a fast 504 for ordinary finite requests.
	// Long-lived endpoints (/events, log/stats streams, image pull/build/push,
	// container export/get, container archive i.e. docker cp, and the blocking
	// /containers/{id}/wait) are exempt so the deadline never severs a
	// legitimately long response.
	//
	// Default is "60s" (changed from unlimited default prior to v1.5). Set
	// "off" to explicitly disable the deadline; the legacy empty string ("")
	// remains valid for backward compatibility with configs written before
	// "off" existed. Use RequestTimeoutDisabled to check either spelling — it
	// is the single source of truth validate.go and cmd/serve.go both consult.
	// Any other value must parse as a positive Go duration; 0 and negative
	// durations are validation errors.
	//
	// Caveat: SOCKGUARD_UPSTREAM_REQUEST_TIMEOUT="" (an explicitly empty env
	// var) is treated as UNSET by Viper and falls through to the "60s"
	// default rather than disabling it — only the literal "off" reliably
	// disables the deadline via environment variable. An explicit
	// request_timeout: "" in YAML does correctly disable it, since YAML
	// values bypass Viper's env-emptiness gate. Prefer "off" in both
	// channels.
	RequestTimeout string `mapstructure:"request_timeout"`
	// Endpoints is an ordered failover set. The first entry is the preferred
	// primary; later entries are tried when earlier ones fail their health
	// probe. Every endpoint MUST address the same logical daemon/swarm —
	// container IDs, exec sessions, and owner labels are daemon-local, so
	// failover only makes sense across redundant endpoints (a swarm VIP plus
	// its managers, an HA pair behind keepalived), not distinct daemons.
	Endpoints []UpstreamEndpoint `mapstructure:"endpoints"`
	// Failover tunes the active health-probe loop that drives endpoint
	// selection. Ignored unless endpoints is set.
	Failover UpstreamFailover `mapstructure:"failover"`
}

// RequestTimeoutDisabled reports whether the per-request upstream deadline is
// explicitly disabled: the canonical "off" sentinel or the legacy empty
// string, both of which mean "no deadline". Centralizing the check here
// means validate.go and cmd/serve.go read the same definition of "disabled"
// and cannot drift on it. Comparison is exact-case, matching the existing
// enum style elsewhere in config (log.level, response.deny_verbosity) — "OFF"
// or "Off" is not recognized and falls through to duration parsing, where it
// fails validation.
func (u UpstreamConfig) RequestTimeoutDisabled() bool {
	return u.RequestTimeout == "" || u.RequestTimeout == "off"
}

// UpstreamEndpoint is one daemon in an ordered failover set.
type UpstreamEndpoint struct {
	// Address is a Docker-style upstream address: a unix socket
	// ("unix:///var/run/docker.sock" or a bare path) or a remote daemon
	// ("tcp://host:2376").
	Address string `mapstructure:"address"`
	// TLS configures the client certificate, key, and CA used to dial a remote
	// daemon over TLS. Required for tcp:// endpoints unless an insecure opt-in
	// below is set. Meaningless for unix sockets.
	TLS UpstreamTLSConfig `mapstructure:"tls"`
	// InsecureAllowPlainTCP permits a tcp:// endpoint with no TLS material,
	// exposing the Docker API in plaintext to anyone on the path. Mirrors the
	// listener-side insecure_allow_plain_tcp acknowledgement.
	InsecureAllowPlainTCP bool `mapstructure:"insecure_allow_plain_tcp"`
	// InsecureSkipTLSVerify disables verification of the remote daemon's server
	// certificate (self-signed homelab daemons). Dangerous in production: it
	// defeats authentication of the upstream.
	InsecureSkipTLSVerify bool `mapstructure:"insecure_skip_tls_verify"`
}

// UpstreamTLSConfig is the client-side TLS material for dialing a remote daemon.
type UpstreamTLSConfig struct {
	// CAFile verifies the remote daemon's server certificate. Empty uses the
	// system roots.
	CAFile string `mapstructure:"ca_file"`
	// CertFile and KeyFile present a client certificate to the daemon (mutual
	// TLS). Both set together or both empty.
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	// ServerName overrides the SNI / verified hostname. Empty derives it from
	// the address host.
	ServerName string `mapstructure:"server_name"`
}

// UpstreamFailover tunes the endpoint health-probe loop.
type UpstreamFailover struct {
	// HealthInterval is the active probe period (Go duration, e.g. "5s"). Empty
	// uses the resolver default. A negative duration disables continuous
	// probing (a single startup probe still runs).
	HealthInterval string `mapstructure:"health_interval"`
	// HealthTimeout bounds each probe (Go duration, e.g. "2s"). Empty uses the
	// resolver default.
	HealthTimeout string `mapstructure:"health_timeout"`
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
	AllowPrivileged          bool                   `mapstructure:"allow_privileged"`
	AllowHostNetwork         bool                   `mapstructure:"allow_host_network"`
	AllowHostPID             bool                   `mapstructure:"allow_host_pid"`
	AllowHostIPC             bool                   `mapstructure:"allow_host_ipc"`
	AllowedBindMounts        []string               `mapstructure:"allowed_bind_mounts"`
	AllowAllDevices          bool                   `mapstructure:"allow_all_devices"`
	AllowedDevices           []string               `mapstructure:"allowed_devices"`
	AllowDeviceRequests      bool                   `mapstructure:"allow_device_requests"`
	AllowedDeviceRequests    []AllowedDeviceRequest `mapstructure:"allowed_device_requests"`
	AllowDeviceCgroupRules   bool                   `mapstructure:"allow_device_cgroup_rules"`
	AllowedDeviceCgroupRules []string               `mapstructure:"allowed_device_cgroup_rules"`

	RequireNoNewPrivileges     bool             `mapstructure:"require_no_new_privileges"`
	RequireNonRootUser         bool             `mapstructure:"require_non_root_user"`
	RequireReadonlyRootfs      bool             `mapstructure:"require_readonly_rootfs"`
	RequireDropAllCapabilities bool             `mapstructure:"require_drop_all_capabilities"`
	AllowAllCapabilities       bool             `mapstructure:"allow_all_capabilities"`
	AllowedCapabilities        []string         `mapstructure:"allowed_capabilities"`
	RequireMemoryLimit         bool             `mapstructure:"require_memory_limit"`
	RequireCPULimit            bool             `mapstructure:"require_cpu_limit"`
	RequirePidsLimit           bool             `mapstructure:"require_pids_limit"`
	AllowedSeccompProfiles     []string         `mapstructure:"allowed_seccomp_profiles"`
	DenyUnconfinedSeccomp      bool             `mapstructure:"deny_unconfined_seccomp"`
	AllowedAppArmorProfiles    []string         `mapstructure:"allowed_apparmor_profiles"`
	DenyUnconfinedAppArmor     bool             `mapstructure:"deny_unconfined_apparmor"`
	AllowHostUserNS            bool             `mapstructure:"allow_host_userns"`
	AllowSysctls               bool             `mapstructure:"allow_sysctls"`
	RequiredLabels             []string         `mapstructure:"required_labels"`
	AllowedRuntimes            []string         `mapstructure:"allowed_runtimes"`
	ImageTrust                 ImageTrustConfig `mapstructure:"image_trust"`
	DenySelinuxDisable         bool             `mapstructure:"deny_selinux_disable"`
	DenySelinuxLabelOverride   bool             `mapstructure:"deny_selinux_label_override"`
	DenyUnconfinedSystemPaths  bool             `mapstructure:"deny_unconfined_system_paths"`
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
	AllowAllDevices      bool `mapstructure:"allow_all_devices"`
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
	AllowHostNetwork           bool     `mapstructure:"allow_host_network"`
	AllowedBindMounts          []string `mapstructure:"allowed_bind_mounts"`
	AllowAllRegistries         bool     `mapstructure:"allow_all_registries"`
	AllowOfficial              bool     `mapstructure:"allow_official"`
	AllowedRegistries          []string `mapstructure:"allowed_registries"`
	AllowAllCapabilities       bool     `mapstructure:"allow_all_capabilities"`
	AllowedCapabilities        []string `mapstructure:"allowed_capabilities"`
	AllowSysctls               bool     `mapstructure:"allow_sysctls"`
	RequireNonRootUser         bool     `mapstructure:"require_non_root_user"`
	RequireNoNewPrivileges     bool     `mapstructure:"require_no_new_privileges"`
	RequireReadonlyRootfs      bool     `mapstructure:"require_readonly_rootfs"`
	RequireDropAllCapabilities bool     `mapstructure:"require_drop_all_capabilities"`
	// DenyUnconfinedSeccomp denies service create/update when
	// ContainerSpec.Privileges.Seccomp.Mode is "unconfined". Default false (opt-in).
	DenyUnconfinedSeccomp bool `mapstructure:"deny_unconfined_seccomp"`
	// DenyCustomSeccompProfiles denies service create/update when
	// ContainerSpec.Privileges.Seccomp.Mode is "custom". A "custom" profile can
	// encode an allow-everything policy equivalent to "unconfined"; enable this
	// alongside deny_unconfined_seccomp for full seccomp confinement enforcement.
	// Default false (opt-in).
	DenyCustomSeccompProfiles bool `mapstructure:"deny_custom_seccomp_profiles"`
	// DenyUnconfinedAppArmor denies service create/update when
	// ContainerSpec.Privileges.AppArmor.Mode is "disabled" (the swarm equivalent
	// of "unconfined" AppArmor). Default false (opt-in).
	DenyUnconfinedAppArmor bool `mapstructure:"deny_unconfined_apparmor"`
	// DenySelinuxDisable denies service create/update when
	// ContainerSpec.Privileges.SELinuxContext.Disable is true — the swarm
	// equivalent of the container-create deny_selinux_disable. Default false (opt-in).
	DenySelinuxDisable bool `mapstructure:"deny_selinux_disable"`
	// DenySelinuxLabelOverride denies service create/update that customizes the
	// SELinux context via ContainerSpec.Privileges.SELinuxContext.{User,Role,Type,
	// Level} — the swarm equivalent of container-create deny_selinux_label_override.
	// Default false (opt-in).
	DenySelinuxLabelOverride bool             `mapstructure:"deny_selinux_label_override"`
	ImageTrust               ImageTrustConfig `mapstructure:"image_trust"`
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
	AllowHostIPC          bool     `mapstructure:"allow_host_ipc"`
	AllowHostPID          bool     `mapstructure:"allow_host_pid"`
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
	Enabled   bool                  `mapstructure:"enabled"`
	Path      string                `mapstructure:"path"`
	Watchdog  HealthWatchdogConfig  `mapstructure:"watchdog"`
	Readiness HealthReadinessConfig `mapstructure:"readiness"`
}

// HealthWatchdogConfig configures active upstream socket monitoring.
type HealthWatchdogConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Interval string `mapstructure:"interval"`
}

// HealthReadinessConfig configures the optional readiness endpoint. Unlike the
// watchdog (which dials the upstream socket — a liveness signal), readiness
// issues a real GET /containers/json against the upstream Docker API, so a
// daemon that accepts connections but no longer answers the API is reported
// unready. Disabled by default; the whole health.* block is reload-immutable.
type HealthReadinessConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Path     string `mapstructure:"path"`
	Interval string `mapstructure:"interval"`
	Timeout  string `mapstructure:"timeout"`
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
	Enabled         bool   `mapstructure:"enabled"`
	Path            string `mapstructure:"path"`
	MaxRequestBytes int64  `mapstructure:"max_request_bytes"`
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

// AdminListenConfig configures the dedicated admin listener. It embeds
// ListenConfig so operators have a single mental model for the two
// listeners; the behavioral differences are limited to defaults and
// the fact that the admin listener never carries Docker-API traffic.
//
// Configured reports whether a dedicated admin listener has been requested.
// When false the admin endpoints fall back to riding the main listener.
type AdminListenConfig struct {
	ListenConfig `mapstructure:",squash"`
	// InsecureAllowWideOpen is the third acknowledgment a wide-open admin
	// listener requires. The embedded insecure_allow_plain_tcp /
	// insecure_allow_unauthenticated_clients flags opt a non-loopback TCP
	// admin listener out of TLS, but unlike the main listener — where
	// unauthenticated requests still face the full policy filter chain — the
	// admin endpoints accept candidate YAML and expose policy metadata with
	// client CIDRs as their ONLY admission control. A non-loopback plaintext
	// admin listener with no clients.allowed_cidrs is therefore a validation
	// error unless this flag explicitly accepts that exposure.
	InsecureAllowWideOpen bool `mapstructure:"insecure_allow_wide_open"`
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
// upstream.socket, upstream.endpoints, upstream.failover, log.*, health.*,
// metrics.*, admin.* — is rejected; the running config is preserved and the
// operator must restart sockguard to pick the new values up. (upstream.endpoints
// and upstream.failover are pinned because the long-lived Resolver and its
// health loop are built once at startup; upstream.request_timeout stays mutable.)
//
// Debounce collapses bursts of filesystem events (editors commonly emit
// chmod + write + rename + create per save) into a single reload trigger.
// Default "250ms".
//
// Reload is opt-in because enabling it changes the meaning of SIGHUP:
// historically SIGHUP terminated sockguard; with reload enabled, SIGHUP
// triggers a config reload and never terminates the process. Operators
// that script around the old behavior must update their tooling before
// flipping this on.
type ReloadConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Debounce string `mapstructure:"debounce"`
	// PollInterval is an optional fallback that periodically stats the
	// config file and triggers a reload when its size, modification time, or
	// inode has changed since the last check. Useful on filesystems where
	// fsnotify is unreliable (Synology / DSM btrfs bind-mounts, some FUSE
	// backends, NFS) — inotify events on the host don't always propagate
	// into the container, so a SIGHUP or this poll is the only way the
	// watcher learns the file moved. Empty string disables polling (default);
	// typical values are "5s"–"15s". SIGHUP remains the canonical reload
	// trigger for unreliable propagation backends.
	PollInterval string `mapstructure:"poll_interval"`
}

// PolicyBundleConfig configures verification of signed policy bundles.
//
// When Enabled, sockguard reads the YAML config file bytes and the sigstore
// bundle JSON at SignaturePath, then asks the policybundle verifier to
// confirm the bundle signs the YAML's sha256 digest under one of the
// configured trust paths (AllowedSigningKeys or AllowedKeyless). Both
// startup load and SIGHUP / fsnotify-driven reloads consult the verifier;
// an unsigned or invalid bundle fails startup and rejects reloads with the
// reject_signature metrics reason. The verified signer fingerprint or
// identity is published on GET /admin/policy/version so operators can
// confirm exactly who vouched for the running policy.
//
// SignaturePath is reload-mutable so an operator can re-sign without
// rotating the YAML; the other fields (enable / trust material / Rekor
// requirement / timeout) are reload-immutable for the same reasons as the
// listener / TLS material: changing the trust root mid-reload would
// silently expand the set of accepted signers.
type PolicyBundleConfig struct {
	Enabled               bool                     `mapstructure:"enabled"`
	SignaturePath         string                   `mapstructure:"signature_path"`
	AllowedSigningKeys    []PolicyBundleSigningKey `mapstructure:"allowed_signing_keys"`
	AllowedKeyless        []PolicyBundleKeyless    `mapstructure:"allowed_keyless"`
	RequireRekorInclusion bool                     `mapstructure:"require_rekor_inclusion"`
	VerifyTimeout         string                   `mapstructure:"verify_timeout"`
}

// PolicyBundleSigningKey is one entry in policy_bundle.allowed_signing_keys.
type PolicyBundleSigningKey struct {
	// PEM is the PEM-encoded public key (ECDSA, RSA, or ed25519).
	PEM string `mapstructure:"pem"`
}

// PolicyBundleKeyless is one entry in policy_bundle.allowed_keyless.
type PolicyBundleKeyless struct {
	// Issuer is the exact OIDC issuer URL to match against the Fulcio cert.
	Issuer string `mapstructure:"issuer"`
	// SubjectPattern is a Go regexp matched against the cert's SAN.
	SubjectPattern string `mapstructure:"subject_pattern"`
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
// or explicitly opt into legacy plaintext mode with both
// listen.insecure_allow_plain_tcp=true and
// listen.insecure_allow_unauthenticated_clients=true.
func Defaults() Config {
	return Config{
		Listen: ListenConfig{
			Address:    "127.0.0.1:2375",
			SocketMode: HardenedListenSocketMode, // used only when the user opts into a unix socket listener
		},
		Upstream: UpstreamConfig{
			Socket: "/var/run/docker.sock",
			// 60s bounds a hung upstream body or heavy read by default; set
			// "off" (or the legacy "") to disable. See RequestTimeout's doc
			// comment for the full migration story.
			RequestTimeout: "60s",
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
			// Image trust defaults to requiring a Rekor inclusion proof for
			// keyless signatures (matching policy_bundle), so old/revoked
			// signatures cannot be replayed without a transparency-log entry.
			// Operators must opt out explicitly.
			ContainerCreate: ContainerCreateRequestBodyConfig{
				ImageTrust: ImageTrustConfig{RequireRekorInclusion: true},
			},
			ImagePull: ImagePullRequestBodyConfig{
				AllowOfficial: true,
			},
			ImageLoad: ImageLoadRequestBodyConfig{
				AllowOfficial: true,
			},
			Service: ServiceRequestBodyConfig{
				AllowOfficial: true,
				ImageTrust:    ImageTrustConfig{RequireRekorInclusion: true},
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
			Readiness: HealthReadinessConfig{
				Enabled:  false,
				Path:     "/ready",
				Interval: "10s",
				Timeout:  "5s",
			},
		},
		Metrics: MetricsConfig{
			Enabled: false,
			Path:    "/metrics",
		},
		Admin: AdminConfig{
			Enabled:           false,
			Path:              "/admin/validate",
			MaxRequestBytes:   524288,
			PolicyVersionPath: "/admin/policy/version",
			Listen: AdminListenConfig{
				ListenConfig: ListenConfig{
					// Socket and Address both default to "" so the admin endpoints
					// ride the main listener until the operator opts in. SocketMode
					// still defaults to the hardened mode so that an operator who
					// only sets admin.listen.socket gets owner-only permissions
					// without needing to repeat the boilerplate.
					SocketMode: HardenedListenSocketMode,
				},
			},
		},
		Reload: ReloadConfig{
			Enabled:      false,
			Debounce:     "250ms",
			PollInterval: "",
		},
		PolicyBundle: PolicyBundleConfig{
			Enabled:               false,
			RequireRekorInclusion: true,
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
