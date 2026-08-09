package config

import (
	"os"
	"regexp"
)

// HardenedListenSocketMode is the only supported unix-socket permission mode
// (string form, as it appears in YAML).
const HardenedListenSocketMode = "0600"

// HardenedListenSocketFileMode is the os.FileMode equivalent of
// HardenedListenSocketMode, exported so listener creation paths derive the
// umask from a single source of truth.
const HardenedListenSocketFileMode = os.FileMode(0o600)

// GroupReadableListenSocketMode is the second (and only other) unix-socket
// permission mode a listener may opt into, in addition to
// HardenedListenSocketMode. It requires an explicit SocketGID — see
// validateSocketOwnership — so a group-shared socket is always an
// affirmative, per-listener operator choice rather than a default.
const GroupReadableListenSocketMode = "0660"

// GroupReadableListenSocketFileMode is the os.FileMode equivalent of
// GroupReadableListenSocketMode.
const GroupReadableListenSocketFileMode = os.FileMode(0o660)

// Multi-listener (#149) naming/scoping constants.
const (
	// DefaultListenerName is the synthetic name given to the legacy
	// Config.Listen block when EffectiveListeners synthesizes it into a
	// single-entry list.
	DefaultListenerName = "default"
	// AdminListenerName is reserved: no entry in Config.Listeners may use
	// this name, so Admin.MountOn's namespace (main listener names) can
	// never collide with the dedicated admin listener.
	AdminListenerName = "admin"
	// WildcardProfile, as the sole element of a ListenerConfig's
	// AllowedProfiles, preserves the legacy "every profile admitted"
	// behavior. It cannot be combined with concrete profile names and is a
	// reserved profile name (clients.profiles entries may not use it).
	WildcardProfile = "*"
	// MaxListeners bounds Config.Listeners: a small, operator-authored cap
	// that keeps validation's all-pairs uniqueness check, metrics
	// cardinality, and log/health fan-out proportionate.
	MaxListeners = 32
)

// ListenerNamePattern is the validation regex for ListenerConfig.Name:
// lowercase alphanumeric plus hyphen, starting with a letter, up to 63
// characters — safe to use unescaped as a Prometheus label value, a log
// field, and a reload-diff key.
var listenerNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// ValidListenerName reports whether name matches ListenerNamePattern.
func ValidListenerName(name string) bool {
	return listenerNamePattern.MatchString(name)
}

// EffectiveListeners is the single read path every downstream consumer
// (validation, serve wiring, reload diff, banner, metrics, audit) must use
// instead of reading Config.Listen or Config.Listeners directly. When
// Listeners is empty it synthesizes the legacy Listen block into a
// single-entry list named DefaultListenerName with AllowedProfiles
// [WildcardProfile] — byte-for-byte equivalent to today's global behavior —
// so every config that sets only listen: continues to behave identically.
func (c *Config) EffectiveListeners() []ListenerConfig {
	if len(c.Listeners) > 0 {
		return c.Listeners
	}
	return []ListenerConfig{{
		Name:            DefaultListenerName,
		ListenConfig:    c.Listen,
		AllowedProfiles: []string{WildcardProfile},
	}}
}

// Wildcard reports whether l's AllowedProfiles is exactly [WildcardProfile],
// i.e. this listener admits every resolved profile (and the unprofiled
// default-policy path), matching legacy single-listener behavior.
func (l ListenerConfig) Wildcard() bool {
	return len(l.AllowedProfiles) == 1 && l.AllowedProfiles[0] == WildcardProfile
}

// Config represents the sockguard configuration.
type Config struct {
	Listen                        ListenConfig       `mapstructure:"listen"`
	Listeners                     []ListenerConfig   `mapstructure:"listeners"`
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
	Mutations                     MutationsConfig    `mapstructure:"mutations"`
	Rules                         []RuleConfig       `mapstructure:"rules"`
	InsecureAllowBodyBlindWrites  bool               `mapstructure:"insecure_allow_body_blind_writes"`
	InsecureAllowReadExfiltration bool               `mapstructure:"insecure_allow_read_exfiltration"`

	// explicitLegacyListen records whether the legacy listen.* fields were
	// set explicitly — a YAML key, a SOCKGUARD_LISTEN_* environment
	// variable, or the --listen-socket CLI flag — as opposed to left at
	// their zero/default value. It is populated by Load/LoadBytes (via a
	// provenance-only Viper pass) and by applyFlagOverrides in
	// internal/cmd, and consulted by validateListeners to detect the
	// "both listen and listeners configured" ambiguity (#149). Unexported
	// so it never round-trips through mapstructure/YAML/JSON; a Config
	// built directly (most tests) simply reads as "not explicit", which
	// only matters once Listeners is also non-empty.
	explicitLegacyListen bool

	// explicitNetworkEndpointConfig records whether
	// request_body.network.endpoint_config was set explicitly — a YAML key
	// or a matching SOCKGUARD_REQUEST_BODY_NETWORK_ENDPOINT_CONFIG_*
	// environment variable — as opposed to left at its defaulted value
	// (EndpointConfigRequestBodyConfig.AllowAliases defaults to true, so the
	// merged struct is never the Go zero value even when the operator never
	// wrote the block — see EndpointConfigRequestBodyConfig's doc comment).
	// Populated by Load/LoadBytes via a provenance-only Viper pass mirroring
	// explicitLegacyListen, and consulted by validateNetworkEndpointConfig
	// to reject request_body.network.allow_endpoint_config: true combined
	// with an explicit endpoint_config block (#186). Unexported so it never
	// round-trips through mapstructure/YAML/JSON.
	explicitNetworkEndpointConfig bool

	// InsecureAcceptOpaqueBuildkitTunnels acknowledges opening POST /session,
	// POST /grpc, or a direct BuildKit Control-service method path. Both
	// endpoints are unversioned opaque hijacked streams: dockerd's embedded
	// BuildKit frontend/session bridge, still used by current Buildx (0.36.0)
	// even though Engine API 1.53 deprecated them. Unlike the bounded exec
	// escape hatch InsecureAllowBodyBlindWrites covers, these streams carry
	// secrets, SSH agent forwarding, and arbitrary file sync with no request
	// body sockguard can inspect or bound — so they get their own dedicated
	// acknowledgment rather than folding into insecure_allow_body_blind_writes.
	// Default false: a rule admitting either endpoint fails startup unless this
	// is set. Tecnativa GRPC=1/SESSION=1 compat vars still work (see
	// ApplyCompat) but log a deprecation warning naming this key. A single
	// global setting, not per-profile — see cmd/rules.go.
	InsecureAcceptOpaqueBuildkitTunnels bool `mapstructure:"insecure_accept_opaque_buildkit_tunnels"`
}

// MarkLegacyListenExplicit records that the legacy listen.* block was set
// through a channel Load's provenance pass cannot see — currently the
// --listen-socket CLI flag, which is applied to an already-loaded Config in
// internal/cmd. Safe to call unconditionally; it only ever turns the flag on.
func (c *Config) MarkLegacyListenExplicit() {
	c.explicitLegacyListen = true
}

// ExplicitLegacyListen reports whether the legacy listen.* block was set
// explicitly, for tests and validation.
func (c *Config) ExplicitLegacyListen() bool {
	return c.explicitLegacyListen
}

// ExplicitNetworkEndpointConfig reports whether
// request_body.network.endpoint_config was set explicitly, for tests and
// validation (#186's allow_endpoint_config/endpoint_config mutual-exclusion
// check — see validateNetworkEndpointConfig).
func (c *Config) ExplicitNetworkEndpointConfig() bool {
	return c.explicitNetworkEndpointConfig
}

// ListenConfig configures a single proxy listener (unix socket or TCP).
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
	// SocketUID and SocketGID optionally chown a freshly created unix socket
	// after bind. Pointers distinguish "omitted" from UID/GID 0. Only
	// meaningful when Socket is set. Combined with SocketMode they gate the
	// 0600 (default, no explicit ownership required) vs 0660 (requires
	// SocketGID) posture — see validateSocketOwnership.
	SocketUID *int `mapstructure:"socket_uid"`
	SocketGID *int `mapstructure:"socket_gid"`
}

// ListenerConfig is one entry in Config.Listeners: a named, independently
// scoped main (Docker-API) listener. See Config.EffectiveListeners.
type ListenerConfig struct {
	// Name identifies the listener for logs, metrics, health, audit, and
	// reload diagnostics. Must match ListenerNamePattern, be unique within
	// Listeners, and must not be AdminListenerName ("admin").
	Name         string `mapstructure:"name"`
	ListenConfig `mapstructure:",squash"`
	// AllowedProfiles scopes this listener to a subset of clients.profiles.
	// Required and non-empty on every explicit entry. The single-element
	// list [WildcardProfile] ("*") preserves the legacy global behavior:
	// every resolved profile, plus the unprofiled/default-policy path, is
	// admitted. A concrete list is an admission gate evaluated AFTER normal
	// profile resolution (certificate > unix peer > source IP > default):
	// an otherwise-valid client resolved to a profile outside this list is
	// denied with reason listener_profile_not_allowed, never retried
	// against a weaker selector.
	AllowedProfiles []string `mapstructure:"allowed_profiles"`
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
	// RedactHostTopology redacts GET /info fields that fingerprint the host's
	// container runtime plumbing: Containerd, FirewallBackend,
	// DiscoveredDevices, and NRI. Separate from RedactNetworkTopology (which
	// covers swarm/network addressing) — this is host-process/device topology.
	// Default false; hardened presets enable it.
	RedactHostTopology bool `mapstructure:"redact_host_topology"`
	// AllowAttestationStatements permits GET /images/{name}/attestations
	// responses that include the full in-toto statement content
	// (?statement=true). Engine API 1.53 added this endpoint; broad allow
	// rules such as "/images/**" (portainer.yaml) admit it at the rule-engine
	// layer without knowing it exists, so this response-layer gate closes
	// that gap independent of the rule set. Default false.
	AllowAttestationStatements bool `mapstructure:"allow_attestation_statements"`
}

// RequestBodyConfig configures request-body inspection policies.
type RequestBodyConfig struct {
	ContainerCreate       ContainerCreateRequestBodyConfig       `mapstructure:"container_create"`
	LibpodContainerCreate LibpodContainerCreateRequestBodyConfig `mapstructure:"libpod_container_create"`
	// Exec configures body inspection for BOTH the Docker-compat exec
	// create/start endpoints AND their libpod equivalents
	// (POST /libpod/containers/*/exec, POST /libpod/exec/*/start). There is
	// deliberately no separate libpod_exec block: libpod exec bodies are
	// decoded by the identical Go handler Docker-compat exec bodies are
	// (confirmed against Podman's own route table, see exec.go), so a split
	// config would just be a configure-one-forget-other trap (#148 design
	// doc, decision C3).
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
	// Buildkit configures the (currently deny-only — see issue #185 phase 1)
	// BuildKit gRPC mediation policy for POST /session and POST /grpc. An
	// absent block denies both endpoints internally even when an outer HTTP
	// rule allows them — there is no separate enabled toggle to drift out of
	// sync with the sub-blocks below. See BuildkitRequestBodyConfig's doc
	// comment for the full posture and validateBuildkitAckMutualExclusion in
	// validate.go for its interaction with InsecureAcceptOpaqueBuildkitTunnels.
	Buildkit BuildkitRequestBodyConfig `mapstructure:"buildkit"`
	// LibpodPodCreate configures body inspection for POST /libpod/pods/create
	// (Podman's native pod-create endpoint; pods have no Docker-compat
	// equivalent, so this is its own top-level key rather than reusing
	// container_create). #148.
	LibpodPodCreate LibpodPodCreateRequestBodyConfig `mapstructure:"libpod_pod_create"`
	// LibpodVolume, LibpodNetwork, and LibpodSecret configure body/query
	// inspection for the libpod-native volume/network/secret create
	// endpoints (POST /libpod/volumes/create, /libpod/networks/create,
	// /libpod/secrets/create). They reuse the EXISTING
	// Volume/Network/SecretRequestBodyConfig types — libpod's wire shapes
	// for these resources differ from Docker's (see libpod_volume.go,
	// libpod_network.go, libpod_secret.go for the decode structs and which
	// fields have no libpod analog), but the policy knobs an operator
	// reasons about are the same, so a second parallel type would only add
	// schema noise. #148.
	LibpodVolume  VolumeRequestBodyConfig  `mapstructure:"libpod_volume"`
	LibpodNetwork NetworkRequestBodyConfig `mapstructure:"libpod_network"`
	LibpodSecret  SecretRequestBodyConfig  `mapstructure:"libpod_secret"`
}

// LibpodPodCreateRequestBodyConfig configures body inspection for
// POST /libpod/pods/create. Cross-owner namespace-sharing checks and label
// injection for ownership are deferred to a follow-up PR (#148 design doc
// C6) — this config only covers the raw request-body gates below.
type LibpodPodCreateRequestBodyConfig struct {
	// AllowHostNetwork permits a pod-level NetNS of {"nsmode":"host"} — the
	// pod (and every container that joins it) shares the host network
	// namespace. Mirrors container_create.allow_host_network's posture for
	// the pod-wide equivalent. Default false.
	AllowHostNetwork bool `mapstructure:"allow_host_network"`
	// AllowSharedPIDNamespace permits "pid" in the pod's shared_namespaces
	// list, letting every container in the pod see (and signal) every other
	// container's processes — the pod-wide analog of container_create's
	// PidMode: host, scoped to the pod rather than the host. Default false.
	AllowSharedPIDNamespace bool `mapstructure:"allow_shared_pid_namespace"`
	// AllowedInfraImageRegistries allowlists the registry the pod's
	// infra_image reference resolves to, reusing the same host-allowlist
	// shape as image_pull.allowed_registries. An empty infra_image (Podman's
	// built-in default pause image) is always allowed regardless of this
	// list. Default empty: any explicit infra_image is denied.
	AllowedInfraImageRegistries []string `mapstructure:"allowed_infra_image_registries"`
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

	RequireNoNewPrivileges     bool     `mapstructure:"require_no_new_privileges"`
	RequireNonRootUser         bool     `mapstructure:"require_non_root_user"`
	RequireReadonlyRootfs      bool     `mapstructure:"require_readonly_rootfs"`
	RequireDropAllCapabilities bool     `mapstructure:"require_drop_all_capabilities"`
	AllowAllCapabilities       bool     `mapstructure:"allow_all_capabilities"`
	AllowedCapabilities        []string `mapstructure:"allowed_capabilities"`
	RequireMemoryLimit         bool     `mapstructure:"require_memory_limit"`
	RequireCPULimit            bool     `mapstructure:"require_cpu_limit"`
	// RequireCPULimitHard, unlike RequireCPULimit, only accepts a genuine
	// CPU-time cap: HostConfig.NanoCpus or CpuQuota. CpuShares (and CpuPeriod
	// set without CpuQuota) only set relative priority under contention — an
	// uncontended host still lets the container consume every CPU it can
	// schedule onto — so neither satisfies this stricter check. Independent
	// of RequireCPULimit: enabling this alone is sufficient; you do not also
	// need RequireCPULimit: true. Default false (opt-in).
	RequireCPULimitHard     bool     `mapstructure:"require_cpu_limit_hard"`
	RequirePidsLimit        bool     `mapstructure:"require_pids_limit"`
	AllowedSeccompProfiles  []string `mapstructure:"allowed_seccomp_profiles"`
	DenyUnconfinedSeccomp   bool     `mapstructure:"deny_unconfined_seccomp"`
	AllowedAppArmorProfiles []string `mapstructure:"allowed_apparmor_profiles"`
	DenyUnconfinedAppArmor  bool     `mapstructure:"deny_unconfined_apparmor"`
	AllowHostUserNS         bool     `mapstructure:"allow_host_userns"`
	AllowHostCgroupNS       bool     `mapstructure:"allow_host_cgroupns"`
	// RestrictNamespaceSharing gates HostConfig.NetworkMode/PidMode/IpcMode/
	// UsernsMode values of the form "container:<ref>" (join another
	// container's namespace) against AllowedNamespaceSharingContainers.
	// Default false: container:<ref> values continue to pass through
	// unchecked exactly as before this knob existed — AllowHostNetwork/PID/
	// IPC/UserNS above only ever match the literal "host" value and still
	// only do; this is an independent, orthogonal gate.
	RestrictNamespaceSharing bool `mapstructure:"restrict_namespace_sharing"`
	// AllowedNamespaceSharingContainers allowlists the container:<ref>
	// targets permitted when RestrictNamespaceSharing is true. Only
	// consulted when RestrictNamespaceSharing is true; empty denies every
	// container: ref.
	AllowedNamespaceSharingContainers []string `mapstructure:"allowed_namespace_sharing_containers"`
	// DenyNamespacePathMode denies HostConfig.NetworkMode values with an
	// "ns:" prefix (case-insensitive): Docker's raw host-namespace-file
	// attachment form, which bypasses the "host" literal check entirely.
	// Default false.
	DenyNamespacePathMode     bool             `mapstructure:"deny_namespace_path_mode"`
	AllowSysctls              bool             `mapstructure:"allow_sysctls"`
	RequiredLabels            []string         `mapstructure:"required_labels"`
	AllowedRuntimes           []string         `mapstructure:"allowed_runtimes"`
	ImageTrust                ImageTrustConfig `mapstructure:"image_trust"`
	DenySelinuxDisable        bool             `mapstructure:"deny_selinux_disable"`
	DenySelinuxLabelOverride  bool             `mapstructure:"deny_selinux_label_override"`
	DenyUnconfinedSystemPaths bool             `mapstructure:"deny_unconfined_system_paths"`
	// AllowTmpfsPrivilegedOptions permits tmpfs mount options that re-enable
	// exec/dev/suid semantics inside the tmpfs (HostConfig.Mounts[].
	// TmpfsOptions.Options, Engine API 1.46+): "exec", "dev", "suid". Docker's
	// own tmpfs default already sets noexec/nodev/nosuid; a client-supplied
	// Options entry can override that default per-mount, so it is denied
	// unless explicitly allowed. Default false.
	AllowTmpfsPrivilegedOptions bool `mapstructure:"allow_tmpfs_privileged_options"`
}

// LibpodContainerCreateRequestBodyConfig configures body inspection for
// POST /libpod/containers/create requests — Podman's native SpecGenerator
// create endpoint, distinct from the Docker-compat container_create block
// above. Field names mirror ContainerCreateRequestBodyConfig where the
// underlying semantics map onto a libpod equivalent (see design doc #148),
// so operator knowledge transfers between the two surfaces; two fields
// (AllowSystemdMode, AllowCustomIDMappings) have no Docker analog.
type LibpodContainerCreateRequestBodyConfig struct {
	AllowPrivileged   bool     `mapstructure:"allow_privileged"`
	AllowHostNetwork  bool     `mapstructure:"allow_host_network"`
	AllowHostPID      bool     `mapstructure:"allow_host_pid"`
	AllowHostIPC      bool     `mapstructure:"allow_host_ipc"`
	AllowHostUserNS   bool     `mapstructure:"allow_host_userns"`
	AllowedBindMounts []string `mapstructure:"allowed_bind_mounts"`
	AllowAllDevices   bool     `mapstructure:"allow_all_devices"`
	AllowedDevices    []string `mapstructure:"allowed_devices"`

	// RestrictNamespaceSharing/AllowedNamespaceSharingContainers gate
	// netns/pidns/ipcns/userns/utsns objects of the form
	// {"nsmode":"container","value":"<ref>"}, mirroring
	// ContainerCreateRequestBodyConfig.RestrictNamespaceSharing.
	RestrictNamespaceSharing          bool     `mapstructure:"restrict_namespace_sharing"`
	AllowedNamespaceSharingContainers []string `mapstructure:"allowed_namespace_sharing_containers"`

	AllowAllCapabilities   bool     `mapstructure:"allow_all_capabilities"`
	AllowedCapabilities    []string `mapstructure:"allowed_capabilities"`
	AllowedSeccompProfiles []string `mapstructure:"allowed_seccomp_profiles"`
	DenyUnconfinedSeccomp  bool     `mapstructure:"deny_unconfined_seccomp"`

	AllowedAppArmorProfiles []string `mapstructure:"allowed_apparmor_profiles"`
	DenyUnconfinedAppArmor  bool     `mapstructure:"deny_unconfined_apparmor"`

	DenySelinuxDisable bool `mapstructure:"deny_selinux_disable"`

	RequireNonRootUser    bool `mapstructure:"require_non_root_user"`
	RequireReadonlyRootfs bool `mapstructure:"require_readonly_rootfs"`
	RequireMemoryLimit    bool `mapstructure:"require_memory_limit"`
	RequireCPULimit       bool `mapstructure:"require_cpu_limit"`
	RequireCPULimitHard   bool `mapstructure:"require_cpu_limit_hard"`
	RequirePidsLimit      bool `mapstructure:"require_pids_limit"`

	AllowSysctls bool `mapstructure:"allow_sysctls"`

	ImageTrust ImageTrustConfig `mapstructure:"image_trust"`

	// AllowSystemdMode permits a "systemd" value other than "false"
	// (SpecGenerator's own default, sent even when --systemd was never
	// passed). No Docker Engine API analog. Default false: fail-closed.
	AllowSystemdMode bool `mapstructure:"allow_systemd_mode"`

	// AllowCustomIDMappings permits a non-default idmappings.UIDMap/GIDMap
	// or --userns=auto. A blunt gate for v1.6; default false.
	AllowCustomIDMappings bool `mapstructure:"allow_custom_id_mappings"`
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
	// AllowedEnvVars, when non-empty, restricts the exec-create Env array to
	// these variable names — matched by name only (the substring before the
	// first "="), exact string comparison, case-sensitive; the value is
	// never inspected. Default empty means no restriction at all: unlike
	// AllowedCommands (whose empty default denies every exec), an empty
	// AllowedEnvVars is a deliberate zero-behavior-change default so
	// enabling exec command allowlisting does not also silently start
	// denying every exec session's environment.
	AllowedEnvVars []string `mapstructure:"allowed_env_vars"`
	// DeniedEnvVars variable names are always blocked and are checked
	// before AllowedEnvVars, so a name present in both lists is denied
	// (fail closed on operator misconfiguration). Default empty means
	// nothing is blocked.
	DeniedEnvVars []string `mapstructure:"denied_env_vars"`
	// AllowedEnvValues optionally pins selected exec environment entries to
	// exact NAME=VALUE strings. A variable name represented here is denied
	// unless the complete entry exactly matches one of its configured values;
	// values are compared but never included in denial reasons or logs. Names
	// not represented here continue to follow AllowedEnvVars/DeniedEnvVars.
	AllowedEnvValues []string `mapstructure:"allowed_env_values"`
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

	// RequireMemoryLimit/RequireCPULimit/RequireCPULimitHard/RequirePidsLimit
	// revalidate the container's EFFECTIVE resource state (current values
	// merged with the request's explicit fields, using Docker's own update
	// merge semantics) against the same requirements container_create.require_*
	// enforces at create time. Names are copied verbatim from
	// ContainerCreateRequestBodyConfig so operator knowledge transfers. All
	// default false (opt-in, v1.x-safe).
	//
	// Evaluated ONLY when AllowResourceUpdates is true: when it is false, the
	// existing blanket deny of every resource-control field already preserves
	// the create-time guarantee, so there is nothing for these flags to add.
	// Enabling any of these while AllowResourceUpdates is false is accepted
	// (not a config error) but inert; sockguard logs a startup/reload warning
	// since it is very likely operator confusion.
	//
	// Ratchet behavior: because the check runs against the merged EFFECTIVE
	// state rather than only the fields the request touches, a container that
	// predates a newly-enabled requirement (e.g. one created with no memory
	// limit) will have its NEXT guarded update denied until a compliant value
	// is supplied — even an update that does not itself touch resources. See
	// the migration note in docs/content/docs/configuration.mdx.
	RequireMemoryLimit  bool `mapstructure:"require_memory_limit"`
	RequireCPULimit     bool `mapstructure:"require_cpu_limit"`
	RequireCPULimitHard bool `mapstructure:"require_cpu_limit_hard"`
	RequirePidsLimit    bool `mapstructure:"require_pids_limit"`
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
	// EndpointConfig narrows allow_endpoint_config into independent per-field
	// gates (#186) — see EndpointConfigRequestBodyConfig's doc comment for
	// the field mapping and precedence rules. Only consulted when
	// allow_endpoint_config is false/unset; setting both is a config
	// validation error (validateNetworkEndpointConfig). Has no libpod analog
	// — never consulted by the libpod_network inspector, see libpod_network.go.
	EndpointConfig       EndpointConfigRequestBodyConfig `mapstructure:"endpoint_config"`
	AllowDisconnectForce bool                            `mapstructure:"allow_disconnect_force"`
	// AllowDisableIPv4 permits POST /networks/create with EnableIPv4 explicitly
	// false (Engine API 1.48+). Docker defaults EnableIPv4 to true (unset and
	// true both pass); a client-set false disables IPv4 addressing entirely,
	// an unusual and rarely-intended posture, so it requires this opt-in.
	// Default false.
	AllowDisableIPv4 bool `mapstructure:"allow_disable_ipv4"`
}

// EndpointConfigRequestBodyConfig configures granular per-field admission for
// Docker's EndpointSettings object — the payload carried by both
// POST /networks/*/connect's EndpointConfig and POST /containers/create's
// NetworkingConfig.EndpointsConfig entries (request_body.network's
// allow_endpoint_config governs both, see filter_options.go's cross-wire).
//
// Precedence (#186): request_body.network.allow_endpoint_config: true is the
// legacy whole-object escape hatch and, when set, admits every field
// unchanged — this block is not consulted at all in that case, and setting
// both is rejected at config-load time (validateNetworkEndpointConfig) to
// avoid silent ambiguity. When allow_endpoint_config is false/unset, each
// field below gates independently. EndpointSettings fields with no gate here
// — Links (joining another container's linked alias namespace) and
// DriverOpts — have no individual escape hatch under the granular form:
// they are always denied, fail-closed, unless allow_endpoint_config: true is
// used instead.
type EndpointConfigRequestBodyConfig struct {
	// AllowStaticAddressing permits IPAMConfig.IPv4Address/IPv6Address and the
	// deprecated top-level Gateway/IPAddress/IPPrefixLen/IPv6Gateway/
	// GlobalIPv6Address/GlobalIPv6PrefixLen fields. Default false.
	AllowStaticAddressing bool `mapstructure:"allow_static_addressing"`
	// AllowLinkLocalIPs permits IPAMConfig.LinkLocalIPs, independent of
	// AllowStaticAddressing. Default false.
	AllowLinkLocalIPs bool `mapstructure:"allow_link_local_ips"`
	// AllowMACPinning permits MacAddress — shared by network connect's
	// EndpointConfig and container-create's deprecated top-level MacAddress
	// field. Default false.
	AllowMACPinning bool `mapstructure:"allow_mac_pinning"`
	// AllowGwPriority permits GwPriority (Engine API 1.55+, which network
	// provides the container's default gateway when attached to more than
	// one). Default false.
	AllowGwPriority bool `mapstructure:"allow_gw_priority"`
	// AllowAliases permits Aliases. Default true: this reproduces
	// allow_endpoint_config's long-standing behavior of never gating Aliases
	// at all — Docker Compose sets Aliases: [serviceName] on every endpoint
	// it creates, so denying them by default would break every multi-network
	// Compose recreate. Set explicitly to false to deny Aliases under the
	// granular form; there is no equivalent opt-out under
	// allow_endpoint_config: true, which always admits Aliases.
	AllowAliases bool `mapstructure:"allow_aliases"`
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

	// RequireCPULimit / RequireCPULimitHard require
	// TaskTemplate.Resources.Limits.NanoCPUs to be positive on service create,
	// ordinary update, and any spec that could become active via rollback
	// (manual ?rollback=previous or an automatic UpdateConfig.FailureAction:
	// rollback). Scope is deliberately CPU-only, matching the container-create
	// CPU-limit parity this closes; service memory/PIDs parity is deferred.
	// Swarm's TaskTemplate.Resources.Limits has no CpuShares/CpuQuota-style
	// soft/hard split the way containers do, so both flags collapse to the
	// same NanoCPUs>0 predicate — kept as two knobs for schema parity with
	// container_create/container_update so a policy can be mirrored field-name
	// for field-name. RequireCPULimitHard alone is sufficient; it does not
	// require RequireCPULimit. Both default false (opt-in).
	RequireCPULimit     bool `mapstructure:"require_cpu_limit"`
	RequireCPULimitHard bool `mapstructure:"require_cpu_limit_hard"`
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

// BuildkitRequestBodyConfig configures sockguard's BuildKit gRPC mediation
// policy (issue #185) for the two opaque tunnel endpoints POST /session and
// POST /grpc. As of phase 1 this is schema and policy ONLY — there is no
// runtime mediator yet, so a configured block still results in both
// endpoints being denied at request time (see
// filter.buildkitPolicy.inspect); the policy this struct describes is what
// later phases will actually enforce once the h2c-terminating mediator
// exists.
//
// Presence, not an "enabled" flag, is what matters: an absent block (the
// Go zero value, identical to what a config that never mentions "buildkit:"
// at all decodes to) denies /session and /grpc internally even when an
// outer HTTP rule allows them. Every leaf below follows the same
// "empty/false allowed_* = deny" convention as the rest of RequestBodyConfig
// — see e.g. ImagePullRequestBodyConfig.AllowedRegistries.
//
// Works at the top level (RequestBodyConfig here) and per client profile
// (ClientProfileConfig.RequestBody carries the identical type) exactly like
// every other request_body.* block; there is no merge between the two —
// see ClientProfileConfig's doc comment.
type BuildkitRequestBodyConfig struct {
	// Control gates moby.buildkit.v1.Control, reached over POST /grpc.
	Control BuildkitControlRequestBodyConfig `mapstructure:"control"`
	// Session gates the services buildkitd calls back into the client for,
	// reached over POST /session.
	Session BuildkitSessionRequestBodyConfig `mapstructure:"session"`
}

// BuildkitControlRequestBodyConfig gates moby.buildkit.v1.Control's Solve/
// Status/Info/ListWorkers RPCs. Every other Control method (Prune,
// DiskUsage, ListenBuildHistory, UpdateBuildHistory, the nested
// Control/Session bidirectional stream) has no enabling knob at all in
// v1.7 — see buildkitproxy.DeniedExamples — matching the #185 sign-off's
// "hard-deny the rest, no enabling knobs" compatibility boundary.
type BuildkitControlRequestBodyConfig struct {
	// AllowInfo permits the passthrough Control/Info RPC (worker/buildkit
	// version metadata; no policy-relevant fields). Default false.
	AllowInfo bool `mapstructure:"allow_info"`
	// AllowListWorkers permits the passthrough Control/ListWorkers RPC
	// (worker capability metadata; no policy-relevant fields). Default
	// false.
	AllowListWorkers bool `mapstructure:"allow_list_workers"`
	// AllowStatus permits the mediated Control/Status RPC. Once the
	// mediator exists, a Status call is only ever admitted for a Ref that
	// belongs to a Solve already admitted on the same client/profile (#185
	// synthesis) — there is no independent allowlist here because Status
	// has nothing to allowlist beyond that ownership check. Default false.
	AllowStatus bool `mapstructure:"allow_status"`
	// Solve gates the mediated Control/Solve RPC.
	Solve BuildkitSolveRequestBodyConfig `mapstructure:"solve"`
}

// BuildkitSolveRequestBodyConfig gates moby.buildkit.v1.Control/Solve.
//
// Deliberately has no allow_run_instructions/allow_host_network/
// allow_remote_context fields of its own: per the #185 synthesis, "the
// existing request_body.build knobs ... apply to both classic /build and
// BuildKit Solve" — BuildRequestBodyConfig's three flags are reused
// verbatim once the mediator can decode a Solve's LLB definition, the same
// way network.allow_endpoint_config (not a duplicate
// container_create.allow_endpoint_config) governs both network connect and
// container-create's embedded EndpointsConfig. Duplicating those flags here
// would let an operator widen one path and forget the other.
type BuildkitSolveRequestBodyConfig struct {
	// Allow permits the Control/Solve RPC at all. Default false.
	Allow bool `mapstructure:"allow"`
}

// BuildkitSessionRequestBodyConfig gates the services buildkitd calls back
// into the client for over POST /session. moby.buildkit.v1.frontend.LLBBridge,
// moby.exporter.v1.Exporter, and
// moby.buildkit.v1.sourcepolicy.policysession.PolicyVerifier have no
// enabling knob at all — see buildkitproxy.DeniedExamples.
type BuildkitSessionRequestBodyConfig struct {
	// Health permits the passthrough grpc.health.v1.Health/{Check,Watch}
	// RPCs. Default false.
	Health bool `mapstructure:"health"`
	// Auth gates moby.filesync.v1.Auth's four RPCs (Credentials,
	// FetchToken, GetTokenAuthority, VerifyTokenAuthority) — "Auth/*" in
	// the #185 synthesis; one Allow flag governs all four, since a client
	// implementation cannot meaningfully use one without the others.
	Auth BuildkitAuthRequestBodyConfig `mapstructure:"auth"`
	// Secrets gates moby.buildkit.secrets.v1.Secrets/GetSecret.
	Secrets BuildkitSecretsRequestBodyConfig `mapstructure:"secrets"`
	// SSH gates moby.sshforward.v1.SSH's CheckAgent and ForwardAgent RPCs —
	// "SSH/{CheckAgent,ForwardAgent}" in the #185 synthesis.
	SSH BuildkitSSHRequestBodyConfig `mapstructure:"ssh"`
	// FileSync gates moby.filesync.v1.FileSync/DiffCopy.
	// FileSync/TarStream has no enabling knob — see
	// buildkitproxy.DeniedExamples.
	FileSync BuildkitFileSyncRequestBodyConfig `mapstructure:"file_sync"`
	// FileSend gates moby.filesync.v1.FileSend/DiffCopy.
	FileSend BuildkitFileSendRequestBodyConfig `mapstructure:"file_send"`
	// Upload gates moby.upload.v1.Upload/Pull.
	Upload BuildkitUploadRequestBodyConfig `mapstructure:"upload"`
}

// BuildkitAuthRequestBodyConfig gates moby.filesync.v1.Auth. Per the #185
// synthesis ("registry/realm/scope allowlists"), once the mediator exists a
// call is admitted only when its registry host, realm, and scope each match
// one of the corresponding allowlists below (empty = deny, the standard
// RequestBodyConfig convention) — Allow alone does not admit every host.
type BuildkitAuthRequestBodyConfig struct {
	Allow             bool     `mapstructure:"allow"`
	AllowedRegistries []string `mapstructure:"allowed_registries"`
	AllowedRealms     []string `mapstructure:"allowed_realms"`
	AllowedScopes     []string `mapstructure:"allowed_scopes"`
}

// BuildkitSecretsRequestBodyConfig gates
// moby.buildkit.secrets.v1.Secrets/GetSecret. Per the #185 synthesis
// ("exact ID allowlists"), once the mediator exists a call is admitted only
// when its secret ID exactly matches an entry in AllowedIDs (empty = deny).
type BuildkitSecretsRequestBodyConfig struct {
	Allow      bool     `mapstructure:"allow"`
	AllowedIDs []string `mapstructure:"allowed_ids"`
}

// BuildkitSSHRequestBodyConfig gates moby.sshforward.v1.SSH. Per the #185
// synthesis ("exact ID allowlists"), once the mediator exists a call is
// admitted only when its SSH agent ID exactly matches an entry in
// AllowedIDs (empty = deny).
type BuildkitSSHRequestBodyConfig struct {
	Allow      bool     `mapstructure:"allow"`
	AllowedIDs []string `mapstructure:"allowed_ids"`
}

// BuildkitFileSyncRequestBodyConfig gates moby.filesync.v1.FileSync/DiffCopy.
// Path/file/byte caps and the Dockerfile hold-and-inspect behavior the #185
// synthesis describes are phase 5 runtime concerns; phase 1 only ships the
// Allow gate itself.
type BuildkitFileSyncRequestBodyConfig struct {
	Allow bool `mapstructure:"allow"`
}

// BuildkitFileSendRequestBodyConfig gates moby.filesync.v1.FileSend/DiffCopy.
type BuildkitFileSendRequestBodyConfig struct {
	Allow bool `mapstructure:"allow"`
}

// BuildkitUploadRequestBodyConfig gates moby.upload.v1.Upload/Pull.
type BuildkitUploadRequestBodyConfig struct {
	Allow bool `mapstructure:"allow"`
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
	// AllowCrossOwnerNamespaceSharing restores the pre-v1.5 pass-through
	// behavior for POST /containers/create when Owner is configured. By
	// default (false — a security-relevant default, see CHANGELOG),
	// sockguard resolves every HostConfig.NetworkMode/PidMode/IpcMode/
	// UsernsMode "container:<ref>" namespace-sharing target and denies the
	// request if the referenced container belongs to a different owner —
	// joining a foreign container's namespace is a full cross-tenant
	// compromise (shared sockets, process visibility, shared /dev/shm),
	// strictly worse than the access ownership already gates on every other
	// endpoint. Set true to restore the old unchecked behavior. Same-owner
	// refs always pass; an unlabeled target is treated as untrusted and
	// denied too (consistent with every other container-targeting ownership
	// check), so only a same-owner ref is allowed when this is false.
	AllowCrossOwnerNamespaceSharing bool `mapstructure:"allow_cross_owner_namespace_sharing"`
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
	// MountOn names the effective main listener (see Config.EffectiveListeners)
	// that carries in-band admin traffic when Listen is NOT configured. It
	// disambiguates "admin rides the main listener" once there is more than
	// one effective main listener — mounting admin on every listener by
	// default would silently widen the admin attack surface in proportion
	// to listener count. Required when Enabled && !Listen.Configured() &&
	// there are 2+ effective main listeners; ignored (may be left empty)
	// when there is exactly one, preserving today's zero-config behavior
	// byte-for-byte.
	MountOn string `mapstructure:"mount_on"`
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

// MutationsConfig configures declarative fail-closed admission mutations
// (#151): a bounded set of config-driven rules that inject owner-independent
// labels or remap image references on a matched request body before the
// existing container_create/service body inspectors, image-trust
// verification, and ownership stamping run. See docs/content/docs for the
// full schema and security model.
//
// Mutations are deliberately not part of clients.profiles: v1 has one
// mutation authority and no global/profile merge rules — every configured
// rule applies identically regardless of which client profile matched the
// request. This block is decoded with a strict subtree decode (see
// decodeMutationsStrict in load.go) that rejects unknown keys and disables
// weak/YAML-typing coercion, unlike the rest of this legacy schema.
type MutationsConfig struct {
	Rules []MutationRuleConfig `mapstructure:"rules"`
}

// MutationRuleConfig is one declarative admission-mutation rule. Exactly one
// of InjectLabels/RemapImage must be set; validate.go enforces this and the
// remaining bounds (rule/label counts, key/value sizes, surface/action
// compatibility, overlap rejection, owner-label-key reservation).
type MutationRuleConfig struct {
	// ID uniquely identifies the rule for logging/audit correlation.
	// Required; must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$.
	ID string `mapstructure:"id"`
	// Mode is the rule's rollout posture: "enforce" (default when empty),
	// "warn", or "audit". See config.ParseRolloutMode for semantics.
	Mode string `mapstructure:"mode"`
	// Surfaces lists the request surfaces this rule applies to, from
	// "container_create", "service_create", "service_update". No duplicates.
	Surfaces []string `mapstructure:"surfaces"`
	// InjectLabels configures a label-map merge mutation. Mutually exclusive
	// with RemapImage.
	InjectLabels *InjectLabelsMutationConfig `mapstructure:"inject_labels"`
	// RemapImage configures a single string-field image replace mutation.
	// Mutually exclusive with InjectLabels.
	RemapImage *ImageRemapMutationConfig `mapstructure:"remap_image"`
}

// InjectLabelsMutationConfig unconditionally sets/replaces the configured
// labels on every request matching the rule's surfaces. Valid only on
// surfaces that carry a label map (container_create, service_create).
type InjectLabelsMutationConfig struct {
	Labels map[string]string `mapstructure:"labels"`
}

// ImageRemapMutationConfig rewrites a matched image reference. Match is
// "exact" (the whole reference must equal From) or "prefix" (From must
// prefix the reference; the remainder is preserved after To).
type ImageRemapMutationConfig struct {
	Match string `mapstructure:"match"`
	From  string `mapstructure:"from"`
	To    string `mapstructure:"to"`
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
			LibpodContainerCreate: LibpodContainerCreateRequestBodyConfig{
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
			// Network.EndpointConfig.AllowAliases defaults true so the granular
			// form's default reproduces allow_endpoint_config's long-standing
			// unconditional-allow behavior for Aliases exactly (#186) — see
			// EndpointConfigRequestBodyConfig's doc comment. LibpodNetwork
			// reuses the same struct type and gets the identical default for
			// posture consistency, even though it has no libpod-native network
			// connect endpoint to gate and never consults EndpointConfig at all
			// — see libpod_network.go.
			Network: NetworkRequestBodyConfig{
				EndpointConfig: EndpointConfigRequestBodyConfig{
					AllowAliases: true,
				},
			},
			LibpodNetwork: NetworkRequestBodyConfig{
				EndpointConfig: EndpointConfigRequestBodyConfig{
					AllowAliases: true,
				},
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
