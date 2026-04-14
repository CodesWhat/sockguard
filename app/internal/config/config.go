package config

// Config represents the sockguard configuration.
type Config struct {
	Listen                       ListenConfig      `mapstructure:"listen"`
	Upstream                     UpstreamConfig    `mapstructure:"upstream"`
	Log                          LogConfig         `mapstructure:"log"`
	Response                     ResponseConfig    `mapstructure:"response"`
	RequestBody                  RequestBodyConfig `mapstructure:"request_body"`
	Clients                      ClientsConfig     `mapstructure:"clients"`
	Ownership                    OwnershipConfig   `mapstructure:"ownership"`
	Health                       HealthConfig      `mapstructure:"health"`
	Rules                        []RuleConfig      `mapstructure:"rules"`
	InsecureAllowBodyBlindWrites bool              `mapstructure:"insecure_allow_body_blind_writes"`
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
	CertFile     string `mapstructure:"cert_file"`
	KeyFile      string `mapstructure:"key_file"`
	ClientCAFile string `mapstructure:"client_ca_file"`
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
}

// ResponseConfig configures HTTP responses returned by sockguard itself.
type ResponseConfig struct {
	DenyVerbosity      string `mapstructure:"deny_verbosity"`
	RedactContainerEnv bool   `mapstructure:"redact_container_env"`
	RedactMountPaths   bool   `mapstructure:"redact_mount_paths"`
}

// RequestBodyConfig configures request-body inspection policies.
type RequestBodyConfig struct {
	ContainerCreate ContainerCreateRequestBodyConfig `mapstructure:"container_create"`
}

// ContainerCreateRequestBodyConfig configures body inspection for
// POST /containers/create requests.
type ContainerCreateRequestBodyConfig struct {
	AllowPrivileged   bool     `mapstructure:"allow_privileged"`
	AllowHostNetwork  bool     `mapstructure:"allow_host_network"`
	AllowedBindMounts []string `mapstructure:"allowed_bind_mounts"`
}

// ClientsConfig configures coarse per-client access controls.
type ClientsConfig struct {
	AllowedCIDRs    []string                    `mapstructure:"allowed_cidrs"`
	ContainerLabels ClientContainerLabelsConfig `mapstructure:"container_labels"`
}

// ClientContainerLabelsConfig configures opt-in per-client ACLs loaded from
// the calling container's labels after resolving the caller by source IP.
type ClientContainerLabelsConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	LabelPrefix string `mapstructure:"label_prefix"`
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
			SocketMode: "0660", // used only when the user opts into a unix socket listener
		},
		Upstream: UpstreamConfig{
			Socket: "/var/run/docker.sock",
		},
		Log: LogConfig{
			Level:     "info",
			Format:    "json",
			Output:    "stderr",
			AccessLog: true,
		},
		Response: ResponseConfig{
			// Default to minimal deny responses: the generic message only,
			// no method, path, or reason echoed back. Verbose mode is still
			// supported for rule-authoring and dev work, but it is never a
			// production default because it can leak request path details
			// (even with `/secrets/*` and `/swarm/unlockkey` redacted) that
			// a honest security product should not hand a denied caller.
			DenyVerbosity:      "minimal",
			RedactContainerEnv: true,
			RedactMountPaths:   true,
		},
		RequestBody: RequestBodyConfig{
			ContainerCreate: ContainerCreateRequestBodyConfig{},
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
	}
}
