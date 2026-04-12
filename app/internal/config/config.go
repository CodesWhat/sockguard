package config

// Config represents the sockguard configuration.
type Config struct {
	Listen                       ListenConfig   `mapstructure:"listen"`
	Upstream                     UpstreamConfig `mapstructure:"upstream"`
	Log                          LogConfig      `mapstructure:"log"`
	Response                     ResponseConfig `mapstructure:"response"`
	Health                       HealthConfig   `mapstructure:"health"`
	Rules                        []RuleConfig   `mapstructure:"rules"`
	InsecureAllowBodyBlindWrites bool           `mapstructure:"insecure_allow_body_blind_writes"`

	rulesExplicitlyConfigured bool
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
	DenyVerbosity string `mapstructure:"deny_verbosity"`
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
			DenyVerbosity: "verbose",
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
