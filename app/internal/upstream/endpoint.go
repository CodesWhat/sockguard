// Package upstream resolves and dials the Docker daemon sockguard proxies to.
//
// Historically the upstream was a single local unix socket dialed inline by
// every consumer (the reverse proxy, the hijack path, the exec inspector, the
// ownership/visibility/client-ACL side channels, and the health monitors). This
// package replaces that hardcoded assumption with a single seam — a Resolver
// over an ordered list of Endpoints — so the upstream can be a remote Docker
// daemon over TCP+TLS, and so a redundant set of endpoints for the same logical
// daemon/swarm can be health-checked with automatic failover.
//
// Every endpoint in a Resolver MUST address the same logical daemon (a swarm
// VIP plus its backing managers, an HA pair behind keepalived, etc.). Container
// IDs, exec session IDs, and owner labels are daemon-local; failing a live
// session over to a genuinely different daemon would surface dangling IDs. The
// Resolver therefore models active/passive redundancy, not cross-daemon
// fan-out.
package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Endpoint is one resolved upstream target: either a local unix socket or a
// remote TCP daemon, optionally wrapped in client TLS.
type Endpoint struct {
	// Name is a stable identifier used for metrics labels and log fields. For a
	// unix socket it is the socket path; for TCP it is host:port. It is never
	// empty for a valid endpoint.
	Name string
	// Network is "unix" or "tcp" — the first argument to net.Dial.
	Network string
	// Address is the unix socket path or the TCP host:port. It is the second
	// argument to net.Dial.
	Address string
	// BasePath is prepended to every Docker API request sent through this
	// endpoint. RawBasePath preserves the configured percent-encoding when it
	// differs from BasePath's default escaping. Both are empty for endpoints
	// without a URL path prefix.
	BasePath    string
	RawBasePath string
	// TLSConfig is non-nil only for TCP endpoints that negotiate TLS. It is nil
	// for unix sockets and for plain-TCP endpoints (which require an explicit
	// insecure acknowledgement to construct).
	TLSConfig *tls.Config
}

// IsTLS reports whether the endpoint dials over TLS.
func (e Endpoint) IsTLS() bool { return e.TLSConfig != nil }

// String renders the endpoint for logs: scheme://address, with a "+tls" suffix
// when TLS is in play.
func (e Endpoint) String() string {
	scheme := e.Network
	if e.IsTLS() {
		scheme += "+tls"
	}
	return scheme + "://" + e.Address + e.escapedBasePath()
}

// EndpointSpec is the parsed, validated configuration for one endpoint before
// its TLS material is loaded. BuildEndpoint turns a spec into an Endpoint.
type EndpointSpec struct {
	// Address is a Docker-style upstream address: "unix:///var/run/docker.sock",
	// "tcp://host:2376", or a bare path (treated as a unix socket for backward
	// compatibility with the legacy upstream.socket field).
	Address string
	// CAFile verifies the remote daemon's server certificate. Empty falls back
	// to the system roots.
	CAFile string
	// CertFile and KeyFile present a client certificate to the remote daemon
	// (mutual TLS). Both must be set together or both empty.
	CertFile string
	KeyFile  string
	// ServerName overrides the SNI / certificate hostname verified against the
	// daemon's server cert. Empty derives it from the address host.
	ServerName string
	// InsecureAllowPlainTCP permits a tcp:// endpoint with no TLS material. A
	// remote daemon reached over plaintext TCP exposes the full Docker API to
	// anyone on the path; this must be set deliberately, mirroring the
	// listener-side insecure_allow_plain_tcp acknowledgement.
	InsecureAllowPlainTCP bool
	// InsecureSkipTLSVerify disables verification of the daemon's server
	// certificate. Useful for self-signed homelab daemons; dangerous in
	// production because it defeats authentication of the upstream.
	InsecureSkipTLSVerify bool
}

// BuildEndpoint parses spec.Address, loads any TLS material, and returns a
// dialable Endpoint. It returns a descriptive error for every malformed or
// inconsistent spec so config validation can surface the exact problem.
func BuildEndpoint(spec EndpointSpec) (Endpoint, error) {
	parsed, err := parseEndpointAddress(spec.Address)
	if err != nil {
		return Endpoint{}, err
	}

	switch parsed.network {
	case "unix":
		// TLS material on a unix endpoint is meaningless and almost always a
		// copy-paste mistake — reject it rather than silently ignore.
		if spec.ServerName != "" {
			return Endpoint{}, fmt.Errorf("upstream endpoint %q: tls.server_name is not valid for a unix socket", spec.Address)
		}
		if spec.CertFile != "" || spec.KeyFile != "" || spec.CAFile != "" {
			return Endpoint{}, fmt.Errorf("upstream endpoint %q: TLS settings are not valid for a unix socket", spec.Address)
		}
		return Endpoint{Name: parsed.address, Network: "unix", Address: parsed.address}, nil
	case "tcp":
		tlsConfig, err := buildClientTLS(spec, parsed.address)
		if err != nil {
			return Endpoint{}, err
		}
		name := parsed.address + parsed.escapedBasePath()
		return Endpoint{
			Name:        name,
			Network:     "tcp",
			Address:     parsed.address,
			BasePath:    parsed.basePath,
			RawBasePath: parsed.rawBasePath,
			TLSConfig:   tlsConfig,
		}, nil
	default:
		return Endpoint{}, fmt.Errorf("upstream endpoint %q: unsupported scheme %q (use unix:// or tcp://)", spec.Address, parsed.network)
	}
}

// ValidateSpec checks a spec's address and TLS-field consistency WITHOUT
// touching the filesystem, so config validation (including the remote
// POST /admin/validate path, where cert files may not exist on the validating
// host) can reject a malformed endpoint without loading its TLS material.
// BuildEndpoint performs the same structural checks and additionally loads the
// referenced files.
func ValidateSpec(spec EndpointSpec) error {
	parsed, err := parseEndpointAddress(spec.Address)
	if err != nil {
		return err
	}
	switch parsed.network {
	case "unix":
		if spec.ServerName != "" {
			return fmt.Errorf("upstream endpoint %q: tls.server_name is not valid for a unix socket", spec.Address)
		}
		if spec.CertFile != "" || spec.KeyFile != "" || spec.CAFile != "" {
			return fmt.Errorf("upstream endpoint %q: TLS settings are not valid for a unix socket", spec.Address)
		}
		return nil
	case "tcp":
		if (spec.CertFile == "") != (spec.KeyFile == "") {
			return fmt.Errorf("upstream endpoint %q: tls.cert_file and tls.key_file must be set together", spec.Address)
		}
		hasAnyTLS := spec.CertFile != "" || spec.KeyFile != "" || spec.CAFile != "" || spec.InsecureSkipTLSVerify
		if !hasAnyTLS && !spec.InsecureAllowPlainTCP {
			return fmt.Errorf("upstream endpoint %q: TCP requires TLS (set tls.ca_file/cert_file/key_file) or insecure_allow_plain_tcp: true", spec.Address)
		}
		return nil
	default:
		return fmt.Errorf("upstream endpoint %q: unsupported scheme %q (use unix:// or tcp://)", spec.Address, parsed.network)
	}
}

type parsedEndpointAddress struct {
	network     string
	address     string
	basePath    string
	rawBasePath string
}

func (a parsedEndpointAddress) escapedBasePath() string {
	return (&url.URL{Path: a.basePath, RawPath: a.rawBasePath}).EscapedPath()
}

func (e Endpoint) escapedBasePath() string {
	return (&url.URL{Path: e.BasePath, RawPath: e.RawBasePath}).EscapedPath()
}

// parseAddress splits a Docker-style upstream address into a (network, address)
// pair. A bare path with no scheme is treated as a unix socket for backward
// compatibility with the legacy upstream.socket field.
func parseAddress(raw string) (network, address string, err error) {
	parsed, err := parseEndpointAddress(raw)
	if err != nil {
		return "", "", err
	}
	return parsed.network, parsed.address, nil
}

func parseEndpointAddress(raw string) (parsedEndpointAddress, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return parsedEndpointAddress{}, fmt.Errorf("upstream endpoint address is empty")
	}

	// Bare absolute or relative path with no scheme → unix socket.
	if !strings.Contains(raw, "://") {
		if strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
			return parsedEndpointAddress{network: "unix", address: raw}, nil
		}
		return parsedEndpointAddress{}, fmt.Errorf("upstream endpoint %q: address must be a unix path or a unix://, tcp:// URL", raw)
	}

	// Docker treats everything after unix:// as literal socket-name bytes.
	// URL parsing would decode %2F and reinterpret ?/# as query/fragment
	// delimiters, selecting a different socket from the one the client named.
	if strings.HasPrefix(raw, "unix://") {
		address := strings.TrimPrefix(raw, "unix://")
		if address == "" {
			return parsedEndpointAddress{}, fmt.Errorf("upstream endpoint %q: missing socket path", raw)
		}
		if strings.Contains(address, "://") {
			return parsedEndpointAddress{}, fmt.Errorf("upstream endpoint %q: invalid unix socket address", raw)
		}
		// Validate the URL grammar before discarding the parsed form. In
		// particular, Go's host parser rejects escapes such as %2F and %3F in
		// unix://relative%2Fsock while accepting them in the absolute path form.
		// Docker performs the same validation but still dials the original,
		// literal address bytes after it succeeds.
		if _, err := url.Parse(raw); err != nil {
			return parsedEndpointAddress{}, fmt.Errorf("upstream endpoint %q: invalid unix socket address: %w", raw, err)
		}
		return parsedEndpointAddress{network: "unix", address: address}, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return parsedEndpointAddress{}, fmt.Errorf("upstream endpoint %q: %w", raw, err)
	}

	switch u.Scheme {
	case "tcp", "http", "https":
		if u.Host == "" {
			return parsedEndpointAddress{}, fmt.Errorf("upstream endpoint %q: missing host:port", raw)
		}
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return parsedEndpointAddress{}, fmt.Errorf("upstream endpoint %q: TCP query, fragment, and userinfo components are not supported", raw)
		}
		host := u.Host
		if u.Port() == "" {
			return parsedEndpointAddress{}, fmt.Errorf("upstream endpoint %q: TCP address must include a port (e.g. tcp://host:2376)", raw)
		}
		return parsedEndpointAddress{
			network:     "tcp",
			address:     host,
			basePath:    u.Path,
			rawBasePath: u.RawPath,
		}, nil
	default:
		return parsedEndpointAddress{}, fmt.Errorf("upstream endpoint %q: unsupported scheme %q (use unix:// or tcp://)", raw, u.Scheme)
	}
}

// buildClientTLS constructs the *tls.Config used to dial a remote daemon. It
// returns nil only when plaintext TCP is explicitly acknowledged.
func buildClientTLS(spec EndpointSpec, address string) (*tls.Config, error) {
	hasCert := spec.CertFile != "" || spec.KeyFile != ""
	hasAnyTLS := hasCert || spec.CAFile != "" || spec.InsecureSkipTLSVerify

	if !hasAnyTLS {
		if spec.InsecureAllowPlainTCP {
			return nil, nil
		}
		return nil, fmt.Errorf("upstream endpoint %q: TCP requires TLS (set tls.ca_file/cert_file/key_file) or insecure_allow_plain_tcp: true", spec.Address)
	}

	if (spec.CertFile == "") != (spec.KeyFile == "") {
		return nil, fmt.Errorf("upstream endpoint %q: tls.cert_file and tls.key_file must be set together", spec.Address)
	}

	serverName := spec.ServerName
	if serverName == "" {
		// Derive SNI from the host portion of host:port.
		if host, _, ok := splitHostPort(address); ok {
			serverName = host
		} else {
			serverName = address
		}
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		// #nosec G402 -- opt-in and gated behind an explicit acknowledgement.
		InsecureSkipVerify: spec.InsecureSkipTLSVerify, //nolint:gosec // opt-in, gated behind an explicit acknowledgement
	}

	if hasCert {
		cert, err := tls.LoadX509KeyPair(spec.CertFile, spec.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("upstream endpoint %q: loading client certificate: %w", spec.Address, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if spec.CAFile != "" {
		pem, err := os.ReadFile(spec.CAFile)
		if err != nil {
			return nil, fmt.Errorf("upstream endpoint %q: reading tls.ca_file: %w", spec.Address, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("upstream endpoint %q: tls.ca_file %q contains no valid PEM certificates", spec.Address, spec.CAFile)
		}
		tlsConfig.RootCAs = pool
	}

	return tlsConfig, nil
}

// splitHostPort splits host:port without failing on IPv6 literals the way a
// naive strings.Split would. It returns ok=false when no port is present.
func splitHostPort(hostport string) (host, port string, ok bool) {
	i := strings.LastIndex(hostport, ":")
	if i < 0 {
		return hostport, "", false
	}
	host = hostport[:i]
	port = hostport[i+1:]
	// Strip brackets from an IPv6 literal: [::1]:2376 → ::1
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return host, port, port != ""
}

const (
	dockerDefaultHost = "localhost"
	dockerDefaultPort = "2375"
)

func parseDockerHost(raw string) (normalized, network string, err error) {
	host := strings.TrimSpace(raw)
	if host == "" {
		return "", "", fmt.Errorf("DOCKER_HOST is empty")
	}

	protocol, address, hasProtocol := strings.Cut(host, "://")
	if !hasProtocol {
		address = protocol
		protocol = "tcp"
	}

	switch protocol {
	case "tcp":
		address, err = parseDockerTCPAddress(address)
		if err != nil {
			return "", "", fmt.Errorf("DOCKER_HOST %q: %w", host, err)
		}
		return "tcp://" + address, "tcp", nil
	case "unix":
		if strings.Contains(address, "://") {
			return "", "", fmt.Errorf("DOCKER_HOST %q: invalid Unix socket address", host)
		}
		if address == "" {
			address = "/var/run/docker.sock"
		}
		return "unix://" + address, "unix", nil
	default:
		return "", "", fmt.Errorf("DOCKER_HOST %q: unsupported transport %q (use unix:// or tcp://)", host, protocol)
	}
}

func parseDockerTCPAddress(address string) (string, error) {
	if address == "" {
		return net.JoinHostPort(dockerDefaultHost, dockerDefaultPort), nil
	}
	if strings.Contains(address, "://") {
		return "", fmt.Errorf("invalid TCP address")
	}
	if strings.HasSuffix(address, "]:") {
		address += dockerDefaultPort
	}

	u, err := url.Parse("tcp://" + address)
	if err != nil {
		return "", fmt.Errorf("invalid TCP address: %w", err)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("TCP query, fragment, and userinfo components are not supported")
	}
	host, port := u.Hostname(), u.Port()
	if host == "" {
		host = dockerDefaultHost
	}
	if port == "" {
		port = dockerDefaultPort
	}
	// Keep Docker's exact numeric-port check: zero and out-of-range numeric
	// values are accepted here and rejected only when the client dials.
	if parsedPort, err := strconv.Atoi(port); err != nil && parsedPort == 0 {
		return "", fmt.Errorf("invalid TCP port %q", port)
	}
	return net.JoinHostPort(host, port) + u.EscapedPath(), nil
}

// SpecsFromDockerEnv reads the standard Docker client environment variables
// and returns one normalized TCP or Unix EndpointSpec. It returns ok=false only
// when DOCKER_HOST is absent; a present invalid or unsupported value is an
// error so startup cannot silently route to a different daemon.
func SpecsFromDockerEnv(lookupEnv func(string) (string, bool)) (EndpointSpec, bool, error) {
	rawHost, present := lookupEnv("DOCKER_HOST")
	if !present {
		return EndpointSpec{}, false, nil
	}
	normalizedHost, network, err := parseDockerHost(rawHost)
	if err != nil {
		return EndpointSpec{}, false, err
	}
	if network == "unix" {
		return EndpointSpec{Address: normalizedHost}, true, nil
	}

	spec := EndpointSpec{Address: normalizedHost}
	tlsValue, _ := lookupEnv("DOCKER_TLS")
	tlsVerifyValue, _ := lookupEnv("DOCKER_TLS_VERIFY")
	tlsEnabled := tlsValue != ""
	tlsVerify := tlsVerifyValue != ""
	if tlsEnabled || tlsVerify {
		certPath, err := dockerCertificateDirectory(lookupEnv)
		if err != nil {
			return EndpointSpec{}, false, err
		}
		spec.CAFile = filepath.Join(certPath, "ca.pem")
		certFile := filepath.Join(certPath, "cert.pem")
		keyFile := filepath.Join(certPath, "key.pem")
		certPresent := dockerOptionalFilePresent(certFile)
		keyPresent := dockerOptionalFilePresent(keyFile)
		if certPresent && keyPresent {
			spec.CertFile = certFile
			spec.KeyFile = keyFile
		} else if certPresent {
			if _, err := os.ReadFile(certFile); err != nil { // #nosec G304 -- the Docker client certificate directory is explicit operator configuration.
				return EndpointSpec{}, false, fmt.Errorf("reading Docker client certificate: %w", err)
			}
		} else if keyPresent {
			if _, err := os.ReadFile(keyFile); err != nil { // #nosec G304 -- the Docker client certificate directory is explicit operator configuration.
				return EndpointSpec{}, false, fmt.Errorf("reading Docker client key: %w", err)
			}
		}
	}
	if tlsEnabled && !tlsVerify {
		// Like Docker CLI's --tls flag, any non-empty DOCKER_TLS value enables
		// encrypted transport without server verification. DOCKER_TLS_VERIFY
		// takes precedence and enables verification when both are set.
		spec.InsecureSkipTLSVerify = true
	} else if !tlsVerify {
		// DOCKER_CERT_PATH only locates TLS material; it does not enable TLS.
		// With neither TLS signal present the Docker CLI uses plaintext TCP.
		spec.InsecureAllowPlainTCP = true
	}
	return spec, true, nil
}

func dockerCertificateDirectory(lookupEnv func(string) (string, bool)) (string, error) {
	if certPath, _ := lookupEnv("DOCKER_CERT_PATH"); certPath != "" {
		return certPath, nil
	}
	if configDir, _ := lookupEnv("DOCKER_CONFIG"); configDir != "" {
		return configDir, nil
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve Docker client config directory: %w", err)
	}
	return filepath.Join(homeDir, ".docker"), nil
}

func dockerOptionalFilePresent(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
