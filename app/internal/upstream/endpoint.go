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
	"net/url"
	"os"
	"path/filepath"
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
	return scheme + "://" + e.Address
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
	// TLSSystemRoots requests verified TLS using the host's system root CA pool
	// and no client certificate — the server-authentication-only case produced
	// by DOCKER_TLS_VERIFY with no DOCKER_CERT_PATH. It makes a tcp:// endpoint
	// valid without any explicit CA/cert/key material (the CA defaults to the
	// system roots). Not exposed as a YAML knob; it only originates from the
	// DOCKER_* environment drop-in.
	TLSSystemRoots bool
}

// BuildEndpoint parses spec.Address, loads any TLS material, and returns a
// dialable Endpoint. It returns a descriptive error for every malformed or
// inconsistent spec so config validation can surface the exact problem.
func BuildEndpoint(spec EndpointSpec) (Endpoint, error) {
	network, address, err := parseAddress(spec.Address)
	if err != nil {
		return Endpoint{}, err
	}

	switch network {
	case "unix":
		// TLS material on a unix endpoint is meaningless and almost always a
		// copy-paste mistake — reject it rather than silently ignore.
		if spec.CertFile != "" || spec.KeyFile != "" || spec.CAFile != "" {
			return Endpoint{}, fmt.Errorf("upstream endpoint %q: TLS settings are not valid for a unix socket", spec.Address)
		}
		return Endpoint{Name: address, Network: "unix", Address: address}, nil
	case "tcp":
		tlsConfig, err := buildClientTLS(spec, address)
		if err != nil {
			return Endpoint{}, err
		}
		return Endpoint{Name: address, Network: "tcp", Address: address, TLSConfig: tlsConfig}, nil
	default:
		return Endpoint{}, fmt.Errorf("upstream endpoint %q: unsupported scheme %q (use unix:// or tcp://)", spec.Address, network)
	}
}

// ValidateSpec checks a spec's address and TLS-field consistency WITHOUT
// touching the filesystem, so config validation (including the remote
// POST /admin/validate path, where cert files may not exist on the validating
// host) can reject a malformed endpoint without loading its TLS material.
// BuildEndpoint performs the same structural checks and additionally loads the
// referenced files.
func ValidateSpec(spec EndpointSpec) error {
	network, address, err := parseAddress(spec.Address)
	if err != nil {
		return err
	}
	switch network {
	case "unix":
		if spec.CertFile != "" || spec.KeyFile != "" || spec.CAFile != "" {
			return fmt.Errorf("upstream endpoint %q: TLS settings are not valid for a unix socket", spec.Address)
		}
		return nil
	case "tcp":
		if (spec.CertFile == "") != (spec.KeyFile == "") {
			return fmt.Errorf("upstream endpoint %q: tls.cert_file and tls.key_file must be set together", spec.Address)
		}
		hasAnyTLS := spec.CertFile != "" || spec.KeyFile != "" || spec.CAFile != "" || spec.InsecureSkipTLSVerify || spec.TLSSystemRoots
		if !hasAnyTLS && !spec.InsecureAllowPlainTCP {
			return fmt.Errorf("upstream endpoint %q: TCP requires TLS (set tls.ca_file/cert_file/key_file) or insecure_allow_plain_tcp: true", spec.Address)
		}
		_ = address
		return nil
	default:
		return fmt.Errorf("upstream endpoint %q: unsupported scheme %q (use unix:// or tcp://)", spec.Address, network)
	}
}

// parseAddress splits a Docker-style upstream address into a (network, address)
// pair. A bare path with no scheme is treated as a unix socket for backward
// compatibility with the legacy upstream.socket field.
func parseAddress(raw string) (network, address string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("upstream endpoint address is empty")
	}

	// Bare absolute or relative path with no scheme → unix socket.
	if !strings.Contains(raw, "://") {
		if strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
			return "unix", raw, nil
		}
		return "", "", fmt.Errorf("upstream endpoint %q: address must be a unix path or a unix://, tcp:// URL", raw)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("upstream endpoint %q: %w", raw, err)
	}

	switch u.Scheme {
	case "unix":
		// unix:///var/run/docker.sock → Path carries the socket path. A
		// host-form unix://relative.sock is rejected as ambiguous.
		if u.Host != "" {
			return "", "", fmt.Errorf("upstream endpoint %q: unix sockets use an absolute path (unix:///var/run/docker.sock)", raw)
		}
		if u.Path == "" {
			return "", "", fmt.Errorf("upstream endpoint %q: missing socket path", raw)
		}
		return "unix", u.Path, nil
	case "tcp", "http", "https":
		if u.Host == "" {
			return "", "", fmt.Errorf("upstream endpoint %q: missing host:port", raw)
		}
		host := u.Host
		if u.Port() == "" {
			return "", "", fmt.Errorf("upstream endpoint %q: TCP address must include a port (e.g. tcp://host:2376)", raw)
		}
		return "tcp", host, nil
	default:
		return "", "", fmt.Errorf("upstream endpoint %q: unsupported scheme %q (use unix:// or tcp://)", raw, u.Scheme)
	}
}

// buildClientTLS constructs the *tls.Config used to dial a remote daemon. It
// returns nil only when plaintext TCP is explicitly acknowledged.
func buildClientTLS(spec EndpointSpec, address string) (*tls.Config, error) {
	hasCert := spec.CertFile != "" || spec.KeyFile != ""
	hasAnyTLS := hasCert || spec.CAFile != "" || spec.InsecureSkipTLSVerify || spec.TLSSystemRoots

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
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
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

// SpecsFromDockerEnv reads the standard Docker client environment variables
// (DOCKER_HOST, DOCKER_TLS_VERIFY, DOCKER_CERT_PATH) and returns a single
// EndpointSpec when DOCKER_HOST names a TCP daemon, so an operator with a
// working `docker -H tcp://…` setup can point sockguard at it with no YAML.
// It returns ok=false when DOCKER_HOST is unset or names a unix socket (the
// local-socket default already covers that case).
func SpecsFromDockerEnv(getenv func(string) string) (EndpointSpec, bool) {
	host := strings.TrimSpace(getenv("DOCKER_HOST"))
	if host == "" {
		return EndpointSpec{}, false
	}
	network, _, err := parseAddress(host)
	if err != nil || network != "tcp" {
		return EndpointSpec{}, false
	}

	spec := EndpointSpec{Address: host}
	tlsVerify := getenv("DOCKER_TLS_VERIFY") != ""
	certPath := strings.TrimSpace(getenv("DOCKER_CERT_PATH"))
	if certPath != "" {
		spec.CAFile = filepath.Join(certPath, "ca.pem")
		spec.CertFile = filepath.Join(certPath, "cert.pem")
		spec.KeyFile = filepath.Join(certPath, "key.pem")
	}
	switch {
	case tlsVerify && certPath == "":
		// DOCKER_TLS_VERIFY with no DOCKER_CERT_PATH: verify the daemon against
		// the system root CAs and present no client cert (server-auth only).
		// Without this signal the spec would carry no TLS material and be
		// rejected as plain TCP, breaking the documented env drop-in.
		spec.TLSSystemRoots = true
	case !tlsVerify && certPath == "":
		// No verification and no cert material → plaintext TCP, matching the
		// docker CLI when neither TLS env var is set.
		spec.InsecureAllowPlainTCP = true
	case !tlsVerify && certPath != "":
		// Cert material present but verification off → encrypted, unverified.
		spec.InsecureSkipTLSVerify = true
	}
	// tlsVerify && certPath != "" → verified mTLS loaded from the cert files,
	// no insecure flag needed.
	return spec, true
}
