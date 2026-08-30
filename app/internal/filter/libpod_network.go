package filter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

const maxLibpodNetworkBodyBytes = 1 << 20 // 1 MiB

// libpodNetworkCreateRequest mirrors Podman's libnetwork/types.Network
// (go.podman.io/common's libnetwork/types package, pinned via Podman
// v5.8.1's go.sum — confirmed directly against upstream source per the
// design doc's C4 requirement). Its shape has almost nothing in common with
// Docker's networkCreateRequest: lowercase snake_case json tags, no nested
// IPAM object (subnets/options are top-level fields), and no
// Attachable/Ingress/ConfigOnly/ConfigFrom/Scope/EnableIPv4 concept at
// all — libpod networks predate and are independent of Docker's swarm mode.
// Subnets is decoded as raw messages only to detect presence (custom static
// IPAM config); its element shape is irrelevant to the gates below and
// deliberately not modeled. Kept as its own decode struct — never made
// "smart" for both shapes — per the design doc's C6/agreed-core guidance.
//
// Fields on the reused NetworkRequestBodyConfig with no libpod analog
// (allow_swarm_scope, allow_ingress, allow_attachable, allow_config_only,
// allow_config_from, allow_custom_ipam_drivers, allow_disable_ipv4) are
// simply never consulted here — see configuration.mdx's libpod_network
// section for the documented list, rather than silently reinterpreting them
// against unrelated fields. allow_endpoint_config, endpoint_config and
// allow_disconnect_force are not consulted by THIS inspector either, but
// they are not unused: they gate the libpod connect/disconnect endpoints —
// see inspectLibpodConnect and inspectLibpodDisconnect. allow_dns_servers
// runs the other way: it has no DOCKER analog and is consulted here (for
// network_dns_servers) and by inspectLibpodUpdate.
type libpodNetworkCreateRequest struct {
	Driver      string            `json:"driver"`
	Options     map[string]string `json:"options"`
	IPAMOptions map[string]string `json:"ipam_options"`
	Subnets     []json.RawMessage `json:"subnets"`
	// NetworkDNSServers is types.Network's `network_dns_servers`: the
	// resolvers every container attached to this network will use. Gated by
	// the same allow_dns_servers knob as the update endpoint's add/remove
	// pair, so the knob covers the whole per-network resolver surface rather
	// than half of it — see networkPolicy.inspectLibpodUpdate. Note the
	// spelling differs from update's: create carries the snake_case tag from
	// go.podman.io/common's types.Network, update carries the run-together
	// tag from Podman's own entities.NetworkUpdateOptions.
	NetworkDNSServers []string `json:"network_dns_servers"`
}

// libpodNetworkUpdateRequest mirrors Podman's entities.NetworkUpdateOptions
// (pkg/domain/entities/network.go:57 at v5.8.1), the body
// POST /libpod/networks/{name}/update decodes.
//
// The JSON tags are the whole reason this is a separate struct and the one
// thing a fix here can get wrong. There are TWO NetworkUpdateOptions types in
// the Podman tree with DIFFERENT tags, and only one of them ever touches the
// wire:
//
//   - entities.NetworkUpdateOptions — `adddnsservers` / `removednsservers`,
//     run together, no underscores. This is what libpod.UpdateNetwork
//     json.Decodes straight off r.Body, so this is the wire shape.
//   - libnetwork/types.NetworkUpdateOptions — `add_dns_servers` /
//     `remove_dns_servers`. Internal only: abi.ContainerEngine.NetworkUpdate
//     copies field-to-field into it AFTER decoding, so those tags are never
//     parsed from a request.
//
// encoding/json's fallback is case-insensitive but not separator-insensitive,
// so a struct tagged with the snake_case spelling would decode nothing and
// allow every DNS change. Case variants of the run-together spelling
// (`AddDNSServers`, `ADDDNSSERVERS`) do decode on Podman's side and therefore
// decode here too, at no extra cost.
type libpodNetworkUpdateRequest struct {
	AddDNSServers    []string `json:"adddnsservers"`
	RemoveDNSServers []string `json:"removednsservers"`
}

// libpodNetworkConnectRequest mirrors Podman's
// entities.NetworkConnectOptions (pkg/domain/entities/types/network.go at
// v5.8.1), the body POST /libpod/networks/{name}/connect decodes. That type
// is `Container string` plus an EMBEDDED, untagged
// go.podman.io/common/libnetwork/types.PerNetworkOptions, so the endpoint
// fields sit at the top level of the JSON object under snake_case names —
// nothing like Docker's nested {"Container","EndpointConfig":{...}}. Reading
// the Docker spelling here would find nothing and allow every connect, which
// is precisely the failure this struct exists to prevent. PerNetworkOptions
// was read at go.podman.io/common v0.67.0, the version Podman v5.8.1's
// go.mod pins directly.
//
// The five fields are decoded as the loosest type that still detects
// presence, because presence is all the gates below need and a looser type
// cannot be tricked by a spelling Podman accepts and sockguard does not:
//
//   - static_ips is []net.IP on Podman's side; net.IP implements
//     UnmarshalText, so encoding/json only ever accepts a JSON string for an
//     element, and []string sees exactly the same set of accepted documents.
//   - static_mac is types.HardwareAddr, whose UnmarshalJSON first tries
//     net.ParseMAC on a string and then FALLS BACK to a plain []byte decode.
//     That admits canonical strings, base64 strings, and JSON byte arrays;
//     libpodHardwareAddr mirrors all three so the policy never accepts fewer
//     wire shapes than Podman does.
//   - options is Podman's per-container driver-option map, the libpod
//     analog of Docker EndpointSettings.DriverOpts.
//
// A body Podman itself would reject (a non-string static_ips element, or a
// malformed/out-of-range static_mac representation) fails to decode here too
// and is denied as uninspectable rather than forwarded, so the loose typing
// never widens what gets through.
//
// interface_name is decoded but deliberately not gated: it names the
// interface inside the container's own network namespace, has no Docker
// EndpointSettings analog for the shared gate to reuse, and carries no
// host-side privilege — gating it would break `podman network connect
// --interface-name` for no security gain. It is modeled so a future gate has
// somewhere to attach, following the same "only gate what has an analog"
// rule libpodNetworkCreateRequest documents.
type libpodNetworkConnectRequest struct {
	StaticIPs     []string           `json:"static_ips"`
	Aliases       []string           `json:"aliases"`
	StaticMAC     libpodHardwareAddr `json:"static_mac"`
	InterfaceName string             `json:"interface_name"`
	Options       map[string]string  `json:"options"`
}

// libpodHardwareAddr mirrors go.podman.io/common v0.67.0's
// types.HardwareAddr.UnmarshalJSON without importing Podman's dependency tree
// into the request hot path. Sockguard needs only presence after validation,
// but it must accept exactly the wire shapes Podman accepts: a parseable MAC
// string, a base64 string accepted by encoding/json's []byte decoder, a JSON
// byte array, or null. Invalid strings, objects, and byte values outside
// 0..255 return an error and therefore fail closed in inspectLibpodConnect.
type libpodHardwareAddr []byte

func (h *libpodHardwareAddr) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*h = nil
		return nil
	}
	if data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err == nil {
			if parsed, err := net.ParseMAC(value); err == nil {
				*h = libpodHardwareAddr(parsed)
				return nil
			}
		}
	}

	value := make([]byte, 0, 6)
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*h = libpodHardwareAddr(value)
	return nil
}

// toEndpointConfig projects the libpod connect body onto Docker's
// EndpointSettings shape so both API families run through the single
// denyEndpointConfigReason gate instead of each keeping its own copy of the
// allow_endpoint_config / endpoint_config precedence rules. The mapping is
// the inverse of what Podman's own compat.Connect handler does when it
// lowers Docker's EndpointConfig into PerNetworkOptions (verified against
// v5.8.1's pkg/api/handlers/compat/networks.go): it funnels
// EndpointConfig.IPAddress and IPAMConfig.IPv4Address/IPv6Address into
// StaticIPs, MacAddress into StaticMAC, and Aliases into Aliases, which is
// exactly the correspondence relied on here.
//
// Three Docker fields have no libpod counterpart and stay zero, so their
// gates simply never fire on this path: Links and GwPriority do not exist in
// PerNetworkOptions at all, and IPAMConfig.LinkLocalIPs (allow_link_local_ips)
// has no libpod equivalent either — Podman's compat handler drops it rather
// than lowering it, so it is unreachable from either spelling.
func (req libpodNetworkConnectRequest) toEndpointConfig() networkEndpointConfig {
	endpoint := networkEndpointConfig{
		Aliases: req.Aliases,
	}
	if len(req.StaticMAC) > 0 {
		// denyEndpointConfigReason needs presence, not the caller's binary
		// representation. A stable non-empty sentinel gives every accepted
		// HardwareAddr wire shape the same policy decision.
		endpoint.MacAddress = "configured"
	}
	for _, staticIP := range req.StaticIPs {
		if strings.TrimSpace(staticIP) != "" {
			endpoint.IPAddress = staticIP
			break
		}
	}
	if len(req.Options) > 0 {
		endpoint.DriverOpts = make(map[string]any, len(req.Options))
		for key, value := range req.Options {
			endpoint.DriverOpts[key] = value
		}
	}
	return endpoint
}

// inspectLibpod is the single entry point compileRuntimePolicy routes every
// libpod network write through, mirroring how networkPolicy.inspect covers
// the whole Docker-compat /networks write surface from one entry. One
// predicate (isLibpodNetworkWritePath) decides membership and one switch
// picks the sub-shape, so adding a libpod network write cannot leave a
// second, quietly narrower path list behind in the middleware table.
func (p networkPolicy) inspectLibpod(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	switch {
	case normalizedPath == libpodPathPrefix+"networks/create":
		return p.inspectLibpodCreate(logger, r, normalizedPath)
	case isLibpodNetworkConnectPath(normalizedPath):
		return p.inspectLibpodConnect(logger, r, normalizedPath)
	case isLibpodNetworkDisconnectPath(normalizedPath):
		return p.inspectLibpodDisconnect(logger, r, normalizedPath)
	case isLibpodNetworkUpdatePath(normalizedPath):
		return p.inspectLibpodUpdate(logger, r, normalizedPath)
	default:
		return "", nil
	}
}

// isLibpodNetworkWritePath is the libpod counterpart of isNetworkWritePath:
// the complete set of libpod network endpoints that carry a request body
// sockguard inspects.
func isLibpodNetworkWritePath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"networks/create" ||
		isLibpodNetworkConnectPath(normalizedPath) ||
		isLibpodNetworkDisconnectPath(normalizedPath) ||
		isLibpodNetworkUpdatePath(normalizedPath)
}

// inspectLibpodConnect gates POST /libpod/networks/{name}/connect on the same
// allow_endpoint_config / endpoint_config posture that already governs
// Docker's POST /networks/{id}/connect, reading libpod's own body shape (see
// libpodNetworkConnectRequest) and then handing the projection to the shared
// denyEndpointConfigReason. Podman serves both spellings from one socket, so
// leaving this one uninspected let a client that speaks libpod pin a static
// IP or MAC that the identical operator policy denied over the Docker-compat
// path.
func (p networkPolicy) inspectLibpodConnect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	body, err := p.readLibpodNetworkBody(r, normalizedPath, isLibpodNetworkConnectPath, "libpod network connect")
	if err != nil || len(body) == 0 {
		return "", err
	}

	var req libpodNetworkConnectRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "libpod network connect request body could not be decoded for Sockguard policy inspection; deferring to Podman validation", err)
		return "libpod network connect denied: request body could not be inspected", nil
	}

	return denyEndpointConfigReason(req.toEndpointConfig(), p.allowEndpointConfig, p.endpointConfig, "libpod network connect"), nil
}

// inspectLibpodDisconnect gates POST /libpod/networks/{name}/disconnect on
// allow_disconnect_force. Podman registers this route on the Docker-compat
// compat.Disconnect handler, which decodes docker/api/types/network's
// DisconnectOptions — the exact struct networkDisconnectRequest already
// models — so the decode struct and the gate are both reused verbatim and
// only the denial subject differs.
func (p networkPolicy) inspectLibpodDisconnect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	body, err := p.readLibpodNetworkBody(r, normalizedPath, isLibpodNetworkDisconnectPath, "libpod network disconnect")
	if err != nil || len(body) == 0 {
		return "", err
	}

	var req networkDisconnectRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "libpod network disconnect request body could not be decoded for Sockguard policy inspection; deferring to Podman validation", err)
		return "libpod network disconnect denied: request body could not be inspected", nil
	}

	return p.denyDisconnectReason(req, "libpod network disconnect"), nil
}

// inspectLibpodUpdate gates POST /libpod/networks/{name}/update on
// allow_dns_servers. The endpoint has no Docker analog at all — the Engine
// API has no network-update route at any version — so this is not a
// Docker/libpod parity fix like connect and disconnect were, but a surface
// that had no inspector on either side because only one side has it.
//
// It is inspected rather than documented-and-acknowledged for three reasons.
// The primitive is retroactive: ic.NetworkUpdate rewrites the resolver list
// on an EXISTING network, so every container already attached to it starts
// resolving names through whatever the caller supplied, including containers
// the caller does not own and did not create. That is strictly more
// far-reaching than anything allow_endpoint_config gates, which only ever
// affects the one endpoint being attached. The body is also two string
// arrays, so the "sockguard cannot model this shape" argument that puts
// play/kube behind insecure_allow_body_blind_writes simply does not apply —
// an acknowledgment where a decode struct suffices is the weaker control.
// And there is no legitimate caller to break: no Docker-compat client can
// reach the route, and none of the tools sockguard ships presets for issues
// it. It is a `podman network update` admin operation, so a fail-closed
// default costs nothing operationally.
//
// RemoveDNSServers is gated alongside AddDNSServers rather than treated as
// the benign direction. Dropping a resolver is a change to shared state that
// affects containers the caller does not own just as adding one does, and it
// can redirect by omission — removing the entry that was answering a name
// falls resolution through to whatever is next in the list. A body carrying
// neither field is allowed: Podman applies two nil slices and the network is
// left exactly as it was, so there is nothing to gate.
func (p networkPolicy) inspectLibpodUpdate(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	body, err := p.readLibpodNetworkBody(r, normalizedPath, isLibpodNetworkUpdatePath, "libpod network update")
	if err != nil || len(body) == 0 {
		return "", err
	}

	var req libpodNetworkUpdateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "libpod network update request body could not be decoded for Sockguard policy inspection; deferring to Podman validation", err)
		return "libpod network update denied: request body could not be inspected", nil
	}

	if p.allowDNSServers {
		return "", nil
	}
	if len(req.AddDNSServers) > 0 {
		return "libpod network update denied: setting custom DNS servers is not allowed", nil
	}
	if len(req.RemoveDNSServers) > 0 {
		return "libpod network update denied: removing custom DNS servers is not allowed", nil
	}
	return "", nil
}

// readLibpodNetworkBody applies the shared method/path/body guard and the
// maxLibpodNetworkBodyBytes bound for the libpod connect and disconnect
// inspectors. A non-matching request or an empty body yields (nil, nil), and
// the caller then allows: Podman's handlers json.Decode straight off r.Body
// and fail the request themselves when there is nothing to decode, so there
// is no allow to leak here.
func (p networkPolicy) readLibpodNetworkBody(r *http.Request, normalizedPath string, matches func(string) bool, subject string) ([]byte, error) {
	if r == nil || r.Method != http.MethodPost || r.Body == nil || !matches(normalizedPath) {
		return nil, nil
	}

	body, err := readBoundedBody(r, maxLibpodNetworkBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return nil, newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("%s denied: request body exceeds %d byte limit", subject, maxLibpodNetworkBodyBytes))
		}
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

// inspectLibpodCreate is networkPolicy's libpod-path counterpart to
// inspectCreate: config reused verbatim under the libpod_network key
// (#148), narrowed to the gates that have a libpod analog (see
// libpodNetworkCreateRequest's doc comment).
func (p networkPolicy) inspectLibpodCreate(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != libpodPathPrefix+"networks/create" || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxLibpodNetworkBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("libpod network create denied: request body exceeds %d byte limit", maxLibpodNetworkBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req libpodNetworkCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "libpod network create request body could not be decoded for Sockguard policy inspection; deferring to Podman validation", err)
		return "libpod network create denied: request body could not be inspected", nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !isBuiltinNetworkDriver(driver) && !p.allowCustomDrivers {
		return fmt.Sprintf("libpod network create denied: driver %q is not allowed", driver), nil
	}
	if !p.allowDriverOptions && len(req.Options) > 0 {
		return "libpod network create denied: driver options are not allowed", nil
	}
	if !p.allowCustomIPAMConfig && len(req.Subnets) > 0 {
		return "libpod network create denied: custom subnet configuration is not allowed", nil
	}
	if !p.allowIPAMOptions && len(req.IPAMOptions) > 0 {
		return "libpod network create denied: IPAM options are not allowed", nil
	}
	if !p.allowDNSServers && len(req.NetworkDNSServers) > 0 {
		return "libpod network create denied: custom DNS servers are not allowed", nil
	}

	return "", nil
}
