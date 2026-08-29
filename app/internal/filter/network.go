package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

const maxNetworkBodyBytes = 1 << 20 // 1 MiB

// EndpointConfigOptions narrows AllowEndpointConfig into independent
// per-field gates on Docker's EndpointSettings object (#186), so an operator
// can admit a benign field (e.g. Aliases) without also admitting address
// pinning. Only consulted when AllowEndpointConfig is false — see
// denyEndpointConfigReason's precedence doc comment. Fields with no gate
// here (Links, DriverOpts) have no individual escape hatch: only
// AllowEndpointConfig: true can admit them, fail-closed by design.
type EndpointConfigOptions struct {
	// AllowStaticAddressing permits every field endpointHasStaticAddressFields
	// checks: IPAMConfig.IPv4Address/IPv6Address and the deprecated top-level
	// Gateway/IPAddress/IPPrefixLen/IPv6Gateway/GlobalIPv6Address/
	// GlobalIPv6PrefixLen fields. Default false.
	AllowStaticAddressing bool
	// AllowLinkLocalIPs permits IPAMConfig.LinkLocalIPs, independent of
	// AllowStaticAddressing. Default false.
	AllowLinkLocalIPs bool
	// AllowMACPinning permits MacAddress — shared by network connect's
	// EndpointConfig and container-create's deprecated top-level MacAddress
	// field (see container_create.go's denyRootMacAddressReason). Default false.
	AllowMACPinning bool
	// AllowGwPriority permits GwPriority (Engine API 1.55+). Default false.
	AllowGwPriority bool
	// DenyAliases denies Aliases when true. Inverted polarity (unlike every
	// other field here) so a zero-value EndpointConfigOptions reproduces the
	// historical, unconditional "Aliases always allowed" behavior exactly —
	// see denyEndpointConfigReason's doc comment for why Aliases is never
	// gated by default. config.EndpointConfigRequestBodyConfig exposes this
	// to operators as allow_aliases (default true) and inverts it during
	// ToFilterOptions.
	DenyAliases bool
}

// NetworkOptions configures request-body policy checks for network write endpoints.
type NetworkOptions struct {
	AllowCustomDrivers     bool
	AllowSwarmScope        bool
	AllowIngress           bool
	AllowAttachable        bool
	AllowConfigOnly        bool
	AllowConfigFrom        bool
	AllowCustomIPAMDrivers bool
	AllowCustomIPAMConfig  bool
	AllowIPAMOptions       bool
	AllowDriverOptions     bool
	AllowEndpointConfig    bool
	// EndpointConfig narrows AllowEndpointConfig into per-field gates (#186).
	// Only consulted when AllowEndpointConfig is false.
	EndpointConfig       EndpointConfigOptions
	AllowDisconnectForce bool
	// AllowDisableIPv4 permits POST /networks/create with EnableIPv4
	// explicitly false (Engine API 1.48+). Default false.
	AllowDisableIPv4 bool
}

type networkPolicy struct {
	allowCustomDrivers     bool
	allowSwarmScope        bool
	allowIngress           bool
	allowAttachable        bool
	allowConfigOnly        bool
	allowConfigFrom        bool
	allowCustomIPAMDrivers bool
	allowCustomIPAMConfig  bool
	allowIPAMOptions       bool
	allowDriverOptions     bool
	allowEndpointConfig    bool
	endpointConfig         EndpointConfigOptions
	allowDisconnectForce   bool
	allowDisableIPv4       bool
}

type networkCreateRequest struct {
	Driver     string             `json:"Driver"`
	Scope      string             `json:"Scope"`
	Attachable bool               `json:"Attachable"`
	Ingress    bool               `json:"Ingress"`
	ConfigOnly bool               `json:"ConfigOnly"`
	ConfigFrom *networkConfigFrom `json:"ConfigFrom"`
	IPAM       *networkIPAM       `json:"IPAM"`
	Options    map[string]any     `json:"Options"`
	// EnableIPv4 (Engine API 1.48+) defaults to true when absent; an explicit
	// false disables IPv4 addressing on the network. A pointer distinguishes
	// "not set" from "explicitly false".
	EnableIPv4 *bool `json:"EnableIPv4"`
}

type networkConfigFrom struct {
	Network string `json:"Network"`
}

type networkIPAM struct {
	Driver  string         `json:"Driver"`
	Config  []any          `json:"Config"`
	Options map[string]any `json:"Options"`
}

type networkConnectRequest struct {
	EndpointConfig *networkEndpointConfig `json:"EndpointConfig"`
}

type networkEndpointConfig struct {
	IPAMConfig          *networkEndpointIPAMConfig `json:"IPAMConfig"`
	Links               []string                   `json:"Links"`
	Aliases             []string                   `json:"Aliases"`
	Gateway             string                     `json:"Gateway"`
	IPAddress           string                     `json:"IPAddress"`
	IPPrefixLen         int                        `json:"IPPrefixLen"`
	IPv6Gateway         string                     `json:"IPv6Gateway"`
	GlobalIPv6Address   string                     `json:"GlobalIPv6Address"`
	GlobalIPv6PrefixLen int                        `json:"GlobalIPv6PrefixLen"`
	MacAddress          string                     `json:"MacAddress"`
	DriverOpts          map[string]any             `json:"DriverOpts"`
	// GwPriority (Engine API 1.45+) selects which network provides the
	// container's default gateway when it is attached to more than one.
	// Gated by the same allow_endpoint_config posture as the other
	// endpoint-config fields — see denyEndpointConfigReason.
	GwPriority int `json:"GwPriority"`
}

type networkEndpointIPAMConfig struct {
	IPv4Address  string   `json:"IPv4Address"`
	IPv6Address  string   `json:"IPv6Address"`
	LinkLocalIPs []string `json:"LinkLocalIPs"`
}

type networkDisconnectRequest struct {
	Force bool `json:"Force"`
}

func newNetworkPolicy(opts NetworkOptions) networkPolicy {
	return networkPolicy{
		allowCustomDrivers:     opts.AllowCustomDrivers,
		allowSwarmScope:        opts.AllowSwarmScope,
		allowIngress:           opts.AllowIngress,
		allowAttachable:        opts.AllowAttachable,
		allowConfigOnly:        opts.AllowConfigOnly,
		allowConfigFrom:        opts.AllowConfigFrom,
		allowCustomIPAMDrivers: opts.AllowCustomIPAMDrivers,
		allowCustomIPAMConfig:  opts.AllowCustomIPAMConfig,
		allowIPAMOptions:       opts.AllowIPAMOptions,
		allowDriverOptions:     opts.AllowDriverOptions,
		allowEndpointConfig:    opts.AllowEndpointConfig,
		endpointConfig:         opts.EndpointConfig,
		allowDisconnectForce:   opts.AllowDisconnectForce,
		allowDisableIPv4:       opts.AllowDisableIPv4,
	}
}

func (p networkPolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || r.Body == nil || !isNetworkWritePath(normalizedPath) {
		return "", nil
	}

	body, err := readBoundedBody(r, maxNetworkBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("network denied: request body exceeds %d byte limit", maxNetworkBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	switch {
	case normalizedPath == "/networks/create":
		return p.inspectCreate(logger, r, body)
	case isNetworkActionPath(normalizedPath, "connect"):
		return p.inspectConnect(logger, r, body)
	case isNetworkActionPath(normalizedPath, "disconnect"):
		return p.inspectDisconnect(logger, r, body)
	default:
		return "", nil
	}
}

func (p networkPolicy) inspectCreate(logger *slog.Logger, r *http.Request, body []byte) (string, error) {
	var req networkCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logDeferredNetworkValidation(logger, r, err)
		return "network create denied: request body could not be inspected", nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !isBuiltinNetworkDriver(driver) && !p.allowCustomDrivers {
		return fmt.Sprintf("network create denied: driver %q is not allowed", driver), nil
	}
	if !p.allowSwarmScope && strings.EqualFold(strings.TrimSpace(req.Scope), "swarm") {
		return "network create denied: swarm scope is not allowed", nil
	}
	if !p.allowIngress && req.Ingress {
		return "network create denied: ingress networks are not allowed", nil
	}
	if !p.allowAttachable && req.Attachable {
		return "network create denied: attachable networks are not allowed", nil
	}
	if !p.allowConfigOnly && req.ConfigOnly {
		return "network create denied: config-only networks are not allowed", nil
	}
	if !p.allowConfigFrom && req.ConfigFrom != nil {
		return "network create denied: config-from networks are not allowed", nil
	}
	if denyReason := p.denyCreateIPAMReason(req.IPAM); denyReason != "" {
		return denyReason, nil
	}
	if !p.allowDriverOptions && len(req.Options) > 0 {
		return "network create denied: driver options are not allowed", nil
	}
	if req.EnableIPv4 != nil && !*req.EnableIPv4 && !p.allowDisableIPv4 {
		return "network create denied: disabling IPv4 (EnableIPv4: false) is not allowed", nil
	}

	return "", nil
}

func (p networkPolicy) denyCreateIPAMReason(ipam *networkIPAM) string {
	if ipam == nil {
		return ""
	}
	if driver := strings.TrimSpace(ipam.Driver); driver != "" && !isBuiltinIPAMDriver(driver) && !p.allowCustomIPAMDrivers {
		return fmt.Sprintf("network create denied: IPAM driver %q is not allowed", driver)
	}
	if !p.allowCustomIPAMConfig && len(ipam.Config) > 0 {
		return "network create denied: custom IPAM config is not allowed"
	}
	if !p.allowIPAMOptions && len(ipam.Options) > 0 {
		return "network create denied: IPAM options are not allowed"
	}
	return ""
}

func (p networkPolicy) inspectConnect(logger *slog.Logger, r *http.Request, body []byte) (string, error) {
	var req networkConnectRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logDeferredNetworkValidation(logger, r, err)
		return "network connect denied: request body could not be inspected", nil
	}

	if req.EndpointConfig == nil {
		return "", nil
	}
	if reason := denyEndpointConfigReason(*req.EndpointConfig, p.allowEndpointConfig, p.endpointConfig, "network connect"); reason != "" {
		return reason, nil
	}

	return "", nil
}

// denyEndpointConfigReason evaluates a single Docker network endpoint config
// (EndpointSettings) against the allow_endpoint_config / endpoint_config
// policy, returning a "<subject> denied: ..." message (or "" when allowed).
// subject distinguishes the calling context in the denial grammar —
// "network connect" for POST /networks/*/connect, "container create" for the
// primary/extra networks carried in POST /containers/create's
// NetworkingConfig.EndpointsConfig — mirroring the subject-prefixed pattern
// capabilityAddDenyReason already uses to share a check between
// container-create and service inspection.
//
// Precedence (#186): allow (AllowEndpointConfig) is the legacy whole-object
// escape hatch and, when true, always wins — every field is admitted and
// granular is not consulted at all (config validation rejects a config that
// sets both, so this is never an operator surprise in practice). When allow
// is false, granular applies per field: AllowStaticAddressing,
// AllowLinkLocalIPs, AllowMACPinning, and AllowGwPriority each gate their own
// field independently. Links and DriverOpts have no granular field of their
// own — with allow false they are always denied, fail-closed, regardless of
// granular's other settings; only allow=true can admit them.
//
// Aliases are gated by granular.DenyAliases, which defaults false (allowed)
// so the historical, unconditional-allow behavior is preserved when granular
// is left at its zero value: Docker Compose sets Aliases: [serviceName] on
// every endpoint it creates, so gating aliases by default broke every
// multi-network Compose recreate. Aliases were also never enforced on
// container-create's primary network (the only inspector that previously
// existed), so gating them only at connect was a bypassable, low-value
// control rather than a real guarantee. An operator who genuinely wants
// Aliases denied can now do so explicitly via endpoint_config.allow_aliases:
// false. Links remains unconditionally gated — joining another container's
// linked alias namespace is a materially different, higher-privilege
// primitive than an Aliases DNS name.
func denyEndpointConfigReason(ep networkEndpointConfig, allow bool, granular EndpointConfigOptions, subject string) string {
	if allow {
		return ""
	}
	if !granular.AllowStaticAddressing && endpointHasStaticAddressFields(ep) {
		return fmt.Sprintf("%s denied: endpoint static IP configuration is not allowed", subject)
	}
	if !granular.AllowLinkLocalIPs && endpointHasLinkLocalIPs(ep) {
		return fmt.Sprintf("%s denied: endpoint link-local IP addresses are not allowed", subject)
	}
	if !granular.AllowMACPinning && strings.TrimSpace(ep.MacAddress) != "" {
		return fmt.Sprintf("%s denied: endpoint MAC address is not allowed", subject)
	}
	if len(ep.Links) > 0 {
		return fmt.Sprintf("%s denied: endpoint links are not allowed", subject)
	}
	if len(ep.DriverOpts) > 0 {
		return fmt.Sprintf("%s denied: endpoint driver options are not allowed", subject)
	}
	if !granular.AllowGwPriority && ep.GwPriority != 0 {
		return fmt.Sprintf("%s denied: endpoint gateway priority is not allowed", subject)
	}
	if granular.DenyAliases && len(ep.Aliases) > 0 {
		return fmt.Sprintf("%s denied: endpoint aliases are not allowed", subject)
	}
	return ""
}

func (p networkPolicy) inspectDisconnect(logger *slog.Logger, r *http.Request, body []byte) (string, error) {
	var req networkDisconnectRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logDeferredNetworkValidation(logger, r, err)
		return "network disconnect denied: request body could not be inspected", nil
	}

	return p.denyDisconnectReason(req, "network disconnect"), nil
}

// denyDisconnectReason evaluates a decoded disconnect body against
// allow_disconnect_force, returning a "<subject> denied: ..." message (or ""
// when allowed). Subject-prefixed and shared for the same reason
// denyEndpointConfigReason is: Podman routes POST
// /libpod/networks/{name}/disconnect at the identical compat.Disconnect
// handler and decodes the identical Docker struct
// (github.com/docker/docker/api/types/network.DisconnectOptions, verified
// against Podman v5.8.1's pkg/api/server/register_networks.go and
// pkg/api/handlers/compat/networks.go), so one gate must govern both
// spellings or the libpod one drifts open.
func (p networkPolicy) denyDisconnectReason(req networkDisconnectRequest, subject string) string {
	if !p.allowDisconnectForce && req.Force {
		return fmt.Sprintf("%s denied: force disconnect is not allowed", subject)
	}
	return ""
}

// endpointHasStaticIPConfig reports whether endpoint carries any static
// address configuration at all — either the "address" fields
// (endpointHasStaticAddressFields) or IPAMConfig.LinkLocalIPs
// (endpointHasLinkLocalIPs). Kept as the combined predicate for callers (and
// mutation-kill tests) that predate the #186 per-field split; the granular
// denyEndpointConfigReason path consults the two halves independently so
// AllowStaticAddressing and AllowLinkLocalIPs can be set independently.
func endpointHasStaticIPConfig(endpoint networkEndpointConfig) bool {
	return endpointHasStaticAddressFields(endpoint) || endpointHasLinkLocalIPs(endpoint)
}

// endpointHasStaticAddressFields reports whether endpoint sets a static
// IPv4/IPv6 address via IPAMConfig or the deprecated top-level
// Gateway/IPAddress/IPPrefixLen/IPv6Gateway/GlobalIPv6Address/
// GlobalIPv6PrefixLen fields — every static-addressing field except
// IPAMConfig.LinkLocalIPs, which endpointHasLinkLocalIPs covers separately.
func endpointHasStaticAddressFields(endpoint networkEndpointConfig) bool {
	if endpoint.IPAMConfig != nil {
		if strings.TrimSpace(endpoint.IPAMConfig.IPv4Address) != "" ||
			strings.TrimSpace(endpoint.IPAMConfig.IPv6Address) != "" {
			return true
		}
	}

	return strings.TrimSpace(endpoint.Gateway) != "" ||
		strings.TrimSpace(endpoint.IPAddress) != "" ||
		endpoint.IPPrefixLen != 0 ||
		strings.TrimSpace(endpoint.IPv6Gateway) != "" ||
		strings.TrimSpace(endpoint.GlobalIPv6Address) != "" ||
		endpoint.GlobalIPv6PrefixLen != 0
}

// endpointHasLinkLocalIPs reports whether endpoint sets IPAMConfig.LinkLocalIPs.
func endpointHasLinkLocalIPs(endpoint networkEndpointConfig) bool {
	return endpoint.IPAMConfig != nil && len(endpoint.IPAMConfig.LinkLocalIPs) > 0
}

func isNetworkWritePath(normalizedPath string) bool {
	return normalizedPath == "/networks/create" ||
		isNetworkActionPath(normalizedPath, "connect") ||
		isNetworkActionPath(normalizedPath, "disconnect")
}

func isNetworkActionPath(normalizedPath string, action string) bool {
	return isNetworkActionPathUnder("/networks/", normalizedPath, action)
}

// isNetworkActionPathUnder matches <prefix>{id}/{action}: exactly one
// non-empty identifier segment followed by action, nothing after it. The
// collection prefix is a parameter so the Docker-compat "/networks/" family
// and libpod's "/libpod/networks/" family share one implementation of the
// shape rather than each keeping its own copy — the two families are still
// mutually exclusive because prefix is matched literally, so a Docker path
// can never satisfy a libpod matcher or vice versa (see
// TestLibpodMatchersNeverMatchDockerPathsAndViceVersa). Podman routes both
// spellings with gorilla/mux's {name} placeholder, which likewise stops at
// the next slash.
func isNetworkActionPathUnder(prefix string, normalizedPath string, action string) bool {
	if !strings.HasPrefix(normalizedPath, prefix) {
		return false
	}
	networkID, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, prefix), "/")
	return ok && networkID != "" && tail == action
}

func isBuiltinNetworkDriver(driver string) bool {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "bridge", "host", "ipvlan", "macvlan", "none", "null", "overlay":
		return true
	default:
		return false
	}
}

func isBuiltinIPAMDriver(driver string) bool {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "default", "null":
		return true
	default:
		return false
	}
}

func logDeferredNetworkValidation(logger *slog.Logger, r *http.Request, err error) {
	logRequestError(logger, r, slog.LevelDebug, "network request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", err)
}
