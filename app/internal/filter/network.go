package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

const maxNetworkBodyBytes = 1 << 20 // 1 MiB

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
	AllowDisconnectForce   bool
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
	allowDisconnectForce   bool
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
		allowDisconnectForce:   opts.AllowDisconnectForce,
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

	if p.allowEndpointConfig || req.EndpointConfig == nil {
		return "", nil
	}
	if endpointHasStaticIPConfig(*req.EndpointConfig) {
		return "network connect denied: endpoint static IP configuration is not allowed", nil
	}
	if strings.TrimSpace(req.EndpointConfig.MacAddress) != "" {
		return "network connect denied: endpoint MAC address is not allowed", nil
	}
	if len(req.EndpointConfig.Aliases)+len(req.EndpointConfig.Links) > 0 {
		return "network connect denied: endpoint aliases are not allowed", nil
	}
	if len(req.EndpointConfig.DriverOpts) > 0 {
		return "network connect denied: endpoint driver options are not allowed", nil
	}

	return "", nil
}

func (p networkPolicy) inspectDisconnect(logger *slog.Logger, r *http.Request, body []byte) (string, error) {
	var req networkDisconnectRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logDeferredNetworkValidation(logger, r, err)
		return "network disconnect denied: request body could not be inspected", nil
	}

	if !p.allowDisconnectForce && req.Force {
		return "network disconnect denied: force disconnect is not allowed", nil
	}
	return "", nil
}

func endpointHasStaticIPConfig(endpoint networkEndpointConfig) bool {
	if endpoint.IPAMConfig != nil {
		if strings.TrimSpace(endpoint.IPAMConfig.IPv4Address) != "" ||
			strings.TrimSpace(endpoint.IPAMConfig.IPv6Address) != "" ||
			len(endpoint.IPAMConfig.LinkLocalIPs) > 0 {
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

func isNetworkWritePath(normalizedPath string) bool {
	return normalizedPath == "/networks/create" ||
		isNetworkActionPath(normalizedPath, "connect") ||
		isNetworkActionPath(normalizedPath, "disconnect")
}

func isNetworkActionPath(normalizedPath string, action string) bool {
	if !strings.HasPrefix(normalizedPath, "/networks/") {
		return false
	}
	networkID, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/networks/"), "/")
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
	if logger == nil {
		return
	}
	logger.DebugContext(r.Context(), "network request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
}
