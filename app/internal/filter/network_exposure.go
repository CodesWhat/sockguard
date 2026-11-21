package filter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// network_exposure.go holds the opt-in gates on what a create publishes and
// which networks it joins: deny_published_ports, allowed_port_host_ips and
// allowed_networks, on Docker container create, libpod container create,
// service create and update, and network connect.
//
// They sit in ResourceLimitGuard instead of the body inspectors because
// allowed_networks needs the daemon: a caller can name a network by ID or ID
// prefix, so the listed names are compared with the Name the daemon resolves
// each reference to, never with the reference itself. The guard runs after the
// inspectors, ownership and visibility, with the same per-profile policy.
//
// Undecodable bodies are forwarded without a verdict here. The inspectors
// ahead of the guard already refused them under enforce, and the daemon's own
// decoder refuses them again.

// NetworkExposureOptions are the three gates one surface carries. The zero
// value enforces nothing.
type NetworkExposureOptions struct {
	// DenyPublishedPorts refuses any published port.
	DenyPublishedPorts bool
	// AllowedPortHostIPs, when non-empty and ports are published, requires
	// every binding's host IP to be listed. An empty host IP binds every
	// interface and counts as 0.0.0.0.
	AllowedPortHostIPs []string
	// AllowedNetworks, when non-empty, requires every network joined to
	// resolve to a listed network name.
	AllowedNetworks []string
}

func (o NetworkExposureOptions) portsActive() bool {
	return o.DenyPublishedPorts || len(o.AllowedPortHostIPs) > 0
}

func (o NetworkExposureOptions) active() bool {
	return o.portsActive() || len(o.AllowedNetworks) > 0
}

// publishedBinding is one published port reduced to what the host IP gate
// reads. An empty hostIP means every interface.
type publishedBinding struct {
	hostIP string
}

// allIfacesHostIP is what an empty host IP, and a published port with no
// host IP field at all, binds.
const allIfacesHostIP = "0.0.0.0"

// normalizeHostIP parses a bind address the way the engines do (net.ParseIP:
// no padding, brackets or zone) and unmaps 4in6 so 127.0.0.1 and ::ffff:127.0.0.1
// compare equal. An empty address is the all-interfaces literal.
func normalizeHostIP(raw string) (netip.Addr, bool) {
	if raw == "" {
		raw = allIfacesHostIP
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// allowedHostIPSet normalizes the configured list. Entries that don't parse
// are skipped; config validation refuses them before they get here.
func allowedHostIPSet(entries []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(entries))
	for _, entry := range entries {
		if addr, ok := normalizeHostIP(entry); ok {
			out = append(out, addr)
		}
	}
	return out
}

// denyPublishedPortsReason returns the refusal for a set of published
// bindings, or "" when they pass. published is false when the request
// publishes nothing, which always passes.
func (o NetworkExposureOptions) denyPublishedPortsReason(subject string, published bool, bindings []publishedBinding) string {
	if !published {
		return ""
	}
	if o.DenyPublishedPorts {
		return subject + " denied: published ports are not allowed"
	}
	if len(o.AllowedPortHostIPs) == 0 {
		return ""
	}
	allowed := allowedHostIPSet(o.AllowedPortHostIPs)
	for _, binding := range bindings {
		addr, ok := normalizeHostIP(binding.hostIP)
		if !ok {
			return fmt.Sprintf("%s denied: port binding host IP %q is not a valid IP address", subject, binding.hostIP)
		}
		if !slices.Contains(allowed, addr) {
			return fmt.Sprintf("%s denied: port binding host IP %q is not in allowed_port_host_ips", subject, addr.String())
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Network references
// ---------------------------------------------------------------------------

// networkRefs is the networks one request joins, ready for resolution.
type networkRefs struct {
	// refs are names, IDs or ID prefixes the daemon resolves. They are
	// compared by resolved name, never as written.
	refs []string
	// refusal is a mode that can't be shown to stay on a listed network, such
	// as joining another container's namespace. It is refused outright.
	refusal string
	// bound maps a ref to the EndpointConfig.NetworkID sent beside it. The
	// daemon prefers that ID to the key, so it has to resolve to the same
	// network as the key.
	bound map[string]string
}

// bind records the NetworkID an endpoint carries beside its key.
func (n *networkRefs) bind(ref, networkID string) {
	networkID = strings.TrimSpace(networkID)
	if ref == "" || networkID == "" {
		return
	}
	if n.bound == nil {
		n.bound = map[string]string{}
	}
	n.bound[ref] = networkID
}

func (n *networkRefs) add(ref string) {
	if ref != "" && !slices.Contains(n.refs, ref) {
		n.refs = append(n.refs, ref)
	}
}

// dockerNetworkModeRefs classifies HostConfig.NetworkMode. "" and "default"
// are the default bridge, "none" joins nothing, "host" is the host gate's
// (see enforceNetworkRefs) and anything else names a network.
//
// container:<id> and ns:<path> join a namespace that already exists, on
// whatever network the engine put it, which the allowlist can't vouch for.
// slirp4netns and pasta are Podman's host-stack modes, no named network.
func dockerNetworkModeRefs(mode string, into *networkRefs) {
	lower := strings.ToLower(strings.TrimSpace(mode))
	switch {
	case lower == "" || lower == "default":
		into.add("bridge")
	case lower == "none":
	case lower == "host":
		into.add("host")
	case strings.HasPrefix(lower, "container:"), strings.HasPrefix(lower, "ns:"),
		lower == "slirp4netns", lower == "pasta", strings.HasPrefix(lower, "service:"):
		if into.refusal == "" {
			into.refusal = fmt.Sprintf("network mode %q joins a namespace allowed_networks can't verify", mode)
		}
	default:
		into.add(mode)
	}
}

// ---------------------------------------------------------------------------
// Port entries
// ---------------------------------------------------------------------------

// exposurePortBinding and exposurePortMapping read the host IP of one
// published port and refuse an entry holding a key beyond the real fields.
// Podman decodes with jsoniter, which for a struct of ten or fewer fields
// compares a 64-bit hash of each key, so a key this decoder treats as unknown
// could still bind to the host IP in Podman and hide a different address from
// the gate (see libpodNamespace.UnmarshalJSON). The allowed keys are the
// fields of Docker's PortBinding and Podman's PortMapping.
type exposurePortBinding struct {
	HostIP string
}

type exposurePortMapping struct {
	HostIP string
}

var (
	portBindingKeys = []string{"HostIp", "HostPort"}
	portMappingKeys = []string{"container_port", "host_ip", "host_port", "protocol", "range"}
)

func (b *exposurePortBinding) UnmarshalJSON(data []byte) error {
	ip, err := decodePortEntryHostIP(data, portBindingKeys, "HostIp")
	b.HostIP = ip
	return err
}

func (m *exposurePortMapping) UnmarshalJSON(data []byte) error {
	ip, err := decodePortEntryHostIP(data, portMappingKeys, "host_ip")
	m.HostIP = ip
	return err
}

func decodePortEntryHostIP(data []byte, allowed []string, hostIPKey string) (string, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return "", nil
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return "", fmt.Errorf("port entry: %w", err)
	}
	for key := range keys {
		if !slices.ContainsFunc(allowed, func(a string) bool { return strings.EqualFold(a, key) }) {
			return "", &portEntryKeyError{key: key}
		}
	}
	var ip string
	for key, raw := range keys {
		if strings.EqualFold(key, hostIPKey) {
			if err := json.Unmarshal(raw, &ip); err != nil {
				return "", fmt.Errorf("port entry: %w", err)
			}
		}
	}
	return ip, nil
}

// portEntryKeyError is the refusal of a port entry holding an unknown key.
type portEntryKeyError struct{ key string }

func (e *portEntryKeyError) Error() string {
	return fmt.Sprintf("port entry has unknown key %q", e.key)
}

// portEntryKeyReason returns the deny reason when err is, or wraps, a
// portEntryKeyError, and "" otherwise.
func portEntryKeyReason(subject string, err error) string {
	var keyErr *portEntryKeyError
	if !errors.As(err, &keyErr) {
		return ""
	}
	return fmt.Sprintf("%s denied: %s, so its host IP can't be read reliably", subject, keyErr.Error())
}

// denyUndecodable writes the refusal for a body whose port entry holds an
// unknown key while a port gate is set, and reports whether the request can
// carry on. Any other decode failure is forwarded: the daemon's own decoder
// refuses it.
func (g *resourceLimitGuard) denyUndecodable(w http.ResponseWriter, r *http.Request, subject string, opts NetworkExposureOptions, err error, verbosity DenyResponseVerbosity) bool {
	if !opts.portsActive() {
		return true
	}
	reason := portEntryKeyReason(subject, err)
	if reason == "" {
		return true
	}
	return !g.exposureDeny(w, r, http.StatusForbidden, reasonCodeRequestBodyPolicyDenied, reason, verbosity)
}

// ---------------------------------------------------------------------------
// Docker container create
// ---------------------------------------------------------------------------

type exposureDockerCreate struct {
	HostConfig struct {
		NetworkMode     string                           `json:"NetworkMode"`
		PublishAllPorts bool                             `json:"PublishAllPorts"`
		PortBindings    map[string][]exposurePortBinding `json:"PortBindings"`
	} `json:"HostConfig"`
	NetworkingConfig struct {
		EndpointsConfig map[string]json.RawMessage `json:"EndpointsConfig"`
	} `json:"NetworkingConfig"`
}

func (req exposureDockerCreate) ports() (bool, []publishedBinding) {
	var bindings []publishedBinding
	for _, entry := range req.HostConfig.PortBindings {
		for _, b := range entry {
			bindings = append(bindings, publishedBinding{hostIP: b.HostIP})
		}
	}
	if req.HostConfig.PublishAllPorts {
		// The engine binds every exposed port on its default address.
		bindings = append(bindings, publishedBinding{})
	}
	return len(bindings) > 0, bindings
}

// hostStackOptionsReason is the refusal for a NetworkMode that carries
// options for Podman's pasta or slirp4netns, such as "pasta:-t,0.0.0.0/8080:80".
// The options include port forwards that never appear in PortBindings, so the
// port gates can't see them. The bare modes carry no options and publish only
// through PortBindings, which are already read.
func (req exposureDockerCreate) hostStackOptionsReason() string {
	lower := strings.ToLower(strings.TrimSpace(req.HostConfig.NetworkMode))
	if strings.HasPrefix(lower, "pasta:") || strings.HasPrefix(lower, "slirp4netns:") {
		return fmt.Sprintf("network mode %q carries pasta or slirp4netns options that can publish ports the port gates can't read", req.HostConfig.NetworkMode)
	}
	return ""
}

func (req exposureDockerCreate) networks() networkRefs {
	var refs networkRefs
	dockerNetworkModeRefs(req.HostConfig.NetworkMode, &refs)
	keys := make([]string, 0, len(req.NetworkingConfig.EndpointsConfig))
	for key := range req.NetworkingConfig.EndpointsConfig {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		refs.add(key)
		var endpoint struct {
			NetworkID string `json:"NetworkID"`
		}
		if json.Unmarshal(req.NetworkingConfig.EndpointsConfig[key], &endpoint) == nil {
			refs.bind(key, endpoint.NetworkID)
		}
	}
	return refs
}

// ---------------------------------------------------------------------------
// Libpod container create
// ---------------------------------------------------------------------------

type exposureLibpodCreate struct {
	NetNS             libpodNamespace            `json:"netns"`
	Pod               string                     `json:"pod"`
	PortMappings      []exposurePortMapping      `json:"portmappings"`
	PublishImagePorts *bool                      `json:"publish_image_ports"`
	Networks          map[string]json.RawMessage `json:"networks"`
	CNINetworks       []string                   `json:"cni_networks"`
	NetworkOptions    map[string]json.RawMessage `json:"network_options"`
}

// hostStackOptionsReason is the refusal for options handed to Podman's pasta
// or slirp4netns, which can forward host ports (pasta -t 0.0.0.0/8080:80) that
// portmappings never lists. It reads network_options for either key, in any
// letter case, and a non-empty netns value for either mode. A bare pasta or
// slirp4netns publishes only through portmappings, which are already read.
func (req exposureLibpodCreate) hostStackOptionsReason() string {
	for key, raw := range req.NetworkOptions {
		if !isHostStackMode(key) {
			continue
		}
		if trimmed := strings.TrimSpace(string(raw)); trimmed != "null" && trimmed != "[]" {
			return fmt.Sprintf("network_options for %q can forward host ports the port gates can't read", key)
		}
	}
	if isHostStackMode(req.NetNS.NSMode) && strings.TrimSpace(req.NetNS.Value) != "" {
		return fmt.Sprintf("netns %q with a value can forward host ports the port gates can't read", req.NetNS.NSMode)
	}
	return ""
}

func isHostStackMode(mode string) bool {
	lower := strings.ToLower(strings.TrimSpace(mode))
	return lower == "pasta" || lower == "slirp4netns"
}

func (req exposureLibpodCreate) ports() (bool, []publishedBinding) {
	var bindings []publishedBinding
	for _, mapping := range req.PortMappings {
		bindings = append(bindings, publishedBinding{hostIP: mapping.HostIP})
	}
	if req.PublishImagePorts != nil && *req.PublishImagePorts {
		bindings = append(bindings, publishedBinding{})
	}
	return len(bindings) > 0, bindings
}

// networks reads the networks a libpod create joins. netns bridge (and the
// empty, default and private spellings Podman maps to it) joins the keys of
// networks and cni_networks, or Podman's default network when there are none.
// A pod's network namespace is the pod's, which this create doesn't set.
func (req exposureLibpodCreate) networks() networkRefs {
	var refs networkRefs
	mode := strings.ToLower(strings.TrimSpace(req.NetNS.NSMode))
	switch mode {
	case "none":
		return refs
	case "host":
		refs.add("host")
		return refs
	case "", "default", "private", "bridge":
	default:
		refs.refusal = fmt.Sprintf("network mode %q joins a namespace allowed_networks can't verify", req.NetNS.NSMode)
		return refs
	}
	if strings.TrimSpace(req.Pod) != "" {
		refs.refusal = "joining a pod shares the pod's network namespace, which allowed_networks can't verify"
		return refs
	}
	keys := make([]string, 0, len(req.Networks))
	for key := range req.Networks {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		refs.add(key)
	}
	for _, name := range req.CNINetworks {
		refs.add(name)
	}
	if len(refs.refs) == 0 {
		refs.add("podman")
	}
	return refs
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

type exposureServiceSpec struct {
	serviceNetworkTargets
	EndpointSpec *struct {
		Ports []json.RawMessage `json:"Ports"`
	} `json:"EndpointSpec"`
}

func (req exposureServiceSpec) published() int {
	if req.EndpointSpec == nil {
		return 0
	}
	return len(req.EndpointSpec.Ports)
}

// servicePortBindings has no host IP to read: an ingress port binds every
// interface on every node, and so does a host-mode port.
func servicePortBindings(count int) (bool, []publishedBinding) {
	if count == 0 {
		return false, nil
	}
	return true, []publishedBinding{{}}
}

func serviceNetworkRefs(targets []string) networkRefs {
	var refs networkRefs
	for _, target := range targets {
		refs.add(target)
	}
	return refs
}

// ---------------------------------------------------------------------------
// Guard
// ---------------------------------------------------------------------------

// exposureDeny writes a denial. A 403 honors the profile's warn and audit
// pass-through like the inspectors do; it reports whether a response was
// written, so false means the request carries on.
func (g *resourceLimitGuard) exposureDeny(w http.ResponseWriter, r *http.Request, status int, reasonCode, reason string, verbosity DenyResponseVerbosity) bool {
	return g.denyServiceNetwork(w, r, status, reasonCode, reason, verbosity)
}

// enforceNetworkRefs checks every reference against allowed. It returns false
// when a response was written.
//
// The host network never counts as allowed here. With allow_host_network off
// it is refused, however it was named, which also closes naming it by ID.
// With the host gate on, the operator opted in and the host network isn't
// held to the list.
func (g *resourceLimitGuard) enforceNetworkRefs(w http.ResponseWriter, r *http.Request, subject string, refs networkRefs, allowed []string, allowHost bool, verbosity DenyResponseVerbosity) bool {
	if len(allowed) == 0 {
		return true
	}
	if refs.refusal != "" {
		return !g.exposureDeny(w, r, http.StatusForbidden, reasonCodeRequestBodyPolicyDenied,
			fmt.Sprintf("%s denied: %s", subject, refs.refusal), verbosity)
	}
	for _, ref := range refs.refs {
		bound := refs.bound[ref]
		if strings.EqualFold(ref, "host") {
			if allowHost {
				if !g.requireSameNetwork(w, r, subject, ref, bound, NetworkInspectResult{Name: "host", Driver: "host"}, verbosity) {
					return false
				}
				continue
			}
			if g.exposureDeny(w, r, http.StatusForbidden, reasonCodeRequestBodyPolicyDenied,
				subject+" denied: host network is not allowed", verbosity) {
				return false
			}
			continue
		}
		if g.inspectNetwork == nil {
			g.exposureDeny(w, r, http.StatusBadGateway, reasonCodeRequestBodyInspectionFailed,
				subject+" denied: network verification unavailable", verbosity)
			return false
		}
		network, found, err := g.inspectNetwork(r.Context(), ref)
		if err != nil {
			logRequestError(g.logger, r, slog.LevelError, "failed to inspect network for allowed_networks", err)
			g.exposureDeny(w, r, http.StatusBadGateway, reasonCodeRequestBodyInspectionFailed,
				subject+" denied: network verification unavailable", verbosity)
			return false
		}
		if !found {
			if g.exposureDeny(w, r, http.StatusForbidden, reasonCodeRequestBodyPolicyDenied,
				fmt.Sprintf("%s denied: network %q does not exist, so it can't be shown to be in allowed_networks", subject, ref), verbosity) {
				return false
			}
			continue
		}
		if strings.EqualFold(strings.TrimSpace(network.Driver), "host") || strings.EqualFold(network.Name, "host") {
			if allowHost {
				if !g.requireSameNetwork(w, r, subject, ref, bound, network, verbosity) {
					return false
				}
				continue
			}
			if g.exposureDeny(w, r, http.StatusForbidden, reasonCodeRequestBodyPolicyDenied,
				subject+" denied: host network is not allowed", verbosity) {
				return false
			}
			continue
		}
		if !slices.Contains(allowed, network.Name) {
			if g.exposureDeny(w, r, http.StatusForbidden, reasonCodeRequestBodyPolicyDenied,
				fmt.Sprintf("%s denied: network %q is not in allowed_networks", subject, network.Name), verbosity) {
				return false
			}
			continue
		}
		if !g.requireSameNetwork(w, r, subject, ref, bound, network, verbosity) {
			return false
		}
	}
	return true
}

// requireSameNetwork checks an endpoint's NetworkID against the network its
// key resolved to. dockerd prefers EndpointConfig.NetworkID to the key, so a
// NetworkID that resolves elsewhere would join a network the key's check never
// saw. An empty NetworkID passes, and so does one that resolves to the same
// network, which is what recreate tools replay from an inspect. It returns
// false when a response was written.
func (g *resourceLimitGuard) requireSameNetwork(w http.ResponseWriter, r *http.Request, subject, key, networkID string, resolvedKey NetworkInspectResult, verbosity DenyResponseVerbosity) bool {
	if networkID == "" || networkID == key {
		return true
	}
	if g.inspectNetwork == nil {
		g.exposureDeny(w, r, http.StatusBadGateway, reasonCodeRequestBodyInspectionFailed,
			subject+" denied: network verification unavailable", verbosity)
		return false
	}
	network, found, err := g.inspectNetwork(r.Context(), networkID)
	if err != nil {
		logRequestError(g.logger, r, slog.LevelError, "failed to inspect endpoint NetworkID for allowed_networks", err)
		g.exposureDeny(w, r, http.StatusBadGateway, reasonCodeRequestBodyInspectionFailed,
			subject+" denied: network verification unavailable", verbosity)
		return false
	}
	if found && sameNetwork(resolvedKey, network) {
		return true
	}
	return !g.exposureDeny(w, r, http.StatusForbidden, reasonCodeRequestBodyPolicyDenied,
		fmt.Sprintf("%s denied: endpoint NetworkID %q does not resolve to network %q", subject, networkID, key), verbosity)
}

func sameNetwork(a, b NetworkInspectResult) bool {
	if a.ID != "" && b.ID != "" {
		return a.ID == b.ID
	}
	return a.Name == b.Name
}

// denyHostStackOptions refuses pasta and slirp4netns options while a port
// gate is set. It returns false when a response was written.
func (g *resourceLimitGuard) denyHostStackOptions(w http.ResponseWriter, r *http.Request, subject string, opts NetworkExposureOptions, reason string, verbosity DenyResponseVerbosity) bool {
	if reason == "" || !opts.portsActive() {
		return true
	}
	return !g.exposureDeny(w, r, http.StatusForbidden, reasonCodeRequestBodyPolicyDenied,
		fmt.Sprintf("%s denied: %s", subject, reason), verbosity)
}

// enforceExposure runs the port gates and then the network gate.
func (g *resourceLimitGuard) enforceExposure(w http.ResponseWriter, r *http.Request, subject string, opts NetworkExposureOptions, published bool, bindings []publishedBinding, refs networkRefs, allowHost bool, verbosity DenyResponseVerbosity) bool {
	if opts.portsActive() {
		if reason := opts.denyPublishedPortsReason(subject, published, bindings); reason != "" {
			if g.exposureDeny(w, r, http.StatusForbidden, reasonCodeRequestBodyPolicyDenied, reason, verbosity) {
				return false
			}
		}
	}
	return g.enforceNetworkRefs(w, r, subject, refs, opts.AllowedNetworks, allowHost, verbosity)
}

// guardContainerCreateExposure covers POST /containers/create and
// POST /libpod/containers/create. It returns false when a response was written.
func (g *resourceLimitGuard) guardContainerCreateExposure(w http.ResponseWriter, r *http.Request, policy PolicyConfig, libpod bool) bool {
	opts := policy.ContainerCreate.NetworkExposure
	if libpod {
		opts = policy.LibpodContainerCreate.NetworkExposure
	}
	if !opts.active() {
		return true
	}
	body, err := readBoundedBodyUnchecked(r, maxContainerCreateBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			g.exposureDeny(w, r, http.StatusRequestEntityTooLarge, reasonCodeRequestBodyTooLarge,
				fmt.Sprintf("container create denied: request body exceeds %d byte limit", maxContainerCreateBodyBytes), policy.DenyResponseVerbosity)
			return false
		}
		g.exposureDeny(w, r, http.StatusBadRequest, reasonCodeRequestBodyInspectionFailed,
			"container create denied: request body could not be read", policy.DenyResponseVerbosity)
		return false
	}
	if libpod {
		var req exposureLibpodCreate
		if err := json.Unmarshal(body, &req); err != nil {
			return g.denyUndecodable(w, r, "libpod container create", opts, err, policy.DenyResponseVerbosity)
		}
		if !g.denyHostStackOptions(w, r, "libpod container create", opts, req.hostStackOptionsReason(), policy.DenyResponseVerbosity) {
			return false
		}
		published, bindings := req.ports()
		return g.enforceExposure(w, r, "libpod container create", opts, published, bindings, req.networks(),
			policy.LibpodContainerCreate.AllowHostNetwork, policy.DenyResponseVerbosity)
	}
	var req exposureDockerCreate
	if err := json.Unmarshal(body, &req); err != nil {
		return g.denyUndecodable(w, r, "container create", opts, err, policy.DenyResponseVerbosity)
	}
	if !g.denyHostStackOptions(w, r, "container create", opts, req.hostStackOptionsReason(), policy.DenyResponseVerbosity) {
		return false
	}
	published, bindings := req.ports()
	return g.enforceExposure(w, r, "container create", opts, published, bindings, req.networks(),
		policy.ContainerCreate.AllowHostNetwork, policy.DenyResponseVerbosity)
}

// networkConnectTarget extracts the network reference from a Docker-compat or
// libpod network connect path.
func networkConnectTarget(normalizedPath string) (target string, libpod bool, ok bool) {
	if isLibpodNetworkConnectPath(normalizedPath) {
		rest := strings.TrimPrefix(normalizedPath, libpodPathPrefix+"networks/")
		id, _, _ := strings.Cut(rest, "/")
		return id, true, id != ""
	}
	if isNetworkActionPath(normalizedPath, "connect") {
		rest := strings.TrimPrefix(normalizedPath, "/networks/")
		return strings.TrimSuffix(rest, "/connect"), false, true
	}
	return "", false, false
}

// guardNetworkConnectExposure holds POST /networks/{id}/connect and
// POST /libpod/networks/{name}/connect to the create-side allowed_networks of
// the same family, since a connect after create would otherwise put the
// container on any network. The target is in the path, but a Docker connect's EndpointConfig.NetworkID
// overrides it, so that body is read too.
func (g *resourceLimitGuard) guardNetworkConnectExposure(w http.ResponseWriter, r *http.Request, normalizedPath string, policy PolicyConfig) bool {
	target, libpod, ok := networkConnectTarget(normalizedPath)
	if !ok {
		return true
	}
	opts, allowHost := policy.ContainerCreate.NetworkExposure, policy.ContainerCreate.AllowHostNetwork
	if libpod {
		opts, allowHost = policy.LibpodContainerCreate.NetworkExposure, policy.LibpodContainerCreate.AllowHostNetwork
	}
	if len(opts.AllowedNetworks) == 0 {
		return true
	}
	var refs networkRefs
	refs.add(target)
	if !libpod {
		// The daemon prefers EndpointConfig.NetworkID to the path's network.
		body, err := readBoundedBodyUnchecked(r, maxNetworkBodyBytes)
		if err != nil {
			if isBodyTooLargeError(err) {
				g.exposureDeny(w, r, http.StatusRequestEntityTooLarge, reasonCodeRequestBodyTooLarge,
					fmt.Sprintf("network connect denied: request body exceeds %d byte limit", maxNetworkBodyBytes), policy.DenyResponseVerbosity)
				return false
			}
			g.exposureDeny(w, r, http.StatusBadRequest, reasonCodeRequestBodyInspectionFailed,
				"network connect denied: request body could not be read", policy.DenyResponseVerbosity)
			return false
		}
		var req struct {
			EndpointConfig struct {
				NetworkID string `json:"NetworkID"`
			} `json:"EndpointConfig"`
		}
		if json.Unmarshal(body, &req) == nil {
			refs.bind(target, req.EndpointConfig.NetworkID)
		}
	}
	return g.enforceNetworkRefs(w, r, "network connect", refs, opts.AllowedNetworks, allowHost, policy.DenyResponseVerbosity)
}

// guardServiceExposure covers service create and update. An update replaces
// the whole spec, so the body is judged as the new state. A manual rollback
// ignores the body and re-applies the stored PreviousSpec, and a failed update
// with FailureAction=rollback re-applies the current Spec, so those two are
// resolved from the daemon's copy, pinned to the version the caller sent.
// It returns false when a response was written.
func (g *resourceLimitGuard) guardServiceExposure(w http.ResponseWriter, r *http.Request, normalizedPath string, policy PolicyConfig) bool {
	opts := policy.Service.NetworkExposure
	if !opts.active() {
		return true
	}
	verbosity := policy.DenyResponseVerbosity
	const subject = "service"
	id, isUpdate := serviceUpdateIdentifier(normalizedPath)
	if isUpdate {
		manual, valid := serviceManualRollbackQuery(r)
		if !valid {
			g.exposureDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
				"service update denied: rollback query parameter must have exactly one value", verbosity)
			return false
		}
		if manual {
			if _, ok := serviceVersionQuery(r); !ok {
				g.exposureDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
					"service update denied: a single numeric version query parameter is required", verbosity)
				return false
			}
			current, ok := g.inspectServiceForRollbackNetworks(w, r, id, policy, "manual")
			if !ok {
				return false
			}
			if current == nil || !current.HasPreviousSpec {
				return true
			}
			published, bindings := servicePortBindings(current.PreviousSpecPublishedPorts)
			return g.enforceExposure(w, r, subject, opts, published, bindings,
				serviceNetworkRefs(current.PreviousSpecNetworkTargets), policy.Service.AllowHostNetwork, verbosity)
		}
	}
	body, err := readBoundedBodyUnchecked(r, maxServiceBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			g.exposureDeny(w, r, http.StatusRequestEntityTooLarge, reasonCodeRequestBodyTooLarge,
				fmt.Sprintf("service denied: request body exceeds %d byte limit", maxServiceBodyBytes), verbosity)
			return false
		}
		g.exposureDeny(w, r, http.StatusBadRequest, reasonCodeRequestBodyInspectionFailed,
			"service denied: request body could not be read", verbosity)
		return false
	}
	var req exposureServiceSpec
	if len(strings.TrimSpace(string(body))) == 0 || json.Unmarshal(body, &req) != nil {
		return true
	}
	published, bindings := servicePortBindings(req.published())
	if !g.enforceExposure(w, r, subject, opts, published, bindings, serviceNetworkRefs(req.targets()), policy.Service.AllowHostNetwork, verbosity) {
		return false
	}
	if !isUpdate || !req.failureActionIsRollback() {
		return true
	}
	if _, ok := serviceVersionQuery(r); !ok {
		g.exposureDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"service update denied: a single numeric version query parameter is required", verbosity)
		return false
	}
	current, ok := g.inspectServiceForRollbackNetworks(w, r, id, policy, "automatic")
	if !ok {
		return false
	}
	if current == nil {
		return true
	}
	published, bindings = servicePortBindings(current.SpecPublishedPorts)
	return g.enforceExposure(w, r, subject, opts, published, bindings,
		serviceNetworkRefs(current.SpecNetworkTargets), policy.Service.AllowHostNetwork, verbosity)
}

// guardPodCreateExposure holds POST /libpod/pods/create to the
// libpod_container_create gates. A pod publishes ports and owns the network
// namespace its member containers join, so leaving it out would let a caller
// publish through the pod and then join a container to it. PodSpecGenerator
// flattens the same portmappings, netns and networks keys a container spec
// has, so the container decode reads it. The pod's own allow_host_network
// answers for the host network. It returns false when a response was written.
func (g *resourceLimitGuard) guardPodCreateExposure(w http.ResponseWriter, r *http.Request, policy PolicyConfig) bool {
	opts := policy.LibpodContainerCreate.NetworkExposure
	if !opts.active() {
		return true
	}
	body, err := readBoundedBodyUnchecked(r, maxContainerCreateBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			g.exposureDeny(w, r, http.StatusRequestEntityTooLarge, reasonCodeRequestBodyTooLarge,
				fmt.Sprintf("libpod pod create denied: request body exceeds %d byte limit", maxContainerCreateBodyBytes), policy.DenyResponseVerbosity)
			return false
		}
		g.exposureDeny(w, r, http.StatusBadRequest, reasonCodeRequestBodyInspectionFailed,
			"libpod pod create denied: request body could not be read", policy.DenyResponseVerbosity)
		return false
	}
	var req exposureLibpodCreate
	if err := json.Unmarshal(body, &req); err != nil {
		return g.denyUndecodable(w, r, "libpod pod create", opts, err, policy.DenyResponseVerbosity)
	}
	if !g.denyHostStackOptions(w, r, "libpod pod create", opts, req.hostStackOptionsReason(), policy.DenyResponseVerbosity) {
		return false
	}
	published, bindings := req.ports()
	return g.enforceExposure(w, r, "libpod pod create", opts, published, bindings, req.networks(),
		policy.LibpodPodCreate.AllowHostNetwork, policy.DenyResponseVerbosity)
}

// guardPlayKubeExposure refuses POST /libpod/play/kube and its
// /libpod/kube/play alias while any libpod port or network gate is set. The
// pods and containers a kube YAML creates carry their own ports and networks,
// and sockguard doesn't parse the YAML. The route is already behind
// insecure_allow_body_blind_writes, so this only matters once an operator has
// opened it. It returns false when a response was written.
func (g *resourceLimitGuard) guardPlayKubeExposure(w http.ResponseWriter, r *http.Request, policy PolicyConfig) bool {
	if !policy.LibpodContainerCreate.NetworkExposure.active() {
		return true
	}
	return !g.exposureDeny(w, r, http.StatusForbidden, reasonCodeRequestBodyPolicyDenied,
		"libpod play kube denied: the YAML body is not inspected, so it can't be held to the libpod port and network gates", policy.DenyResponseVerbosity)
}

// guardRestoreExposure refuses POST /libpod/containers/{name}/restore while
// any libpod port or network gate is set. A restore with import creates a
// container from a checkpoint archive that carries its own ports and
// networks, and publishPorts publishes ports on any restore, none of which
// sockguard reads. It returns false when a response was written.
func (g *resourceLimitGuard) guardRestoreExposure(w http.ResponseWriter, r *http.Request, policy PolicyConfig) bool {
	if !policy.LibpodContainerCreate.NetworkExposure.active() {
		return true
	}
	return !g.exposureDeny(w, r, http.StatusForbidden, reasonCodeRequestBodyPolicyDenied,
		"libpod container restore denied: a checkpoint archive and publishPorts carry their own ports and networks, so a restore can't be held to the libpod port and network gates", policy.DenyResponseVerbosity)
}
