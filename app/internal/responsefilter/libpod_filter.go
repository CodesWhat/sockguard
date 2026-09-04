package responsefilter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// libpod_filter.go is filter.go's counterpart for Podman's native /libpod/
// API family. It exists because requestfilter.NormalizePath strips the Docker
// API version prefix but NOT the /libpod segment, so every Docker-compat
// predicate in filter.go (isContainerInspectPath, isVolumeInspectPath,
// isNetworkInspectPath, isSecretInspectPath and the exact-match list paths)
// fails to match the Podman spelling of the same read. Before this file the
// whole package was a no-op on /libpod/..., and a client that switched from
// the compat path to the native one received an unredacted body.
//
// It is kept structurally separate rather than folded into filter.go's
// predicates for the same reason internal/visibility/libpod_paths.go and
// internal/dockerresource's DecodeLibpodLabels are separate from their
// Docker-compat siblings: the two API families' wire shapes are pinned
// independently against Podman's own source, and the ones that differ differ
// silently. Reusing a Docker handler here is a decision made per endpoint
// after checking the field names, never the default.

// LibpodPathPrefix is the single definition of the path segment Podman
// prepends to its native API routes. Every libpod path in this package is
// built from it, so the prefix is stated once rather than re-spelled per
// predicate.
const LibpodPathPrefix = "/libpod"

// libpodInspectSuffix is the trailing segment every libpod inspect route
// carries. Unlike Docker-compat, which spells network/volume/secret inspect
// as a bare /{collection}/{id}, Podman suffixes "/json"
// (pkg/api/server/register_{containers,volumes,networks,secrets}.go at
// v5.8.1). The suffix is what keeps a list path from matching an inspect
// predicate: /libpod/volumes/json has no "/" after the collection prefix, so
// the identifier/suffix split fails.
//
// Networks are the one collection where the suffixed spelling is not the only
// one: they also answer inspect on the bare /libpod/networks/{name}. That
// alias gets its own predicate rather than loosening this one, because
// loosening it would make every list path ambiguous with an inspect path.
const libpodInspectSuffix = "json"

// The libpod list endpoints this package filters. Each is the normalized form
// of the route Podman registers; a real client's /v5.8.1/-prefixed spelling
// normalizes onto these exactly as it does for LibpodSystemDataUsagePath.
const (
	libpodVolumeListPath  = LibpodPathPrefix + "/volumes/" + libpodInspectSuffix
	libpodNetworkListPath = LibpodPathPrefix + "/networks/" + libpodInspectSuffix
	libpodSecretListPath  = LibpodPathPrefix + "/secrets/" + libpodInspectSuffix
)

// libpodNetworkTopologyArrayKeys are the array-valued fields of Podman's
// native network object that carry host network topology, transcribed from
// go.podman.io/common's libnetwork/types.Network at the v0.67.0 that Podman
// v5.8.1 pins:
//
//	subnets             []Subnet {subnet, gateway, lease_range{start_ip,end_ip}}
//	routes              []Route  {destination, gateway, metric}
//	network_dns_servers []string
//
// They are the libpod counterpart of the Docker-compat IPAM.Config array
// redactNetworkTopology empties, and they share none of its key names.
var libpodNetworkTopologyArrayKeys = [...]string{"subnets", "routes", "network_dns_servers"}

// isLibpodPath reports whether normPath belongs to Podman's native API
// family. ModifyResponse routes on this before any Docker-compat predicate
// runs, so a /libpod/ path can only ever be handled by the libpod dispatch
// below — a Docker handler can never be reached by a near-miss match on a
// path whose body shape it was never checked against.
func isLibpodPath(normPath string) bool {
	return strings.HasPrefix(normPath, LibpodPathPrefix+"/")
}

// isLibpodInspectPath reports whether normPath is
// /libpod/{collection}/{identifier}/json.
func isLibpodInspectPath(normPath, collection string) bool {
	prefix := LibpodPathPrefix + "/" + collection + "/"
	if !strings.HasPrefix(normPath, prefix) {
		return false
	}
	identifier, tail, ok := strings.Cut(strings.TrimPrefix(normPath, prefix), "/")
	return ok && identifier != "" && tail == libpodInspectSuffix
}

// isLibpodImageInspectPath reports whether normPath is
// /libpod/images/{name}/json. This cannot reuse isLibpodInspectPath: that
// helper Cuts on the first "/" after the collection prefix, which is correct
// for containers/volumes/secrets identifiers (never contain a slash) but
// wrong for an image reference, which routinely does
// (registry.example.com/team/app). register_images.go at v5.8.1 registers
// {name:.*}/json for both /images/{name}/json and /libpod/images/{name}/json,
// so the identifier is intentionally slash-permissive on the wire. This
// follows isImageInspectPath's Docker-compat approach instead: anchor on the
// last path segment being "json" with a non-empty identifier before it.
func isLibpodImageInspectPath(normPath string) bool {
	prefix := LibpodPathPrefix + "/images/"
	if !strings.HasPrefix(normPath, prefix) {
		return false
	}
	rest := strings.TrimPrefix(normPath, prefix)
	idx := strings.LastIndex(rest, "/")
	if idx <= 0 {
		return false
	}
	return rest[idx+1:] == libpodInspectSuffix
}

// isLibpodNetworkInspectPath reports whether normPath is one of the TWO routes
// Podman serves libpod.InspectNetwork on. register_networks.go at v5.8.1
// registers both spellings against that one handler on consecutive lines:
//
//	GET /libpod/networks/{name}/json
//	GET /libpod/networks/{name}
//
// and only the first carries a swagger:operation block, so the bare one is
// easy to miss by reading the API document. Networks are the only libpod
// collection with the alias — containers, volumes and secrets register their
// bare /{name} path for DELETE alone — which is why this is the only
// collection that needs a predicate of its own rather than isLibpodInspectPath.
// Matching the suffixed spelling only would have left the bare one returning
// subnets, routes, the host bridge interface and the cross-owner containers
// map verbatim under any rule broad enough to admit it.
//
// The bare form is restricted to GET because DELETE /libpod/networks/{name} is
// a different handler with a different body, and there is nothing to redact in
// a removal report.
func isLibpodNetworkInspectPath(method, normPath string) bool {
	if isLibpodInspectPath(normPath, "networks") {
		return true
	}
	if method != http.MethodGet {
		return false
	}
	prefix := LibpodPathPrefix + "/networks/"
	if !strings.HasPrefix(normPath, prefix) {
		return false
	}
	segment := strings.TrimPrefix(normPath, prefix)
	if segment == "" || strings.Contains(segment, "/") {
		return false
	}
	// Only json is a GET collection route. create and prune are collection
	// actions on POST, but on GET those same segments are valid network names
	// handled by InspectNetwork. The method guard above already keeps the POST
	// actions out of this response path.
	return segment != libpodInspectSuffix
}

// modifyLibpodResponse dispatches one normalized /libpod/ path to its
// redaction handler, and returns nil for every libpod read this package
// deliberately does not rewrite.
//
// The endpoints that are absent from this switch are absent on purpose, and
// each one was checked against Podman v5.8.1's own types rather than assumed:
//
//   - GET /libpod/containers/json returns []entities.ListContainer
//     (pkg/domain/entities/types/container_ps.go), which has no
//     NetworkSettings and no HostConfig at all, and whose Mounts field is a
//     []string of container-side DESTINATION paths — pkg/ps/ps.go fills it
//     from Container.UserVolumes(), which container_create.go builds under the
//     comment "Take all mount and named volume destinations" out of the
//     mount/volume/overlay/image-volume Destination fields. There is no host
//     source in the body to redact, and routing it to modifyContainerList would
//     instead hand redactMountObjects a string where it requires an object
//     and turn every `podman ps` into a fail-closed 502.
//   - GET /libpod/info returns libpod/define.Info, whose keys are lowercase
//     (host, store, registries, plugins, version) and which has no Swarm
//     object and none of Containerd/FirewallBackend/DiscoveredDevices/NRI.
//     Every field redactInfoPayload rewrites is a Docker Engine field Podman
//     does not have, swarm most of all — Podman has no swarm.
//   - GET /libpod/system/df is refused by the ownership and visibility
//     middlewares instead; see LibpodSystemDataUsageDenyReason.
//   - GET /libpod/pods/{id}/json has no Docker-compat equivalent to inherit a
//     handler from, and libpod/define.InspectPodData spells its bind-mount
//     array as lowercase "mounts" and carries infra network configuration
//     under InfraConfig. Redacting it is a separate change, not a spelling
//     variant of one here; the Podman guide lists it as a known limitation.
//   - GET /libpod/containers/showmounted returns a bare
//     map[containerID]hostMountpoint built from runtime.GetAllContainers(),
//     so it is a host-path disclosure AND a cross-owner enumeration in one
//     body with no field to classify an entry by. Redacting the values alone
//     would leave the enumeration, which makes it the same shape of problem as
//     /libpod/system/df and the same kind of answer — a refusal decided by the
//     ownership and visibility middlewares, not a rewrite here. The Podman
//     guide lists it as a known limitation.
func (f *Filter) modifyLibpodResponse(method, normPath string, resp *http.Response) error {
	switch {
	case isLibpodInspectPath(normPath, "containers"):
		return f.modifyContainerInspect(resp)
	case isLibpodInspectPath(normPath, "volumes"):
		return f.modifyVolumeInspect(resp)
	case isLibpodImageInspectPath(normPath):
		// libpod.GetImage (pkg/api/handlers/libpod/images.go at v5.8.1)
		// writes *libimage.ImageData (containers/common libimage/inspect.go),
		// whose Config field is *ociv1.ImageConfig — json:"Env,omitempty" on
		// []string, the identical key Docker's compat handler uses — and
		// whose GraphDriver field is *DriverData{Name, Data}, the identical
		// shape redactGraphDriverData already handles for container inspect.
		// Checked against both source files rather than assumed; reusing
		// modifyImageInspect is a verified decision, not the default.
		return f.modifyImageInspect(resp)
	case normPath == libpodVolumeListPath:
		return f.modifyLibpodVolumeList(resp)
	case normPath == libpodNetworkListPath:
		return f.modifyLibpodNetworkList(resp)
	case isLibpodNetworkInspectPath(method, normPath):
		return f.modifyLibpodNetworkInspect(resp)
	case isLibpodInspectPath(normPath, "secrets"):
		return f.modifyLibpodSecretInspect(resp)
	case normPath == libpodSecretListPath:
		return f.modifyLibpodSecretList(resp)
	}
	return nil
}

// modifyLibpodVolumeList rewrites GET /libpod/volumes/json.
//
// It cannot reuse modifyVolumeList: Docker's GET /volumes returns an object
// envelope ({"Volumes":[…],"Warnings":[…]}), while libpod.ListVolumes writes
// abi.VolumeList's []*entities.VolumeListReport straight to the wire, so the
// libpod body is a BARE ARRAY of volume objects. The element shape is the
// same either way — VolumeListReport embeds VolumeConfigResponse embeds
// libpod/define.InspectVolumeData, whose host path carries `json:"Mountpoint"`,
// the identical key Docker uses.
func (f *Filter) modifyLibpodVolumeList(resp *http.Response) error {
	if !f.opts.RedactMountPaths {
		return nil
	}
	return streamArrayResponse(resp, func(volume map[string]any) error {
		redactStringField(volume, "Mountpoint")
		return nil
	})
}

// modifyLibpodNetworkList rewrites GET /libpod/networks/json. Podman v4 and
// later return a bare array of go.podman.io/common libnetwork types.Network
// objects. Podman v2.2.1 through v3.4 return embedded libcni
// NetworkConfigList objects instead; redactLibpodNetworkTopology handles both
// generations independently.
func (f *Filter) modifyLibpodNetworkList(resp *http.Response) error {
	if !f.opts.RedactNetworkTopology {
		return nil
	}
	return streamArrayResponse(resp, redactLibpodNetworkTopology)
}

// modifyLibpodNetworkInspect rewrites both routes libpod.InspectNetwork is
// registered on — GET /libpod/networks/{id}/json and the bare
// GET /libpod/networks/{id}. See isLibpodNetworkInspectPath.
//
// Two shapes have to be handled because Podman changed the handler and
// sockguard does not choose which Podman it fronts. Through v3.0.0
// pkg/api/handlers/libpod/networks.go's InspectNetwork wrote the whole
// `reports` slice, so the response was a single-element JSON ARRAY; from
// v3.1.0 onward it writes reports[0] and the response is a bare object.
// Checked directly at v2.2.1 and v3.0.0 (slice) and at v3.1.0, v3.2.0,
// v3.3.0, v3.4.4, v4.0.0 and v5.8.1 (reports[0]).
// internal/dockerresource's decodeLibpodNetworkLabels already accepts both
// for label extraction; this is the response-side counterpart, and it
// re-emits whichever envelope it was given so the client's decoder sees the
// shape its daemon sends.
//
// Unlike the label decoder this does not require the array to hold exactly
// one element. That check exists there to refuse an ambiguous identity; here
// every element is redacted, so accepting more than one is strictly safer
// than turning an unexpected count into a 502 on a read that would otherwise
// have been sanitized.
func (f *Filter) modifyLibpodNetworkInspect(resp *http.Response) error {
	if !f.opts.RedactNetworkTopology {
		return nil
	}

	body, err := readResponseBody(resp)
	if err != nil {
		return rejectResponse(err)
	}

	if bytes.HasPrefix(bytes.TrimLeft(body, " \t\r\n"), []byte("[")) {
		networks, err := decodeJSONObjectArray(body)
		if err != nil {
			return rejectResponse(err)
		}
		for i, network := range networks {
			if err := redactLibpodNetworkTopology(network); err != nil {
				return rejectResponse(fmt.Errorf("libpod network inspect array element %d: %w", i, err))
			}
		}
		return writeResponseBody(resp, networks)
	}

	payload, err := decodeJSONObject(body)
	if err != nil {
		return rejectResponse(err)
	}
	if err := redactLibpodNetworkTopology(payload); err != nil {
		return rejectResponse(err)
	}
	return writeResponseBody(resp, payload)
}

// redactLibpodNetworkTopology empties the host network topology from one
// Podman-native network object. It supports the two incompatible native
// shapes Podman has put on these routes: the raw CNI/libcni structures used
// from v2.2.1 through v3.4, and types.Network used from v4 onward. Neither
// shares its topology keys with Docker's IPAM/Status/Containers/Peers body.
//
// What is emptied, and the Docker-compat field it corresponds to:
//
//   - subnets, routes — CIDRs, gateways and DHCP lease ranges. The libpod
//     equivalent of IPAM.Config, which redactNetworkTopology also empties.
//     routes has no compat counterpart at all; it is host routing state.
//   - network_dns_servers — resolver addresses applied to every container on
//     the network.
//   - containers — entities.NetworkInspectReport.Containers, present only on
//     inspect, keyed by container ID and carrying each container's name, its
//     per-interface addresses and its MAC. This is the same cross-tenant
//     disclosure the compat body's capitalized Containers map carries, under
//     a key the compat redactor does not look for.
//   - network_interface — the host-side bridge device (podman0, podman1, …),
//     the same class of value as the NetworkSettings.Bridge that
//     redactContainerNetworkTopology already redacts on container inspect.
//
// In the legacy CNI shape, inspect exposes the raw lowercase plugins array.
// Its bridge or macvlan master interface and the routes/ranges inside each
// plugin's ipam object are topology. Host-local IPAM also accepts a
// backward-compatible flat subnet/gateway/rangeStart/rangeEnd form, so those
// fields are redacted independently of the newer ranges array. List embeds
// libcni.NetworkConfigList instead, whose capitalized Plugins entries and the
// top-level object each carry a Bytes field. Those []byte values become base64
// strings containing the complete raw plugin or conflist, so leaving either
// copy would undo all structured redaction. The Bytes fields are removed after
// their wire type is validated.
//
// ipam_options on the modern shape and ipam.type on the legacy one are left
// alone. They name the allocator (host-local, dhcp), not an address.
func redactLibpodNetworkTopology(payload map[string]any) error {
	for _, key := range libpodNetworkTopologyArrayKeys {
		value, ok := payload[key]
		if !ok || value == nil {
			continue
		}
		if _, ok := value.([]any); !ok {
			return fmt.Errorf("libpod network %s has unexpected type %T", key, value)
		}
		payload[key] = []any{}
	}

	if value, ok := payload["containers"]; ok && value != nil {
		if _, ok := value.(map[string]any); !ok {
			return fmt.Errorf("libpod network containers has unexpected type %T", value)
		}
		payload["containers"] = map[string]any{}
	}

	redactStringField(payload, "network_interface")
	return redactLegacyCNINetworkTopology(payload)
}

func redactLegacyCNINetworkTopology(payload map[string]any) error {
	if err := removeCNIBytes(payload, "libpod CNI network"); err != nil {
		return err
	}

	for _, key := range []string{"plugins", "Plugins"} {
		value, ok := payload[key]
		if !ok {
			continue
		}
		plugins, ok := value.([]any)
		if !ok {
			return fmt.Errorf("libpod CNI network %s has unexpected type %T", key, value)
		}
		for i, value := range plugins {
			plugin, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("libpod CNI network %s entry %d has unexpected type %T", key, i, value)
			}
			if err := redactLegacyCNIPlugin(plugin); err != nil {
				return fmt.Errorf("libpod CNI network %s entry %d: %w", key, i, err)
			}
		}
	}
	return nil
}

func redactLegacyCNIPlugin(plugin map[string]any) error {
	if err := removeCNIBytes(plugin, "plugin"); err != nil {
		return err
	}

	// A libcni list entry wraps its common fields in Network. A raw inspect
	// plugin has those fields directly. Accept both representations, but never
	// accept a present Network field with a shape that cannot be inspected.
	if value, ok := plugin["Network"]; ok {
		network, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("plugin Network has unexpected type %T", value)
		}
		if err := redactLegacyCNIPluginConfig(network); err != nil {
			return fmt.Errorf("plugin Network: %w", err)
		}
	}

	return redactLegacyCNIPluginConfig(plugin)
}

func redactLegacyCNIPluginConfig(plugin map[string]any) error {
	if value, ok := plugin["bridge"]; ok && value != nil {
		if _, ok := value.(string); !ok {
			return fmt.Errorf("plugin bridge has unexpected type %T", value)
		}
		plugin["bridge"] = redactedValue
	}
	if err := redactLegacyCNIStringTopologyField(plugin, "master", "plugin"); err != nil {
		return err
	}
	if err := redactLegacyCNIDNS(plugin); err != nil {
		return err
	}

	value, ok := plugin["ipam"]
	if !ok {
		return nil
	}
	ipam, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("plugin ipam has unexpected type %T", value)
	}
	for _, key := range []string{"subnet", "gateway", "rangeStart", "rangeEnd"} {
		if err := redactLegacyCNIStringTopologyField(ipam, key, "plugin ipam"); err != nil {
			return err
		}
	}
	if err := redactCNIAddresses(ipam); err != nil {
		return err
	}
	if err := redactLegacyCNIDNS(ipam); err != nil {
		return fmt.Errorf("plugin ipam: %w", err)
	}
	if err := redactCNIObjectArray(ipam, "routes"); err != nil {
		return err
	}
	if err := redactCNIRanges(ipam); err != nil {
		return err
	}
	return nil
}

func redactCNIAddresses(ipam map[string]any) error {
	value, ok := ipam["addresses"]
	if !ok {
		return nil
	}
	addresses, ok := value.([]any)
	if !ok {
		return fmt.Errorf("plugin ipam addresses has unexpected type %T", value)
	}
	for i, value := range addresses {
		address, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("plugin ipam addresses entry %d has unexpected type %T", i, value)
		}
		addressValue, ok := address["address"]
		if !ok {
			return fmt.Errorf("plugin ipam addresses entry %d is missing address", i)
		}
		if _, ok := addressValue.(string); !ok {
			return fmt.Errorf("plugin ipam addresses entry %d address has unexpected type %T", i, addressValue)
		}
		if gateway, ok := address["gateway"]; ok {
			if _, ok := gateway.(string); !ok {
				return fmt.Errorf("plugin ipam addresses entry %d gateway has unexpected type %T", i, gateway)
			}
		}
	}
	ipam["addresses"] = []any{}
	return nil
}

func redactLegacyCNIDNS(plugin map[string]any) error {
	value, ok := plugin["dns"]
	if !ok {
		return nil
	}
	dns, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("plugin dns has unexpected type %T", value)
	}

	_, hasNameservers, err := legacyCNIDNSStringArray(dns, "nameservers")
	if err != nil {
		return err
	}
	_, hasSearch, err := legacyCNIDNSStringArray(dns, "search")
	if err != nil {
		return err
	}
	options, hasOptions, err := legacyCNIDNSStringArray(dns, "options")
	if err != nil {
		return err
	}
	sanitized := make(map[string]any, 4)
	if hasNameservers {
		sanitized["nameservers"] = []any{}
	}
	if value, ok := dns["domain"]; ok {
		if _, ok := value.(string); !ok {
			return fmt.Errorf("plugin dns domain has unexpected type %T", value)
		}
		sanitized["domain"] = redactedValue
	}
	if hasSearch {
		sanitized["search"] = []any{}
	}
	if hasOptions {
		sanitized["options"] = options
	}
	plugin["dns"] = sanitized
	return nil
}

func legacyCNIDNSStringArray(dns map[string]any, key string) ([]any, bool, error) {
	value, ok := dns[key]
	if !ok {
		return nil, false, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, false, fmt.Errorf("plugin dns %s has unexpected type %T", key, value)
	}
	for i, value := range items {
		if _, ok := value.(string); !ok {
			return nil, false, fmt.Errorf("plugin dns %s entry %d has unexpected type %T", key, i, value)
		}
	}
	return items, true, nil
}

func redactLegacyCNIStringTopologyField(payload map[string]any, key, context string) error {
	value, ok := payload[key]
	if !ok {
		return nil
	}
	if _, ok := value.(string); !ok {
		return fmt.Errorf("%s %s has unexpected type %T", context, key, value)
	}
	payload[key] = redactedValue
	return nil
}

func redactCNIObjectArray(payload map[string]any, key string) error {
	value, ok := payload[key]
	if !ok {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("plugin ipam %s has unexpected type %T", key, value)
	}
	for i, value := range items {
		if _, ok := value.(map[string]any); !ok {
			return fmt.Errorf("plugin ipam %s entry %d has unexpected type %T", key, i, value)
		}
	}
	payload[key] = []any{}
	return nil
}

func redactCNIRanges(ipam map[string]any) error {
	value, ok := ipam["ranges"]
	if !ok {
		return nil
	}
	rangeSets, ok := value.([]any)
	if !ok {
		return fmt.Errorf("plugin ipam ranges has unexpected type %T", value)
	}
	for i, value := range rangeSets {
		ranges, ok := value.([]any)
		if !ok {
			return fmt.Errorf("plugin ipam ranges set %d has unexpected type %T", i, value)
		}
		for j, value := range ranges {
			if _, ok := value.(map[string]any); !ok {
				return fmt.Errorf("plugin ipam ranges set %d entry %d has unexpected type %T", i, j, value)
			}
		}
	}
	ipam["ranges"] = []any{}
	return nil
}

func removeCNIBytes(payload map[string]any, context string) error {
	value, ok := payload["Bytes"]
	if !ok {
		return nil
	}
	if _, ok := value.(string); !ok {
		return fmt.Errorf("%s Bytes has unexpected type %T", context, value)
	}
	delete(payload, "Bytes")
	return nil
}

// modifyLibpodSecretInspect rewrites GET /libpod/secrets/{name}/json, a bare
// entities.SecretInfoReport object.
//
// The compat redactor is genuinely not enough here, and the reason is not
// path spelling. Podman's SecretSpec (pkg/domain/entities/types/secrets.go)
// is {Name, Driver{Name,Options}, Labels} — it has NO Data field, so
// redactSecretPayload's Spec.Data rewrite finds nothing on this shape. The
// plaintext lives one level up, on SecretInfoReport.SecretData
// (`json:"SecretData,omitempty"`), which abi.SecretInspect fills from
// SecretsManager.LookupSecretData whenever the request carries
// ?showsecret=true. Nothing in this proxy's default rules or in
// configs/podman-readonly.yaml constrains that query parameter, so an allowed
// inspect is an allowed secret read. redactSecretPayload now covers both
// fields; see its own comment for why that also matters on the compat path.
func (f *Filter) modifyLibpodSecretInspect(resp *http.Response) error {
	if !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyMapResponse(resp, redactSecretPayload)
}

// modifyLibpodSecretList rewrites GET /libpod/secrets/json, a bare array of
// the same entities.SecretInfoReport objects inspect returns.
//
// abi.SecretList has no ShowSecret option and its secretToReport helper
// leaves SecretData empty, so a v5.8.1 daemon does not populate the field on
// this route today. It is filtered anyway because list and inspect serialize
// the identical Go type: the difference is which call site fills the field,
// which is a decision on the far side of the socket and not one this proxy
// gets told about. Filtering both means a Podman that starts honoring
// ?showsecret= on list does not reopen the leak silently.
func (f *Filter) modifyLibpodSecretList(resp *http.Response) error {
	if !f.opts.RedactSensitiveData {
		return nil
	}
	return streamArrayResponse(resp, redactSecretPayload)
}

// decodeJSONObjectArray is decodeJSONObject for a top-level JSON array of
// objects: the same newJSONDecoder configuration so large integers round-trip
// byte for byte, and the same rejection of a second document hiding behind
// the first.
func decodeJSONObjectArray(body []byte) ([]map[string]any, error) {
	dec := newJSONDecoder(bytes.NewReader(body))
	var payload []map[string]any
	if err := dec.Decode(&payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			err = errors.New("unexpected end of JSON input")
		}
		return nil, err
	}
	if err := trailingJSONError(body, dec.InputOffset()); err != nil {
		return nil, err
	}
	return payload, nil
}
