package dockerresource

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
)

// Kind names a category of Docker resource (container, image, network, etc.)
// in the same form the Docker API uses in URL paths.
type Kind string

const (
	KindContainer Kind = "containers"
	KindImage     Kind = "images"
	KindNetwork   Kind = "networks"
	KindVolume    Kind = "volumes"
	KindService   Kind = "services"
	KindTask      Kind = "tasks"
	KindSecret    Kind = "secrets"
	KindConfig    Kind = "configs"
	KindNode      Kind = "nodes"
	KindSwarm     Kind = "swarm"

	// KindLibpodPod identifies Podman's native pod resource (#148). Pods have
	// no Docker-compat equivalent — there is no "/pods/{id}" endpoint on the
	// Docker Engine API a pod is also reachable through — so, unlike every
	// other kind above, a pod can only ever be inspected via the /libpod/
	// route family. See LibpodInspectPath.
	KindLibpodPod Kind = "libpod-pods"
	// KindLibpodNetwork identifies a libpod-native network *inspect request*
	// specifically — i.e. the inbound client request itself is under
	// /libpod/networks/, not "a network that happens to have been created
	// via the libpod API" (any network, regardless of which API created it,
	// is also reachable through the Docker-compat KindNetwork path, and
	// ownership's write-side checks use that path uniformly). It exists as
	// its own Kind because GET /libpod/networks/{id}/json has two wire-shape
	// differences from the Docker-compat GET /networks/{id} DecodeLabels
	// already reads for KindNetwork: a lowercase top-level "labels" key, and
	// — per #148 design doc C6 — a single-element ARRAY-wrapped response on
	// some Podman versions/endpoints. See DecodeLibpodLabels.
	KindLibpodNetwork Kind = "libpod-networks"
)

// InspectPath returns the Docker API path for fetching a single resource of
// the given kind. The result is a server-side path, ready for
// "http://docker" + InspectPath. Returns ("", false) when the kind is not
// individually inspectable.
//
// Ownership and visibility both build the same URLs to fetch labels for a
// resource; centralizing the mapping ensures they cannot drift apart.
func InspectPath(kind Kind, identifier string) (string, bool) {
	escaped := url.PathEscape(identifier)
	switch kind {
	case KindContainer:
		return "/containers/" + escaped + "/json", true
	case KindImage:
		return "/images/" + escaped + "/json", true
	case KindNetwork:
		return "/networks/" + escaped, true
	case KindVolume:
		return "/volumes/" + escaped, true
	case KindService:
		return "/services/" + escaped, true
	case KindTask:
		return "/tasks/" + escaped, true
	case KindSecret:
		return "/secrets/" + escaped, true
	case KindConfig:
		return "/configs/" + escaped, true
	case KindNode:
		return "/nodes/" + escaped, true
	case KindSwarm:
		return "/swarm", true
	case KindLibpodPod, KindLibpodNetwork:
		return LibpodInspectPath(kind, identifier)
	}
	return "", false
}

// LibpodInspectPath returns the libpod-native inspect path for kind — always
// shaped /libpod/<resource>/<id>/json, unlike the Docker-compat paths
// InspectPath returns for kinds such as KindNetwork/KindVolume (bare
// /networks/{id}, no /json suffix). Centralizing this the same way
// InspectPath is centralized keeps ownership and visibility from drifting
// apart on the libpod route shape, per #148 design doc C6. Returns
// ("", false) for any kind with no libpod-native inspect path of its own
// (e.g. KindVolume/KindSecret/KindContainer reuse their Docker-compat path
// via InspectPath instead, since Podman's compat API is a translation layer
// over the same underlying resource store for those kinds).
func LibpodInspectPath(kind Kind, identifier string) (string, bool) {
	escaped := url.PathEscape(identifier)
	switch kind {
	case KindLibpodPod:
		return "/libpod/pods/" + escaped + "/json", true
	case KindLibpodNetwork:
		return "/libpod/networks/" + escaped + "/json", true
	}
	return "", false
}

// DecodeLabels reads a Docker inspect response body and extracts the resource
// labels for the given kind. Ownership and visibility both decode the same
// JSON shapes; centralizing the logic keeps them from drifting apart.
func DecodeLabels(body io.Reader, kind Kind) (map[string]string, error) {
	switch kind {
	case KindContainer:
		var payload struct {
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		return payload.Config.Labels, nil
	case KindImage:
		var payload struct {
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
			ContainerConfig struct {
				Labels map[string]string `json:"Labels"`
			} `json:"ContainerConfig"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		if len(payload.Config.Labels) > 0 {
			return payload.Config.Labels, nil
		}
		return payload.ContainerConfig.Labels, nil
	case KindNetwork, KindVolume:
		var payload struct {
			Labels map[string]string `json:"Labels"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		return payload.Labels, nil
	case KindService, KindSecret, KindConfig, KindNode, KindSwarm:
		var payload struct {
			Spec struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Spec"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		return payload.Spec.Labels, nil
	case KindTask:
		var payload struct {
			Labels map[string]string `json:"Labels"`
			Spec   struct {
				ContainerSpec struct {
					Labels map[string]string `json:"Labels"`
				} `json:"ContainerSpec"`
			} `json:"Spec"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		if len(payload.Labels) > 0 {
			return payload.Labels, nil
		}
		return payload.Spec.ContainerSpec.Labels, nil
	case KindLibpodPod, KindLibpodNetwork:
		return DecodeLibpodLabels(body, kind)
	default:
		return nil, fmt.Errorf("unsupported resource kind %q", kind)
	}
}

// DecodeLibpodLabels reads a libpod-native inspect response body — as
// opposed to DecodeLabels' Docker-compat shapes — and extracts the
// resource's labels. Kept as an entirely separate function, with its own
// switch and no shared case arms with DecodeLabels, per #148 design doc C6:
// the two API families' wire shapes are pinned independently against real
// captures/upstream source and must never be allowed to silently reconverge
// into one "smart" decoder if one family drifts.
func DecodeLibpodLabels(body io.Reader, kind Kind) (map[string]string, error) {
	switch kind {
	case KindLibpodPod:
		// libpod/define.InspectPodData.Labels — top-level, capitalized
		// "Labels" (confirmed against podman v5.8.1 source), unlike the
		// lowercase "labels" libpod uses for the POST .../pods/create
		// request body's PodBasicConfig.Labels field.
		var payload struct {
			Labels map[string]string `json:"Labels"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		return payload.Labels, nil
	case KindLibpodNetwork:
		return decodeLibpodNetworkLabels(body)
	default:
		return nil, fmt.Errorf("unsupported libpod resource kind %q", kind)
	}
}

// decodeLibpodNetworkLabels reads GET /libpod/networks/{id}/json's response.
// Per #148 design doc C6, some Podman versions/endpoints wrap the single
// network object in a single-element JSON array rather than returning the
// bare object Docker's compat API always does for network inspect; this
// unwraps that shape before decoding so a legitimate response is never
// mistaken for a decode failure (which would otherwise surface to the
// client as a 502 from the ownership/visibility policy-lookup-failed path).
// The "labels" key itself is lowercase on this shape
// (go.podman.io/common's libnetwork/types.Network), unlike the Docker-compat
// "Labels" DecodeLabels reads for KindNetwork.
func decodeLibpodNetworkLabels(body io.Reader) (map[string]string, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(data, &arr); err != nil {
			return nil, fmt.Errorf("decode libpod network inspect array: %w", err)
		}
		if len(arr) != 1 {
			return nil, fmt.Errorf("decode libpod network inspect array: expected one object, got %d", len(arr))
		}
		data = bytes.TrimSpace(arr[0])
		if bytes.Equal(data, []byte("null")) {
			return nil, errors.New("decode libpod network inspect array: object is null")
		}
	}
	var payload struct {
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("decode libpod network inspect object: %w", err)
	}
	return payload.Labels, nil
}
