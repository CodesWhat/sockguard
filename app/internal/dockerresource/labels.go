package dockerresource

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

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
	if bytes.Equal(data, []byte("null")) {
		return nil, errors.New("decode libpod network inspect object: object is null")
	}
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
