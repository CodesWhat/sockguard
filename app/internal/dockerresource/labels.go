package dockerresource

import (
	"encoding/json"
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
	default:
		return nil, fmt.Errorf("unsupported resource kind %q", kind)
	}
}
