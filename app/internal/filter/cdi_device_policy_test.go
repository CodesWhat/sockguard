package filter

import (
	"fmt"
	"testing"
)

func TestCDIDeviceRequestsRespectHostDevicePolicy(t *testing.T) {
	for _, path := range []string{"/containers/create", "/v1.47/containers/create"} {
		for _, broad := range []bool{false, true} {
			for _, tc := range []struct {
				id     string
				denied bool
			}{
				{"/dev/sda", true}, {"/dev/sda:/dev/null:rwm", true}, {"../../dev/sda", true},
				{"/dev/null", false}, {"/dev/null:/dev/null:rw", false},
				{"nvidia.com/gpu=all", false}, {"vendor.example/gpu=GPU-1:2", false},
				{"not-a-cdi-name", true}, {"vendor/gpu=../../dev/sda", true},
			} {
				t.Run(fmt.Sprintf("%s/broad=%v/%s", path, broad, tc.id), func(t *testing.T) {
					cfg := PolicyConfig{ContainerCreate: ContainerCreateOptions{AllowDeviceRequests: broad, AllowedDeviceRequests: []AllowedDeviceRequestEntry{{Driver: "cdi"}}, AllowedDevices: []string{"/dev/null"}}}
					body := fmt.Sprintf(`{"HostConfig":{"DeviceRequests":[{"Driver":"cdi","DeviceIDs":[%q]}]}}`, tc.id)
					assertFilterCreateRoundTrip(t, path, body, cfg, tc.denied)
				})
			}
		}
	}
	for _, tc := range []ContainerCreateOptions{{AllowAllDevices: true, AllowDeviceRequests: true}, {AllowedDeviceRequests: []AllowedDeviceRequestEntry{{Driver: "nvidia"}}}} {
		body := `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","DeviceIDs":["GPU-123"]}]}}`
		assertFilterCreateRoundTrip(t, "/containers/create", body, PolicyConfig{ContainerCreate: tc}, false)
	}
	assertFilterCreateRoundTrip(t, "/containers/create", `{"HostConfig":{"DeviceRequests":[{"Driver":"cdi","DeviceIDs":["/dev/sda"]}]}}`, PolicyConfig{ContainerCreate: ContainerCreateOptions{AllowAllDevices: true, AllowDeviceRequests: true}}, false)
}
