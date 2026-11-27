package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestExactDeviceGrantsLoadAndMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	yaml := `request_body:
  container_create:
    allowed_device_requests:
      - driver: cdi
        device_ids: ["nvidia.com/gpu=0", "nvidia.com/gpu=1"]
      - driver: nvidia
        count: 2
  libpod_container_create:
    allowed_gpus: ["nvidia.com/gpu=0"]
    allowed_cdi_devices: ["nvidia.com/gpu=0", "vendor.example/gpu=GPU-1:2"]
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	opts := cfg.RequestBody.ToFilterOptions()
	reqs := opts.ContainerCreate.AllowedDeviceRequests
	if len(reqs) != 2 || !reflect.DeepEqual(reqs[0].DeviceIDs, []string{"nvidia.com/gpu=0", "nvidia.com/gpu=1"}) || reqs[0].Count != nil || reqs[1].Count == nil || *reqs[1].Count != 2 {
		t.Errorf("container_create device requests = %+v", reqs)
	}
	lib := opts.LibpodContainerCreate
	if !reflect.DeepEqual(lib.AllowedGPUs, []string{"nvidia.com/gpu=0"}) || !reflect.DeepEqual(lib.AllowedCDIDevices, []string{"nvidia.com/gpu=0", "vendor.example/gpu=GPU-1:2"}) {
		t.Errorf("libpod options = %+v", lib)
	}
	if opts.ContainerCreate.AllowDeviceRequests || lib.AllowDeviceRequests {
		t.Error("exact lists must not turn on the blanket opt-in")
	}

	def, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatal(err)
	}
	d := def.RequestBody.ToFilterOptions().LibpodContainerCreate
	if d.AllowedGPUs != nil || d.AllowedCDIDevices != nil {
		t.Errorf("defaults not empty: %+v", d)
	}
}

func TestExactDeviceGrantsValidation(t *testing.T) {
	intPtr := func(v int) *int { return &v }
	tests := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"empty device id", func(c *Config) {
			c.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{{Driver: "cdi", DeviceIDs: []string{""}}}
		}, "allowed_device_requests[0].device_ids[0] must be a non-empty value"},
		{"padded device id", func(c *Config) {
			c.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{{Driver: "cdi", DeviceIDs: []string{" nvidia.com/gpu=0"}}}
		}, "device_ids[0] must be a non-empty value without surrounding whitespace"},
		{"count below minus one", func(c *Config) {
			c.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{{Driver: "nvidia", Count: intPtr(-2)}}
		}, "allowed_device_requests[0].count must be -1 or a non-negative integer"},
		{"ids with non-zero count", func(c *Config) {
			c.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{{Driver: "cdi", DeviceIDs: []string{"a.b/c=d"}, Count: intPtr(1)}}
		}, "cannot set device_ids with a non-zero count"},
		{"padded option key", func(c *Config) {
			c.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{{Driver: "nvidia", Options: map[string]string{" visible": "0"}}}
		}, "allowed_device_requests[0].options keys must be non-empty"},
		{"empty option key", func(c *Config) {
			c.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{{Driver: "nvidia", Options: map[string]string{"": "0"}}}
		}, "allowed_device_requests[0].options keys must be non-empty"},
		{"empty gpu", func(c *Config) {
			c.RequestBody.LibpodContainerCreate.AllowedGPUs = []string{""}
		}, "libpod_container_create.allowed_gpus[0] must be a non-empty value"},
		{"unqualified cdi name", func(c *Config) {
			c.RequestBody.LibpodContainerCreate.AllowedCDIDevices = []string{"/dev/sda"}
		}, "libpod_container_create.allowed_cdi_devices[0] must be a fully qualified CDI name"},
		{"cdi wildcard", func(c *Config) {
			c.RequestBody.LibpodContainerCreate.AllowedCDIDevices = []string{"nvidia.com/gpu=*"}
		}, "allowed_cdi_devices[0] must be a fully qualified CDI name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			tc.mut(&cfg)
			err := Validate(&cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

// exactNvidiaSingleGPUYAML is the NVIDIA single-GPU example shipped in the
// configuration docs. The test keeps the documented grant loadable.
const exactNvidiaSingleGPUYAML = `request_body:
  container_create:
    allowed_device_requests:
      - driver: cdi
        device_ids: ["nvidia.com/gpu=0"]
      - driver: nvidia
        count: 1
        allowed_capabilities:
          - ["gpu"]
        options:
          visible: "0"
  libpod_container_create:
    allowed_gpus: ["nvidia.com/gpu=0"]
`

func TestExactDeviceRequestOptionsLoadAndMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	if err := os.WriteFile(path, []byte(exactNvidiaSingleGPUYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	reqs := cfg.RequestBody.ToFilterOptions().ContainerCreate.AllowedDeviceRequests
	if len(reqs) != 2 || reqs[0].Options != nil || !reflect.DeepEqual(reqs[1].Options, map[string]string{"visible": "0"}) {
		t.Errorf("device requests = %+v", reqs)
	}
}
