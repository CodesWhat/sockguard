package filter_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestLoadedDeviceRequestOptionsMatchCaseExactly drives a YAML grant for the
// option Visible through the loaded config: the key as written is admitted and
// the lowercased spelling Viper would have produced is not.
func TestLoadedDeviceRequestOptionsMatchCaseExactly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	yaml := `request_body:
  container_create:
    allowed_device_requests:
      - driver: nvidia
        allowed_capabilities: [["gpu"]]
        options:
          Visible: "0"
rules:
  - match: { method: POST, path: "/containers/create" }
    action: allow
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	handler := drydockPresetHandlerFromConfig(t, cfg)
	body := func(key string) string {
		return `{"Image":"x","HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":1,"Capabilities":[["gpu"]],"Options":{"` + key + `":"0"}}]}}`
	}
	fireDrydockCase(t, handler, presetCase{"option-as-written-allowed", http.MethodPost, "/containers/create", body("Visible"), true})
	fireDrydockCase(t, handler, presetCase{"option-lowercased-denied", http.MethodPost, "/containers/create", body("visible"), false})
}
