package responsefilter

import (
	"net/http"
	"testing"
)

func TestImageInspectRedactsLegacyContainerEnvironment(t *testing.T) {
	t.Parallel()
	const payload = `{"Id":"sha256:kept","Config":{"Env":["CURRENT_SECRET=private"]},"ContainerConfig":{"Env":["LEGACY_SECRET=private"],"Cmd":["kept"]}}`
	for _, path := range []string{"/v1.44/images/app/json", "/images/app/json", "/v5.8.1/libpod/images/app/json"} {
		for _, enabled := range []bool{false, true} {
			resp := newResponseForTest(t, http.MethodGet, path, payload)
			if err := New(Options{RedactContainerEnv: enabled}).ModifyResponse(resp); err != nil {
				t.Fatal(err)
			}
			got := decodeBodyForTest(t, resp)
			for _, key := range []string{"Config", "ContainerConfig"} {
				config := got[key].(map[string]any)
				env := config["Env"].([]any)
				wantLength := 1
				if enabled {
					wantLength = 0
				}
				if len(env) != wantLength {
					t.Errorf("%s redaction=%v: %s.Env=%v", path, enabled, key, env)
				}
			}
			if got["Id"] != "sha256:kept" || got["ContainerConfig"].(map[string]any)["Cmd"].([]any)[0] != "kept" {
				t.Fatal("unrelated image metadata changed")
			}
		}
	}
}
