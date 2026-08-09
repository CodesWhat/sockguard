package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadYAMLBuildkit mirrors FuzzLoadYAML's raw-bytes-through-Load
// pattern (load_test.go) but seeds the corpus with request_body.buildkit
// shapes specifically, so mutation spends its time exploring the new #185
// phase 1 schema (nested control/session blocks, allowlist slices, the
// insecure_accept_opaque_buildkit_tunnels mutual-exclusion pair) rather than
// rediscovering coverage FuzzLoadYAML already has for the rest of Config.
// Every seed both parses (Load) and validates (Validate) cleanly or with a
// well-formed error — neither call should ever panic, regardless of how
// badly shaped the YAML is.
func FuzzLoadYAMLBuildkit(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("request_body:\n  buildkit: {}\n"))
	f.Add([]byte(`request_body:
  buildkit:
    control:
      allow_info: true
      allow_list_workers: true
      allow_status: true
      solve:
        allow: true
    session:
      health: true
      auth:
        allow: true
        allowed_registries: ["ghcr.io", "registry.example.com:5000"]
        allowed_realms: ["realm-a"]
        allowed_scopes: ["repository:foo/bar:pull"]
      secrets:
        allow: true
        allowed_ids: ["my-secret"]
      ssh:
        allow: true
        allowed_ids: ["default"]
      file_sync:
        allow: true
      file_send:
        allow: true
      upload:
        allow: true
`))
	f.Add([]byte(`insecure_accept_opaque_buildkit_tunnels: true
request_body:
  buildkit:
    control:
      solve:
        allow: true
`))
	f.Add([]byte("request_body:\n  buildkit: definitely-not-a-map\n"))
	f.Add([]byte("request_body:\n  buildkit:\n    control: definitely-not-a-map\n"))
	f.Add([]byte("request_body:\n  buildkit:\n    control:\n      allow_info: not-a-bool\n"))
	f.Add([]byte("request_body:\n  buildkit:\n    session:\n      auth:\n        allowed_registries: not-a-list\n"))
	f.Add([]byte("request_body:\n  buildkit:\n    session:\n      secrets:\n        allowed_ids: [\"\", \"  padded  \", \"ok\"]\n"))
	f.Add([]byte(`clients:
  profiles:
    - name: builders
      rules:
        - match: { method: GET, path: /_ping }
          action: allow
      request_body:
        buildkit:
          control:
            solve:
              allow: true
`))
	f.Add([]byte("request_body:\n  buildkit:\n    session:\n      auth:\n        allowed_scopes: [\"\\u0000\", \"日本語\"]\n"))

	f.Fuzz(func(t *testing.T, yaml []byte) {
		restoreEnv := snapshotSockguardEnv(t)
		defer restoreEnv()

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "fuzz.yaml")
		if err := os.WriteFile(cfgPath, yaml, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		cfg, err := Load(cfgPath)
		if err != nil {
			return
		}
		// Load succeeded (the YAML decoded into a Config); Validate must
		// still never panic, no matter how the buildkit block or its
		// interaction with insecure_accept_opaque_buildkit_tunnels is
		// shaped.
		_ = Validate(cfg)
	})
}
