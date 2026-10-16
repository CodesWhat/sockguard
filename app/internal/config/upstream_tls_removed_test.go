package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsRemovedUpstreamTLSSetting(t *testing.T) {
	for _, address := range []string{"tcp://daemon:2376", "unix:///run/docker.sock"} {
		for _, value := range []string{"true", "false", "null", "{}"} {
			for _, key := range []string{"insecure_skip_tls_verify", "INSECURE_SKIP_TLS_VERIFY"} {
				t.Run(address+"/"+key+"/"+value, func(t *testing.T) {
					data := []byte(fmt.Sprintf("upstream:\n  endpoints:\n    - address: %s\n      %s: %s\n", address, key, value))
					path := filepath.Join(t.TempDir(), "config.yaml")
					if err := os.WriteFile(path, data, 0o600); err != nil {
						t.Fatal(err)
					}
					for _, load := range []func() (*Config, error){func() (*Config, error) { return LoadBytes(data) }, func() (*Config, error) { return Load(path) }} {
						_, err := load()
						if err == nil || !strings.Contains(err.Error(), "removed in v3.0.0") || !strings.Contains(err.Error(), "upstream.endpoints[0].insecure_skip_tls_verify") || !strings.Contains(err.Error(), "tls.ca_file") {
							t.Fatalf("load error = %v, want removed-setting migration guidance", err)
						}
					}
				})
			}
		}
	}
}
