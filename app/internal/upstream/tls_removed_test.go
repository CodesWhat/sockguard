package upstream

import (
	"strings"
	"testing"
)

func TestDockerEnvRejectsRemovedUnverifiedTLS(t *testing.T) {
	for _, value := range []string{"1", "0", "false", " "} {
		t.Run(value, func(t *testing.T) {
			env := map[string]string{"DOCKER_HOST": "tcp://daemon:2376", "DOCKER_TLS": value, "DOCKER_CERT_PATH": "/missing"}
			_, ok, err := SpecsFromDockerEnv(func(key string) (string, bool) { value, present := env[key]; return value, present })
			if ok || err == nil || !strings.Contains(err.Error(), "removed in v3.0.0") || !strings.Contains(err.Error(), "DOCKER_TLS_VERIFY=1") {
				t.Fatalf("SpecsFromDockerEnv = ok:%v err:%v, want removed-fallback guidance before reading certificates", ok, err)
			}
		})
	}
}
