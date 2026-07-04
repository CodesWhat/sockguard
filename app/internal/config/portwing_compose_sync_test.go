package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

// TestPortwingComposeExampleInSync guards the embedded compose example against
// drift from the canonical preset. examples/compose/portwing/sockguard.yaml is a
// hand-maintained copy of app/configs/portwing.yaml (its header says "update both
// files together"); a copy that silently diverges ships a broken example.
//
// The compose example directory runs portwing standalone against the shared
// docker.sock (no nested compose stack of its own — see
// examples/compose/portwing/docker-compose.yml), so portwing.yaml is the
// correct comparison target, not portwing-with-compose.yaml.
//
// The two must load to the same rules + request-body inspection + response
// policy. The connection envelope (upstream/log/health) and YAML comments are
// allowed to differ — only the security-relevant policy must stay in lockstep.
func TestPortwingComposeExampleInSync(t *testing.T) {
	canonical, err := Load(filepath.Join("..", "..", "configs", "portwing.yaml"))
	if err != nil {
		t.Fatalf("load canonical portwing.yaml: %v", err)
	}
	compose, err := Load(filepath.Join("..", "..", "..", "examples", "compose", "portwing", "sockguard.yaml"))
	if err != nil {
		t.Fatalf("load compose portwing/sockguard.yaml: %v", err)
	}

	if !reflect.DeepEqual(canonical.Rules, compose.Rules) {
		t.Errorf("rules drifted between app/configs/portwing.yaml and examples/compose/portwing/sockguard.yaml\n canonical: %+v\n compose:   %+v",
			canonical.Rules, compose.Rules)
	}
	if !reflect.DeepEqual(canonical.RequestBody, compose.RequestBody) {
		t.Errorf("request_body drifted between portwing.yaml and the compose example\n canonical: %+v\n compose:   %+v",
			canonical.RequestBody, compose.RequestBody)
	}
	if !reflect.DeepEqual(canonical.Response, compose.Response) {
		t.Errorf("response policy drifted between portwing.yaml and the compose example\n canonical: %+v\n compose:   %+v",
			canonical.Response, compose.Response)
	}
}
