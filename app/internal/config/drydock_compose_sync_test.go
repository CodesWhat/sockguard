package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

// TestDrydockComposeExampleInSync guards the embedded compose example against
// drift from the canonical preset. examples/compose/drydock/sockguard.yaml is a
// hand-maintained copy of app/configs/drydock.yaml (its header says "update both
// files together"); a copy that silently diverges ships a broken example — the
// compose file once dropped allowed_runtimes:[runc] and denied every update.
//
// The two must load to the same rules + request-body inspection + response
// policy. The connection envelope (upstream/log/health) and YAML comments are
// allowed to differ — only the security-relevant policy must stay in lockstep.
func TestDrydockComposeExampleInSync(t *testing.T) {
	canonical, err := Load(filepath.Join("..", "..", "configs", "drydock.yaml"))
	if err != nil {
		t.Fatalf("load canonical drydock.yaml: %v", err)
	}
	compose, err := Load(filepath.Join("..", "..", "..", "examples", "compose", "drydock", "sockguard.yaml"))
	if err != nil {
		t.Fatalf("load compose drydock/sockguard.yaml: %v", err)
	}

	if !reflect.DeepEqual(canonical.Rules, compose.Rules) {
		t.Errorf("rules drifted between app/configs/drydock.yaml and examples/compose/drydock/sockguard.yaml\n canonical: %+v\n compose:   %+v",
			canonical.Rules, compose.Rules)
	}
	if !reflect.DeepEqual(canonical.RequestBody, compose.RequestBody) {
		t.Errorf("request_body drifted between drydock.yaml and the compose example\n canonical: %+v\n compose:   %+v",
			canonical.RequestBody, compose.RequestBody)
	}
	if !reflect.DeepEqual(canonical.Response, compose.Response) {
		t.Errorf("response policy drifted between drydock.yaml and the compose example\n canonical: %+v\n compose:   %+v",
			canonical.Response, compose.Response)
	}
}
