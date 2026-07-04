package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

// TestComposeExamplesInSyncWithCanonicalPresets guards every hand-maintained
// examples/compose/*/sockguard.yaml copy against drift from the canonical
// preset it mirrors. Each example's header says "update both files together";
// a copy that silently diverges ships a broken example. This bit github-actions-runner
// and gitlab-runner concretely: both example copies were missing
// insecure_allow_body_blind_writes / insecure_allow_read_exfiltration that
// the canonical presets carry, so `sockguard serve --config <example>`
// failed startup validation and `docker compose up` crash-looped — with no
// test catching it because only drydock and portwing had a sync guard.
//
// Add a new entry here whenever a new examples/compose/*/sockguard.yaml is
// introduced as a copy of an app/configs/*.yaml preset, so future drift is
// caught automatically instead of requiring a bespoke test per example.
//
// The connection envelope (upstream/log/health) and YAML comments are
// allowed to differ between canonical and example — only the
// security-relevant policy (rules, request-body inspection, response
// redaction, and the insecure_* acknowledgment flags) must stay in
// lockstep.
func TestComposeExamplesInSyncWithCanonicalPresets(t *testing.T) {
	cases := []struct {
		name      string
		canonical string
		example   string
	}{
		{
			name:      "drydock",
			canonical: filepath.Join("..", "..", "configs", "drydock.yaml"),
			example:   filepath.Join("..", "..", "..", "examples", "compose", "drydock", "sockguard.yaml"),
		},
		{
			// The compose example directory runs Portwing standalone against
			// the shared docker.sock (no nested compose stack of its own —
			// see examples/compose/portwing/docker-compose.yml), so
			// portwing.yaml is the correct comparison target, not
			// portwing-with-compose.yaml.
			name:      "portwing",
			canonical: filepath.Join("..", "..", "configs", "portwing.yaml"),
			example:   filepath.Join("..", "..", "..", "examples", "compose", "portwing", "sockguard.yaml"),
		},
		{
			name:      "github-actions-runner",
			canonical: filepath.Join("..", "..", "configs", "github-actions-runner.yaml"),
			example:   filepath.Join("..", "..", "..", "examples", "compose", "github-actions-runner", "sockguard.yaml"),
		},
		{
			name:      "gitlab-runner",
			canonical: filepath.Join("..", "..", "configs", "gitlab-runner.yaml"),
			example:   filepath.Join("..", "..", "..", "examples", "compose", "gitlab-runner", "sockguard.yaml"),
		},
		{
			// examples/compose/tri-tool/sockguard.yaml is a third hand-copy
			// of app/configs/portwing.yaml (the tri-tool stack runs sockguard
			// -> Portwing -> drydock with the plain, no-exec Portwing
			// preset), independent of examples/compose/portwing/sockguard.yaml.
			name:      "tri-tool (portwing leg)",
			canonical: filepath.Join("..", "..", "configs", "portwing.yaml"),
			example:   filepath.Join("..", "..", "..", "examples", "compose", "tri-tool", "sockguard.yaml"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			canonical, err := Load(tc.canonical)
			if err != nil {
				t.Fatalf("load canonical %s: %v", tc.canonical, err)
			}
			example, err := Load(tc.example)
			if err != nil {
				t.Fatalf("load example %s: %v", tc.example, err)
			}

			if !reflect.DeepEqual(canonical.Rules, example.Rules) {
				t.Errorf("rules drifted between %s and %s\n canonical: %+v\n example:   %+v",
					tc.canonical, tc.example, canonical.Rules, example.Rules)
			}
			if !reflect.DeepEqual(canonical.RequestBody, example.RequestBody) {
				t.Errorf("request_body drifted between %s and %s\n canonical: %+v\n example:   %+v",
					tc.canonical, tc.example, canonical.RequestBody, example.RequestBody)
			}
			if !reflect.DeepEqual(canonical.Response, example.Response) {
				t.Errorf("response policy drifted between %s and %s\n canonical: %+v\n example:   %+v",
					tc.canonical, tc.example, canonical.Response, example.Response)
			}
			if canonical.InsecureAllowBodyBlindWrites != example.InsecureAllowBodyBlindWrites {
				t.Errorf("insecure_allow_body_blind_writes drifted between %s (%v) and %s (%v)",
					tc.canonical, canonical.InsecureAllowBodyBlindWrites, tc.example, example.InsecureAllowBodyBlindWrites)
			}
			if canonical.InsecureAllowReadExfiltration != example.InsecureAllowReadExfiltration {
				t.Errorf("insecure_allow_read_exfiltration drifted between %s (%v) and %s (%v)",
					tc.canonical, canonical.InsecureAllowReadExfiltration, tc.example, example.InsecureAllowReadExfiltration)
			}
		})
	}
}
