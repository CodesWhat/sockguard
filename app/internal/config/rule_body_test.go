package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMatchBodyParsesAndValidates pins match.body: it loads, it reaches the
// rule, and the same authoring mistakes match.query refuses are refused here.
func TestMatchBodyParsesAndValidates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	yaml := `upstream:
  socket: /var/run/docker.sock
rules:
  - match:
      method: POST
      path: /libpod/containers/create
      body: { name: ["team-app-*"] }
    action: allow
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Rules[0].Match.Body["name"]; len(got) != 1 || got[0] != "team-app-*" {
		t.Fatalf("match.body did not load: %v", cfg.Rules[0].Match.Body)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestMatchBodyValidationRefusesAuthoringMistakes(t *testing.T) {
	for name, yaml := range map[string]string{
		"empty field name": `upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: POST, path: /x, body: { "": ["a"] } }
    action: allow
`,
		"no patterns": `upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: POST, path: /x, body: { name: [] } }
    action: allow
`,
		"profile rule empty field": `upstream:
  socket: /var/run/docker.sock
clients:
  profiles:
    - name: p
      rules:
        - match: { method: POST, path: /x, body: { "": ["a"] } }
          action: allow
`,
		// A lowercase-s and a long-s key address the same field to the
		// matcher, even though their lowercasings differ.
		"case-folded field names": `upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: POST, path: /x, body: { "ſystemd": ["always"], "systemd": ["false"] } }
    action: deny
`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sockguard.yaml")
			if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			err = Validate(cfg)
			if err == nil {
				t.Fatalf("Validate() accepted %s", name)
			}
			if !strings.Contains(err.Error(), "match.body") {
				t.Fatalf("error %q does not name match.body", err.Error())
			}
		})
	}
}
