package config

import (
	"os"
	"path/filepath"
	"testing"
)

// A key Viper knows only because the YAML file declares it is still a key the
// environment overrides, so the same variable is unknown for one config and
// known for another. The Load assertion in the middle is what makes the
// silence correct rather than merely convenient: clients.global_concurrency is
// a pointer block, registerDefaults skips it, and the configuration reference
// calls it YAML-only — but declaring it puts its leaf on Viper's key list, and
// the environment wins from there.
func TestUnknownEnvVarsAcceptsKeysTheConfigFileDeclares(t *testing.T) {
	const name = "SOCKGUARD_CLIENTS_GLOBAL_CONCURRENCY_MAX_INFLIGHT"
	environ := []string{name + "=9"}

	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	body := "clients:\n  global_concurrency:\n    max_inflight: 5\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Schema alone: nothing binds the variable, so it is reported.
	unknown := UnknownEnvVars("", environ)
	if len(unknown) != 1 || unknown[0].Name != name {
		t.Fatalf("UnknownEnvVars(\"\") = %+v, want exactly %s", unknown, name)
	}

	// With the block declared, Load really does take the variable's value.
	t.Setenv(name, "9")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Clients.GlobalConcurrency == nil {
		t.Fatal("expected the declared global_concurrency block to survive Load")
	}
	if got := cfg.Clients.GlobalConcurrency.MaxInflight; got != 9 {
		t.Fatalf("max_inflight = %d, want the env override 9", got)
	}

	// So reporting it as ignored would be the same failure this warning
	// exists to catch, pointed the other way.
	if unknown := UnknownEnvVars(path, environ); len(unknown) != 0 {
		t.Fatalf("UnknownEnvVars(%q) = %+v, want none", path, unknown)
	}
}

// An unreadable or malformed config file must not turn every variable into a
// known one, and must not stop the schema half of the check from answering.
// Load reports the file problem itself, moments later.
func TestUnknownEnvVarsSurvivesAnUnusableConfigFile(t *testing.T) {
	const name = "SOCKGUARD_LISTEN_SOCKT"
	environ := []string{name + "=/run/typo.sock"}

	malformed := filepath.Join(t.TempDir(), "sockguard.yaml")
	if err := os.WriteFile(malformed, []byte("listen: [unterminated\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	for _, path := range []string{malformed, filepath.Join(t.TempDir(), "absent.yaml")} {
		unknown := UnknownEnvVars(path, environ)
		if len(unknown) != 1 || unknown[0].Name != name {
			t.Fatalf("UnknownEnvVars(%q) = %+v, want exactly %s", path, unknown, name)
		}
		if unknown[0].Suggestion != "SOCKGUARD_LISTEN_SOCKET" {
			t.Fatalf("UnknownEnvVars(%q) suggestion = %q, want SOCKGUARD_LISTEN_SOCKET", path, unknown[0].Suggestion)
		}
	}
}
