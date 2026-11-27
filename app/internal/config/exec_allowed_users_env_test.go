package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const execAllowedUsersEnvName = "SOCKGUARD_REQUEST_BODY_EXEC_ALLOWED_USERS"

func TestEnvExecAllowedUsersRejectsEmptyEntries(t *testing.T) {
	for _, raw := range []string{"app,", "app,,1000", ",app", ","} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv(execAllowedUsersEnvName, raw)
			if _, err := Load(""); err == nil || !strings.Contains(err.Error(), execAllowedUsersEnvName) {
				t.Fatalf("LoadBytes() = %v, want an error naming %s", err, execAllowedUsersEnvName)
			}
		})
	}
}

func TestEnvExecAllowedUsersAcceptsPlainLists(t *testing.T) {
	for raw, want := range map[string][]string{
		"app":      {"app"},
		"app,1000": {"app", "1000"},
	} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv(execAllowedUsersEnvName, raw)
			cfg, err := Load("")
			if err != nil {
				t.Fatalf("LoadBytes() error = %v", err)
			}
			if !slices.Equal(cfg.RequestBody.Exec.AllowedUsers, want) {
				t.Fatalf("AllowedUsers = %q, want %q", cfg.RequestBody.Exec.AllowedUsers, want)
			}
			if err := Validate(cfg); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestYAMLExecAllowedUsersKeepsEmptyEntry(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml string
		want []string
	}{
		"only empty":    {"request_body:\n  exec:\n    allowed_users: [\"\"]\n", []string{""}},
		"app and empty": {"request_body:\n  exec:\n    allowed_users: [\"app\", \"\"]\n", []string{"app", ""}},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sockguard.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("LoadBytes() error = %v", err)
			}
			if !slices.Equal(cfg.RequestBody.Exec.AllowedUsers, tc.want) {
				t.Fatalf("AllowedUsers = %q, want %q", cfg.RequestBody.Exec.AllowedUsers, tc.want)
			}
			if err := Validate(cfg); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}
