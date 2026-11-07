package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestUnknownKeysBytes(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []string
	}{
		{"empty", "", nil},
		{"clean", "log:\n  level: debug\n", nil},
		{"top level", "bogus: 1\n", []string{"bogus"}},
		{"null unknown", "bogus: null\n", []string{"bogus"}},
		{"empty map unknown", "bogus: {}\n", []string{"bogus"}},
		{"nested null unknown", "log:\n  nope: null\n", []string{"log.nope"}},
		{"list null unknown", "clients:\n  profiles:\n    - name: a\n      nope: null\n", []string{"clients.profiles[0].nope"}},
		{"known null and empty", "log: null\nresponse: {}\nclients:\n  profiles: null\n", nil},
		{"dotted known field", "log.level: debug\n", nil},
		{"case insensitive known fields", "LOG:\n  LEVEL: debug\n", nil},
		{"nested", "log:\n  level: debug\n  nope: 1\n", []string{"log.nope"}},
		{
			"list of structs",
			"clients:\n  profiles:\n    - name: a\n      response:\n        redact_container_env: true\n    - name: b\n      nope: 1\n",
			[]string{"clients.profiles[0].response.redact_container_env", "clients.profiles[1].nope"},
		},
		{"multiple sorted", "zzz: 1\naaa: 2\n", []string{"aaa", "zzz"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnknownKeysBytes([]byte(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnknownKeysIgnoresEnvAndCompatEnv(t *testing.T) {
	t.Setenv("SOCKGUARD_LOG_LEVEL", "debug")
	t.Setenv("SOCKGUARD_TOTALLY_MADE_UP", "1")
	t.Setenv("CONTAINERS", "1")
	t.Setenv("POST", "0")
	t.Setenv("ALLOW_START", "1")

	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte("log:\n  format: json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := UnknownKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("env vars must never read as unknown keys, got %v", got)
	}
}

func TestUnknownKeysFileHandling(t *testing.T) {
	if got, err := UnknownKeys(""); err != nil || got != nil {
		t.Fatalf("empty path: %v %v", got, err)
	}
	if got, err := UnknownKeys(filepath.Join(t.TempDir(), "missing.yaml")); err != nil || got != nil {
		t.Fatalf("missing file: %v %v", got, err)
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("log: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := UnknownKeys(bad); err == nil {
		t.Fatal("malformed YAML must error")
	}
}

func TestUnknownKeysDoesNotChangeLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte("bogus: 1\nlog:\n  nope: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("unknown keys must not fail Load: %v", err)
	}
}

func TestMutationsStaysStrict(t *testing.T) {
	if _, err := LoadBytes([]byte("mutations:\n  nope: 1\n")); err == nil {
		t.Fatal("unknown key under mutations must still fail to load")
	}
}

func TestShippedConfigsHaveNoUnknownKeys(t *testing.T) {
	var files []string
	for _, pattern := range []string{"../../configs/*.yaml", "../../../examples/compose/*/sockguard*.yaml"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	if len(files) == 0 {
		t.Fatal("found no shipped configs")
	}
	for _, f := range files {
		got, err := UnknownKeys(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if len(got) != 0 {
			t.Errorf("%s: unknown keys %v", f, got)
		}
	}
}

func TestLoadWithDataReturnsParsedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	body := []byte("zzz: 1\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, data, err := LoadWithData(path)
	if err != nil || cfg == nil || string(data) != string(body) {
		t.Fatalf("LoadWithData = %v, %q, %v", cfg, data, err)
	}
	if _, data, err := LoadWithData(filepath.Join(t.TempDir(), "none.yaml")); err != nil || data != nil {
		t.Fatalf("missing file: data=%q err=%v", data, err)
	}
}
