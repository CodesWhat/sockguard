package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/filter"
)

// logPathGates is allow_log_path on each create route: its YAML key, its
// environment variable, and how to read it off a loaded config and off the
// filter options built from one. The two share a name and nothing else.
var logPathGates = []struct {
	key    string
	envVar string
	config func(*RequestBodyConfig) *bool
	filter func(*filter.PolicyConfig) *bool
}{
	{
		"container_create.allow_log_path", "SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_ALLOW_LOG_PATH",
		func(c *RequestBodyConfig) *bool { return &c.ContainerCreate.AllowLogPath },
		func(p *filter.PolicyConfig) *bool { return &p.ContainerCreate.AllowLogPath },
	},
	{
		"libpod_container_create.allow_log_path", "SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOW_LOG_PATH",
		func(c *RequestBodyConfig) *bool { return &c.LibpodContainerCreate.AllowLogPath },
		func(p *filter.PolicyConfig) *bool { return &p.LibpodContainerCreate.AllowLogPath },
	},
}

// TestLogPathGatesDefaultOff pins that a client-supplied log path is refused
// on both create routes until its option is set.
func TestLogPathGatesDefaultOff(t *testing.T) {
	defaults := Defaults()
	loaded, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	for _, gate := range logPathGates {
		if *gate.config(&defaults.RequestBody) {
			t.Errorf("Defaults() has request_body.%s on, want off", gate.key)
		}
		if *gate.config(&loaded.RequestBody) {
			t.Errorf("Load() with no file has request_body.%s on, want off", gate.key)
		}
		options := loaded.RequestBody.ToFilterOptions()
		if *gate.filter(&options) {
			t.Errorf("filter option for request_body.%s is on with no config, want off", gate.key)
		}
	}
}

// TestLogPathGatesMapOneToOne turns each gate on alone, from YAML and from
// its environment variable, and checks that it reaches its own filter option
// and not the other route's. The compat option wired to the native field, or
// the other way round, would open a route the operator never asked to open.
func TestLogPathGatesMapOneToOne(t *testing.T) {
	for _, gate := range logPathGates {
		block, option, found := strings.Cut(gate.key, ".")
		if !found {
			t.Fatalf("gate key %q has no block", gate.key)
		}
		sources := map[string]func(t *testing.T) *Config{
			"yaml": func(t *testing.T) *Config {
				path := filepath.Join(t.TempDir(), "sockguard.yaml")
				yaml := "request_body:\n  " + block + ":\n    " + option + ": true\n"
				if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
					t.Fatalf("write config: %v", err)
				}
				cfg, err := Load(path)
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				return cfg
			},
			"env": func(t *testing.T) *Config {
				t.Setenv(gate.envVar, "true")
				cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				return cfg
			},
		}
		for source, load := range sources {
			t.Run(gate.key+"/"+source, func(t *testing.T) {
				cfg := load(t)
				options := cfg.RequestBody.ToFilterOptions()
				for _, other := range logPathGates {
					want := other.key == gate.key
					if got := *other.config(&cfg.RequestBody); got != want {
						t.Errorf("config request_body.%s = %t, want %t", other.key, got, want)
					}
					if got := *other.filter(&options); got != want {
						t.Errorf("filter option for request_body.%s = %t, want %t", other.key, got, want)
					}
				}
			})
		}
	}
}

// TestLogPathGateValidatesOnAndOff pins that the option needs nothing else set
// to be valid either way, on both routes together.
func TestLogPathGateValidatesOnAndOff(t *testing.T) {
	for _, on := range []bool{false, true} {
		cfg := Defaults()
		for _, gate := range logPathGates {
			*gate.config(&cfg.RequestBody) = on
		}
		if err := Validate(&cfg); err != nil {
			t.Errorf("Validate() with allow_log_path=%t on both routes: %v", on, err)
		}
	}
}
