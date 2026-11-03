package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// logDriverSurfaces are the four blocks that carry allowed_log_drivers and
// allowed_log_endpoint_options: how to read each pair off a loaded config and
// off the filter options built from one.
var logDriverSurfaces = []struct {
	block   string
	envStem string
	config  func(*RequestBodyConfig) (drivers, endpoints []string)
	filter  func(*filter.PolicyConfig) (drivers, endpoints []string)
}{
	{
		"container_create", "CONTAINER_CREATE",
		func(c *RequestBodyConfig) ([]string, []string) {
			return c.ContainerCreate.AllowedLogDrivers, c.ContainerCreate.AllowedLogEndpointOptions
		},
		func(p *filter.PolicyConfig) ([]string, []string) {
			return p.ContainerCreate.AllowedLogDrivers, p.ContainerCreate.AllowedLogEndpointOptions
		},
	},
	{
		"libpod_container_create", "LIBPOD_CONTAINER_CREATE",
		func(c *RequestBodyConfig) ([]string, []string) {
			return c.LibpodContainerCreate.AllowedLogDrivers, c.LibpodContainerCreate.AllowedLogEndpointOptions
		},
		func(p *filter.PolicyConfig) ([]string, []string) {
			return p.LibpodContainerCreate.AllowedLogDrivers, p.LibpodContainerCreate.AllowedLogEndpointOptions
		},
	},
	{
		"service", "SERVICE",
		func(c *RequestBodyConfig) ([]string, []string) {
			return c.Service.AllowedLogDrivers, c.Service.AllowedLogEndpointOptions
		},
		func(p *filter.PolicyConfig) ([]string, []string) {
			return p.Service.AllowedLogDrivers, p.Service.AllowedLogEndpointOptions
		},
	},
	{
		"libpod_play_kube", "LIBPOD_PLAY_KUBE",
		func(c *RequestBodyConfig) ([]string, []string) {
			return c.LibpodPlayKube.AllowedLogDrivers, c.LibpodPlayKube.AllowedLogEndpointOptions
		},
		func(p *filter.PolicyConfig) ([]string, []string) {
			return p.LibpodPlayKube.AllowedLogDrivers, p.LibpodPlayKube.AllowedLogEndpointOptions
		},
	},
}

// TestLogDriverAllowlistDefaultOff pins that no surface restricts log drivers
// until its list is set.
func TestLogDriverAllowlistDefaultOff(t *testing.T) {
	loaded, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	options := loaded.RequestBody.ToFilterOptions()
	for _, s := range logDriverSurfaces {
		if d, e := s.config(&loaded.RequestBody); len(d) != 0 || len(e) != 0 {
			t.Errorf("request_body.%s has log driver lists by default: %v %v", s.block, d, e)
		}
		if d, e := s.filter(&options); len(d) != 0 || len(e) != 0 {
			t.Errorf("filter options for %s carry log driver lists by default: %v %v", s.block, d, e)
		}
	}
}

// TestLogDriverAllowlistMapsOneToOne sets each surface alone from YAML and
// from its environment variables, and checks that it reaches its own filter
// option and no other surface's.
func TestLogDriverAllowlistMapsOneToOne(t *testing.T) {
	wantDrivers := []string{"json-file", "local"}
	wantEndpoints := []string{"syslog-address"}
	for _, s := range logDriverSurfaces {
		sources := map[string]func(t *testing.T) *Config{
			"yaml": func(t *testing.T) *Config {
				path := filepath.Join(t.TempDir(), "sockguard.yaml")
				yaml := "request_body:\n  " + s.block + ":\n    allowed_log_drivers: [json-file, local]\n    allowed_log_endpoint_options: [syslog-address]\n"
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
				t.Setenv("SOCKGUARD_REQUEST_BODY_"+s.envStem+"_ALLOWED_LOG_DRIVERS", "json-file,local")
				t.Setenv("SOCKGUARD_REQUEST_BODY_"+s.envStem+"_ALLOWED_LOG_ENDPOINT_OPTIONS", "syslog-address")
				cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				return cfg
			},
		}
		for source, load := range sources {
			t.Run(s.block+"/"+source, func(t *testing.T) {
				cfg := load(t)
				options := cfg.RequestBody.ToFilterOptions()
				for _, other := range logDriverSurfaces {
					for name, read := range map[string]func() ([]string, []string){
						"config": func() ([]string, []string) { return other.config(&cfg.RequestBody) },
						"filter": func() ([]string, []string) { return other.filter(&options) },
					} {
						d, e := read()
						if other.block == s.block {
							if !slices.Equal(d, wantDrivers) || !slices.Equal(e, wantEndpoints) {
								t.Errorf("%s %s = %v %v, want %v %v", name, other.block, d, e, wantDrivers, wantEndpoints)
							}
						} else if len(d) != 0 || len(e) != 0 {
							t.Errorf("%s %s = %v %v, want empty", name, other.block, d, e)
						}
					}
				}
			})
		}
	}
}

func TestLogDriverAllowlistValidation(t *testing.T) {
	for _, s := range logDriverSurfaces {
		for _, field := range []string{"allowed_log_drivers", "allowed_log_endpoint_options"} {
			for _, bad := range []string{"", " json-file", "json-file "} {
				t.Run(s.block+"/"+field+"/"+strings.TrimSpace(bad)+"/"+bad, func(t *testing.T) {
					cfg := Defaults()
					switch s.block {
					case "container_create":
						set(field, &cfg.RequestBody.ContainerCreate.AllowedLogDrivers, &cfg.RequestBody.ContainerCreate.AllowedLogEndpointOptions, bad)
					case "libpod_container_create":
						set(field, &cfg.RequestBody.LibpodContainerCreate.AllowedLogDrivers, &cfg.RequestBody.LibpodContainerCreate.AllowedLogEndpointOptions, bad)
					case "service":
						set(field, &cfg.RequestBody.Service.AllowedLogDrivers, &cfg.RequestBody.Service.AllowedLogEndpointOptions, bad)
					case "libpod_play_kube":
						set(field, &cfg.RequestBody.LibpodPlayKube.AllowedLogDrivers, &cfg.RequestBody.LibpodPlayKube.AllowedLogEndpointOptions, bad)
					}
					err := Validate(&cfg)
					if err == nil || !strings.Contains(err.Error(), s.block+"."+field) {
						t.Fatalf("Validate() error = %v, want a complaint about %s.%s", err, s.block, field)
					}
				})
			}
		}
		t.Run(s.block+"/valid", func(t *testing.T) {
			cfg := Defaults()
			cfg.RequestBody.ContainerCreate.AllowedLogDrivers = []string{"json-file"}
			cfg.RequestBody.LibpodContainerCreate.AllowedLogDrivers = []string{"journald"}
			cfg.RequestBody.Service.AllowedLogDrivers = []string{"json-file"}
			cfg.RequestBody.LibpodPlayKube.AllowedLogDrivers = []string{"journald"}
			cfg.RequestBody.LibpodPlayKube.AllowedLogEndpointOptions = []string{"fluentd-address"}
			if err := Validate(&cfg); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func set(field string, drivers, endpoints *[]string, value string) {
	if field == "allowed_log_drivers" {
		*drivers = []string{value}
		return
	}
	*endpoints = []string{value}
}
