package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// exposureSurfaces are the three blocks that carry deny_published_ports,
// allowed_port_host_ips and allowed_networks.
var exposureSurfaces = []struct {
	block   string
	envStem string
	config  func(*RequestBodyConfig) (deny bool, ips, networks []string)
	filter  func(*filter.PolicyConfig) filter.NetworkExposureOptions
	set     func(*RequestBodyConfig, []string, []string)
}{
	{
		"container_create", "CONTAINER_CREATE",
		func(c *RequestBodyConfig) (bool, []string, []string) {
			return c.ContainerCreate.DenyPublishedPorts, c.ContainerCreate.AllowedPortHostIPs, c.ContainerCreate.AllowedNetworks
		},
		func(p *filter.PolicyConfig) filter.NetworkExposureOptions { return p.ContainerCreate.NetworkExposure },
		func(c *RequestBodyConfig, ips, nets []string) {
			c.ContainerCreate.AllowedPortHostIPs, c.ContainerCreate.AllowedNetworks = ips, nets
		},
	},
	{
		"libpod_container_create", "LIBPOD_CONTAINER_CREATE",
		func(c *RequestBodyConfig) (bool, []string, []string) {
			return c.LibpodContainerCreate.DenyPublishedPorts, c.LibpodContainerCreate.AllowedPortHostIPs, c.LibpodContainerCreate.AllowedNetworks
		},
		func(p *filter.PolicyConfig) filter.NetworkExposureOptions {
			return p.LibpodContainerCreate.NetworkExposure
		},
		func(c *RequestBodyConfig, ips, nets []string) {
			c.LibpodContainerCreate.AllowedPortHostIPs, c.LibpodContainerCreate.AllowedNetworks = ips, nets
		},
	},
	{
		"service", "SERVICE",
		func(c *RequestBodyConfig) (bool, []string, []string) {
			return c.Service.DenyPublishedPorts, c.Service.AllowedPortHostIPs, c.Service.AllowedNetworks
		},
		func(p *filter.PolicyConfig) filter.NetworkExposureOptions { return p.Service.NetworkExposure },
		func(c *RequestBodyConfig, ips, nets []string) {
			c.Service.AllowedPortHostIPs, c.Service.AllowedNetworks = ips, nets
		},
	},
}

func TestNetworkExposureDefaultOff(t *testing.T) {
	loaded, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	options := loaded.RequestBody.ToFilterOptions()
	for _, s := range exposureSurfaces {
		if deny, ips, nets := s.config(&loaded.RequestBody); deny || len(ips) != 0 || len(nets) != 0 {
			t.Errorf("request_body.%s restricts exposure by default: %v %v %v", s.block, deny, ips, nets)
		}
		if got := s.filter(&options); got.DenyPublishedPorts || len(got.AllowedPortHostIPs) != 0 || len(got.AllowedNetworks) != 0 {
			t.Errorf("filter options for %s restrict exposure by default: %+v", s.block, got)
		}
	}
}

// TestNetworkExposureMapsOneToOne sets each surface alone from YAML and from
// its environment variables and checks it reaches its own filter option and no
// other surface's.
func TestNetworkExposureMapsOneToOne(t *testing.T) {
	wantIPs := []string{"127.0.0.1", "::1"}
	wantNets := []string{"proxy", "backend"}
	for _, s := range exposureSurfaces {
		sources := map[string]func(t *testing.T) *Config{
			"yaml": func(t *testing.T) *Config {
				path := filepath.Join(t.TempDir(), "sockguard.yaml")
				yaml := "request_body:\n  " + s.block + ":\n    deny_published_ports: true\n    allowed_port_host_ips: [127.0.0.1, \"::1\"]\n    allowed_networks: [proxy, backend]\n"
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
				t.Setenv("SOCKGUARD_REQUEST_BODY_"+s.envStem+"_DENY_PUBLISHED_PORTS", "true")
				t.Setenv("SOCKGUARD_REQUEST_BODY_"+s.envStem+"_ALLOWED_PORT_HOST_IPS", "127.0.0.1,::1")
				t.Setenv("SOCKGUARD_REQUEST_BODY_"+s.envStem+"_ALLOWED_NETWORKS", "proxy,backend")
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
				for _, other := range exposureSurfaces {
					deny, ips, nets := other.config(&cfg.RequestBody)
					got := other.filter(&options)
					if other.block == s.block {
						if !deny || !slices.Equal(ips, wantIPs) || !slices.Equal(nets, wantNets) {
							t.Errorf("config %s = %v %v %v", other.block, deny, ips, nets)
						}
						if !got.DenyPublishedPorts || !slices.Equal(got.AllowedPortHostIPs, wantIPs) || !slices.Equal(got.AllowedNetworks, wantNets) {
							t.Errorf("filter %s = %+v", other.block, got)
						}
					} else {
						if deny || len(ips) != 0 || len(nets) != 0 {
							t.Errorf("config %s = %v %v %v, want zero", other.block, deny, ips, nets)
						}
						if got.DenyPublishedPorts || len(got.AllowedPortHostIPs) != 0 || len(got.AllowedNetworks) != 0 {
							t.Errorf("filter %s = %+v, want zero", other.block, got)
						}
					}
				}
			})
		}
	}
}

func TestNetworkExposureValidation(t *testing.T) {
	for _, s := range exposureSurfaces {
		for _, bad := range []string{"", " 127.0.0.1", "127.0.0.1 ", "localhost", "[::1]", "127.0.0.1:80", "300.1.1.1", "fe80::1%eth0", "10.0.0.0/8"} {
			t.Run(s.block+"/ips/"+bad, func(t *testing.T) {
				cfg := Defaults()
				s.set(&cfg.RequestBody, []string{bad}, nil)
				err := Validate(&cfg)
				if err == nil || !strings.Contains(err.Error(), s.block+".allowed_port_host_ips") {
					t.Fatalf("Validate() error = %v, want a complaint about %s.allowed_port_host_ips", err, s.block)
				}
			})
		}
		for _, bad := range []string{"", " proxy", "proxy "} {
			t.Run(s.block+"/networks/"+bad, func(t *testing.T) {
				cfg := Defaults()
				s.set(&cfg.RequestBody, nil, []string{bad})
				err := Validate(&cfg)
				if err == nil || !strings.Contains(err.Error(), s.block+".allowed_networks") {
					t.Fatalf("Validate() error = %v, want a complaint about %s.allowed_networks", err, s.block)
				}
			})
		}
		t.Run(s.block+"/valid", func(t *testing.T) {
			cfg := Defaults()
			s.set(&cfg.RequestBody, []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0"}, []string{"proxy", "my net"})
			if err := Validate(&cfg); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestNetworkExposureValidationInClientProfile(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.Profiles = []ClientProfileConfig{{Name: "p", RequestBody: RequestBodyConfig{}}}
	cfg.Clients.Profiles[0].RequestBody.ContainerCreate.AllowedPortHostIPs = []string{"nope"}
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "container_create.allowed_port_host_ips") {
		t.Fatalf("Validate() error = %v, want a profile complaint", err)
	}
}
