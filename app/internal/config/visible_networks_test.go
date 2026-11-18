package config

import (
	"strings"
	"testing"
)

func TestValidateVisibleNetworks(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		wantErr string
	}{
		{name: "none", values: nil},
		{name: "plain names", values: []string{"proxy", "app_default", "my-net.1"}},
		{name: "empty entry", values: []string{"proxy", ""}, wantErr: "response.visible_networks[1] must be non-empty"},
		{name: "blank entry", values: []string{"   "}, wantErr: "response.visible_networks[0] must be non-empty"},
		{name: "star", values: []string{"proxy-*"}, wantErr: "response.visible_networks[0] must be an exact network name"},
		{name: "question mark", values: []string{"pro?y"}, wantErr: "response.visible_networks[0] must be an exact network name"},
		{name: "bracket", values: []string{"proxy[1]"}, wantErr: "response.visible_networks[0] must be an exact network name"},
		{name: "comma", values: []string{"a,b"}, wantErr: "response.visible_networks[0] must not contain commas"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Response.VisibleNetworks = tt.values
			err := Validate(&cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateVisibleNetworksErrorsDoNotEchoValues(t *testing.T) {
	cfg := Defaults()
	cfg.Response.VisibleNetworks = []string{"secret-net-*"}
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("Validate() = nil, want error")
	}
	if strings.Contains(err.Error(), "secret-net") {
		t.Fatalf("Validate() = %q, must not echo the offending value", err)
	}
}

func TestValidateRejectsBadProfileVisibleNetworks(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.Profiles = []ClientProfileConfig{{
		Name:     "traefik",
		Response: ClientProfileResponseConfig{VisibleNetworks: []string{"proxy", "bad*"}},
		Rules:    []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}},
	}}
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "response.visible_networks[1]") {
		t.Fatalf("Validate() = %v, want profile visible_networks[1] rejection", err)
	}
}

func TestLoadBytesReadsVisibleNetworks(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
response:
  visible_networks:
    - proxy
clients:
  profiles:
    - name: traefik
      response:
        visible_networks:
          - edge
      rules:
        - match: { method: GET, path: "/_ping" }
          action: allow
        - match: { method: "*", path: "/**" }
          action: deny
`))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}
	if got := cfg.Response.VisibleNetworks; len(got) != 1 || got[0] != "proxy" {
		t.Errorf("Response.VisibleNetworks = %#v, want [proxy]", got)
	}
	if got := cfg.Clients.Profiles[0].Response.VisibleNetworks; len(got) != 1 || got[0] != "edge" {
		t.Errorf("profile Response.VisibleNetworks = %#v, want [edge]", got)
	}
}
