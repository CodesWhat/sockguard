package upstream

import (
	"strings"
	"testing"
)

func TestParseEndpointAddressRejections(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ raw, want string }{
		{"tcp://[::1", "upstream endpoint"},
		{"tcp:///path", "missing host:port"},
		{"tcp://user@host:2375", "userinfo"},
		{"tcp://host:2375?x=1", "userinfo"},
		{"tcp://host:2375#frag", "userinfo"},
		{"ftp://host:21", "unsupported"},
	} {
		if _, err := parseEndpointAddress(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("parseEndpointAddress(%q) err = %v, want one containing %q", tc.raw, err, tc.want)
		}
	}
}

func TestParseDockerHostEdges(t *testing.T) {
	t.Parallel()
	if got, network, err := parseDockerHost("unix://"); err != nil || got != "unix:///var/run/docker.sock" || network != "unix" {
		t.Fatalf("parseDockerHost(unix://) = (%q, %q, %v)", got, network, err)
	}
	for _, raw := range []string{"unix://unix://x", "tcp://tcp://x", "tcp://host:notaport", "ssh://host"} {
		if _, _, err := parseDockerHost(raw); err == nil {
			t.Fatalf("parseDockerHost(%q) succeeded, want error", raw)
		}
	}
}

func TestBuildEndpointAndValidateSpecRejectUnknownSchemes(t *testing.T) {
	t.Parallel()
	spec := EndpointSpec{Address: "ftp://host:21"}
	if _, err := BuildEndpoint(spec); err == nil {
		t.Fatal("BuildEndpoint accepted an ftp scheme")
	}
	if err := ValidateSpec(spec); err == nil {
		t.Fatal("ValidateSpec accepted an ftp scheme")
	}
}
