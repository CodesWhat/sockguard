package filter

import "testing"

func TestContainerCreateDeniesLegacyLinks(t *testing.T) {
	const denied = "container create denied: legacy container links (HostConfig.Links) are not allowed"
	tests := []struct {
		name string
		body string
		want string
	}{
		{"link to another container", `{"HostConfig":{"Links":["victim:x"]}}`, denied},
		{"link without an alias", `{"HostConfig":{"Links":["victim"]}}`, denied},
		{"several links", `{"HostConfig":{"Links":["a:b","c:d"]}}`, denied},
		{"another key case", `{"HostConfig":{"links":["victim:x"]}}`, denied},
		{"empty list", `{"HostConfig":{"Links":[]}}`, ""},
		{"null list", `{"HostConfig":{"Links":null}}`, ""},
		{"absent", `{"HostConfig":{}}`, ""},
		{"endpoint links are the network policy's", `{"HostConfig":{},"NetworkingConfig":{"EndpointsConfig":{}}}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inspectCreateBody(t, ContainerCreateOptions{}, tt.body); got != tt.want {
				t.Fatalf("reason = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestContainerCreateLinksDoNotLeakAcrossPooledRequests pins that a recycled
// decode target forgets the previous request's links.
func TestContainerCreateLinksDoNotLeakAcrossPooledRequests(t *testing.T) {
	for _, body := range []string{
		`{"HostConfig":{"Links":["victim:x"]}}`,
		`{"HostConfig":{}}`,
		`{"HostConfig":{"Links":["victim:x"]}}`,
		`{}`,
	} {
		denied := body == `{"HostConfig":{"Links":["victim:x"]}}`
		if got := inspectCreateBody(t, ContainerCreateOptions{}, body); (got != "") != denied {
			t.Fatalf("inspect(%s) reason = %q, denied want %v", body, got, denied)
		}
	}
}
