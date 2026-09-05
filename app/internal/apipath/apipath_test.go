package apipath

import "testing"

func TestIsLibpodPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "libpod container create", path: "/libpod/containers/create", want: true},
		{name: "libpod pod create", path: "/libpod/pods/create", want: true},
		{name: "libpod info", path: "/libpod/info", want: true},
		{name: "bare libpod without trailing slash", path: "/libpod", want: false},
		{name: "docker containers create", path: "/containers/create", want: false},
		{name: "docker root", path: "/", want: false},
		{name: "empty", path: "", want: false},
		{name: "libpod-prefixed but different resource", path: "/libpodxyz/containers/create", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLibpodPath(tt.path); got != tt.want {
				t.Errorf("IsLibpodPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsNodeUpdatePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "node update", path: "/nodes/node-a/update", want: true},
		{name: "node inspect", path: "/nodes/node-a", want: false},
		{name: "node list", path: "/nodes", want: false},
		{name: "node update wrong tail", path: "/nodes/node-a/remove", want: false},
		{name: "node update missing identifier", path: "/nodes//update", want: false},
		{name: "not a node path", path: "/swarm/update", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNodeUpdatePath(tt.path); got != tt.want {
				t.Errorf("IsNodeUpdatePath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
