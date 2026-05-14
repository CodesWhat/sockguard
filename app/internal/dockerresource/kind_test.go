package dockerresource

import "testing"

func TestInspectPath(t *testing.T) {
	tests := []struct {
		name       string
		kind       Kind
		identifier string
		wantPath   string
		wantOK     bool
	}{
		{name: "container", kind: KindContainer, identifier: "abc123", wantPath: "/containers/abc123/json", wantOK: true},
		{name: "image", kind: KindImage, identifier: "nginx:latest", wantPath: "/images/nginx:latest/json", wantOK: true},
		{name: "network", kind: KindNetwork, identifier: "bridge", wantPath: "/networks/bridge", wantOK: true},
		{name: "volume", kind: KindVolume, identifier: "data", wantPath: "/volumes/data", wantOK: true},
		{name: "service", kind: KindService, identifier: "web", wantPath: "/services/web", wantOK: true},
		{name: "task", kind: KindTask, identifier: "task-1", wantPath: "/tasks/task-1", wantOK: true},
		{name: "secret", kind: KindSecret, identifier: "db-pwd", wantPath: "/secrets/db-pwd", wantOK: true},
		{name: "config", kind: KindConfig, identifier: "app-cfg", wantPath: "/configs/app-cfg", wantOK: true},
		{name: "node", kind: KindNode, identifier: "manager-1", wantPath: "/nodes/manager-1", wantOK: true},
		{name: "swarm has no identifier", kind: KindSwarm, identifier: "ignored", wantPath: "/swarm", wantOK: true},
		{name: "unknown kind", kind: Kind("unknown"), identifier: "abc", wantPath: "", wantOK: false},
		{name: "empty kind", kind: Kind(""), identifier: "abc", wantPath: "", wantOK: false},
		{name: "identifier is path-escaped", kind: KindContainer, identifier: "name with spaces/and slashes", wantPath: "/containers/name%20with%20spaces%2Fand%20slashes/json", wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := InspectPath(tt.kind, tt.identifier)
			if got != tt.wantPath || ok != tt.wantOK {
				t.Fatalf("InspectPath(%q, %q) = (%q, %v), want (%q, %v)", tt.kind, tt.identifier, got, ok, tt.wantPath, tt.wantOK)
			}
		})
	}
}
