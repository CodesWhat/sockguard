package apipath

import (
	"net/http"
	"testing"
)

func TestDockerContainerRoute(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method, path, name, action string
		ok                         bool
	}{
		{http.MethodPost, "/containers/web/stop", "web", "stop", true},
		{http.MethodPost, "/containers/A/x/stop", "A/x", "stop", true},
		{http.MethodPost, "/containers/A/x/y/kill", "A/x/y", "kill", true},
		{http.MethodPost, "/containers/A/x/exec", "A/x", "exec", true},
		{http.MethodPost, "/containers/A/x/attach", "A/x", "attach", true},
		{http.MethodGet, "/containers/A/x/attach/ws", "A/x", "attach/ws", true},
		{http.MethodGet, "/containers/A/x/json", "A/x", "json", true},
		{http.MethodGet, "/containers/A/x/archive", "A/x", "archive", true},
		{http.MethodHead, "/containers/A/x/archive", "A/x", "archive", true},
		{http.MethodPut, "/containers/A/x/archive", "A/x", "archive", true},
		{http.MethodPost, "/containers/A/x/update", "A/x", "update", true},
		{http.MethodDelete, "/containers/A/x", "A/x", "", true},
		{http.MethodDelete, "/containers/web", "web", "", true},
		{http.MethodDelete, "/containers/web/checkpoints/cp", "web", "checkpoints", true},
		{http.MethodDelete, "/containers/a/b/checkpoints/cp", "a/b/checkpoints/cp", "", true},
		{http.MethodDelete, "/containers/a/checkpoints/cp/extra", "a/checkpoints/cp/extra", "", true},
		{http.MethodDelete, "/containers/a/checkpoints/", "a/checkpoints/", "", true},
		{http.MethodGet, "/containers/web", "web", "", true},
		// A name that is itself an action word still resolves like dockerd.
		{http.MethodPost, "/containers/create/start", "create", "start", true},
		{http.MethodPost, "/containers/json/stop", "json", "stop", true},
		// An unregistered trailing segment makes the whole remainder the name.
		{http.MethodPost, "/containers/A/x/unknown", "A/x/unknown", "", true},
		{http.MethodGet, "/containers/A/x/start", "A/x/start", "", true},
		// Collections and other families.
		{http.MethodGet, "/containers/json", "", "", false},
		{http.MethodPost, "/containers/create", "", "", false},
		{http.MethodPost, "/containers/prune", "", "", false},
		{http.MethodGet, "/containers/", "", "", false},
		{http.MethodGet, "/networks/x", "", "", false},
		{http.MethodPost, "/libpod/containers/x/stop", "", "", false},
	}
	for _, tt := range tests {
		name, action, ok := DockerContainerRoute(tt.method, tt.path)
		if name != tt.name || action != tt.action || ok != tt.ok {
			t.Errorf("DockerContainerRoute(%s, %q) = (%q, %q, %v), want (%q, %q, %v)", tt.method, tt.path, name, action, ok, tt.name, tt.action, tt.ok)
		}
	}
}

func TestDockerContainerAction(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		path, action, name string
		ok                 bool
	}{
		{"/containers/web/exec", "exec", "web", true},
		{"/containers/A/x/exec", "exec", "A/x", true},
		{"/containers/exec", "exec", "", false},
		{"/containers//exec", "exec", "", true},
		{"/libpod/containers/web/exec", "exec", "", false},
		{"/containers/web/execx", "exec", "", false},
	} {
		name, ok := DockerContainerAction(tt.path, tt.action)
		if name != tt.name || ok != tt.ok {
			t.Errorf("DockerContainerAction(%q, %q) = (%q, %v), want (%q, %v)", tt.path, tt.action, name, ok, tt.name, tt.ok)
		}
	}
}
