package filter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// SwarmKit expands Go templates in mount fields after the request is judged,
// so the policy refuses templates wherever they can reach a host path.
func TestServiceInspectMountTemplatesAndUnnormalizableSources(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{AllowedBindMounts: []string{"/srv/data"}, AllowAllRegistries: true})
	mount := func(m map[string]any) string {
		raw, err := json.Marshal(map[string]any{"TaskTemplate": map[string]any{"ContainerSpec": map[string]any{
			"Image": "alpine", "Mounts": []any{m},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	volume := func(opts map[string]string) map[string]any {
		return map[string]any{"Type": "volume", "Source": "data", "Target": "/d",
			"VolumeOptions": map[string]any{"DriverConfig": map[string]any{"Name": "local", "Options": opts}}}
	}

	tests := []struct {
		name string
		body string
		want string // substring of the denial; empty means allowed
	}{
		{name: "templated bind source", body: mount(map[string]any{"Type": "bind", "Source": `{{print "/"}}`, "Target": "/h"}), want: "template expressions are not allowed in a bind mount source"},
		{name: "allowlisted prefix expanding to root", body: mount(map[string]any{"Type": "bind", "Source": `/srv/data/{{".."}}/{{".."}}`, "Target": "/h"}), want: "template expressions are not allowed in a bind mount source"},
		{name: "templated source on a bind with no Type", body: mount(map[string]any{"Source": `/srv/data/{{".."}}`, "Target": "/h"}), want: "template expressions are not allowed in a bind mount source"},
		{name: "nfs o template hides a bind", body: mount(volume(map[string]string{"type": "nfs", "o": `{{"bind"}}`, "device": "/"})), want: "template expressions are not allowed in volume driver options"},
		{name: "template in an option key", body: mount(volume(map[string]string{`{{"device"}}`: "/", "type": "nfs"})), want: "template expressions are not allowed in volume driver options"},
		{name: "template in a third-party driver option", body: mount(map[string]any{"Type": "volume", "Source": "d", "Target": "/d",
			"VolumeOptions": map[string]any{"DriverConfig": map[string]any{"Name": "other", "Options": map[string]string{"x": "{{.Task.ID}}"}}}}), want: "template expressions are not allowed in volume driver options"},
		{name: "relative bind source is denied, not skipped", body: mount(map[string]any{"Type": "bind", "Source": "etc", "Target": "/h"}), want: "must be an absolute path"},
		{name: "empty bind source is denied", body: mount(map[string]any{"Type": "bind", "Source": "", "Target": "/h"}), want: "must be an absolute path"},
		{name: "empty Type is a bind to SwarmKit", body: mount(map[string]any{"Source": "/etc", "Target": "/h"}), want: `bind mount source "/etc" is not allowlisted`},
		{name: "volume name template stays allowed", body: mount(map[string]any{"Type": "volume", "Source": "{{.Service.Name}}-{{.Task.Slot}}", "Target": "/d"})},
		{name: "plain allowlisted bind", body: mount(map[string]any{"Type": "bind", "Source": "/srv/data/app", "Target": "/h"})},
		{name: "tmpfs target template is not a host path", body: mount(map[string]any{"Type": "tmpfs", "Target": "/{{.Task.Slot}}"})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(tt.body))
			got, err := policy.inspect(nil, req, "/services/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if tt.want == "" && got != "" || tt.want != "" && !strings.Contains(got, tt.want) {
				t.Fatalf("denyReason = %q, want %q", got, tt.want)
			}
		})
	}
}
