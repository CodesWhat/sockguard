package filter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPluginBooleanPrivilegesRequireTheirOwnGrant(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		grant PluginOptions
	}{
		{"host ipc namespace", PluginOptions{AllowHostIPC: true}},
		{"host pid namespace", PluginOptions{AllowHostPID: true}},
		{"allow-all-devices", PluginOptions{AllowAllDevices: true}},
	} {
		for _, endpoint := range []string{"/plugins/pull?remote=registry.example/acme/plugin:1", "/plugins/acme/upgrade?remote=registry.example/acme/plugin:1"} {
			for _, enabled := range []bool{false, true} {
				options := PluginOptions{}
				if enabled {
					options = tc.grant
				}
				options.AllowedRegistries = []string{"registry.example"}
				allow, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/plugins/**", Action: ActionAllow})
				if err != nil {
					t.Fatal(err)
				}
				payload, err := json.Marshal([]pluginPrivilege{{Name: tc.name, Value: []string{"true"}}})
				if err != nil {
					t.Fatal(err)
				}
				reached := false
				handler := MiddlewareWithOptions([]*CompiledRule{allow}, testLogger(), Options{PolicyConfig: PolicyConfig{Plugin: options}})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached = true
					w.WriteHeader(http.StatusNoContent)
				}))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1.44"+endpoint, strings.NewReader(string(payload))))
				want := http.StatusForbidden
				if enabled {
					want = http.StatusNoContent
				}
				if rec.Code != want || reached != enabled {
					t.Errorf("%s %s grant=%v: reached=%v status=%d want=%d", tc.name, endpoint, enabled, reached, rec.Code, want)
				}
			}
		}
	}
}
