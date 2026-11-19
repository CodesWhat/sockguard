package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func inspectCreateBody(t *testing.T, opts ContainerCreateOptions, body string) string {
	t.Helper()
	opts.AllowAllCapabilities = true
	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(body))
	reason, err := newContainerCreatePolicy(opts).inspect(nil, req, "/containers/create")
	if err != nil {
		t.Fatalf("inspect(%s) error = %v", body, err)
	}
	return reason
}

func TestContainerCreateRejectsRootLevelHostConfigFields(t *testing.T) {
	for _, key := range legacyRootHostConfigKeys {
		for _, spelling := range []string{key, strings.ToLower(key), strings.ToUpper(key)} {
			body := `{"Image":"alpine","` + spelling + `":null}`
			reason := inspectCreateBody(t, ContainerCreateOptions{}, body)
			if !strings.HasPrefix(reason, "container create denied: HostConfig field ") {
				t.Errorf("%s: reason = %q, want a root-level HostConfig refusal", body, reason)
			}
		}
	}
}

func TestContainerCreateRootLevelHostConfigBypassShapes(t *testing.T) {
	tests := []struct {
		name string
		body string
		deny bool
	}{
		{"privileged and binds with no HostConfig", `{"Image":"alpine","Privileged":true,"Binds":["/:/host"]}`, true},
		{"privileged beside a null HostConfig", `{"Image":"alpine","HostConfig":null,"Privileged":true}`, true},
		{"binds beside an empty HostConfig", `{"Image":"alpine","HostConfig":{},"Binds":["/:/host"]}`, true},
		{"mixed-case key", `{"Image":"alpine","pRiViLeGeD":true}`, true},
		{"escaped key", `{"Image":"alpine","\u0050rivileged":true}`, true},
		{"escaped lowercase key", `{"Image":"alpine","\u0062inds":["/:/h"]}`, true},
		{"false value is still refused", `{"Image":"alpine","Privileged":false}`, true},
		{"legacy resource field", `{"Image":"alpine","Memory":1048576}`, true},
		{"legacy cpuset", `{"Image":"alpine","Cpuset":"0-1"}`, true},
		{"legacy device list", `{"Image":"alpine","Devices":[{"PathOnHost":"/dev/sda"}]}`, true},
		{"nested HostConfig stays supported", `{"Image":"alpine","HostConfig":{"Memory":1048576,"ReadonlyRootfs":true}}`, false},
		{"absent HostConfig", `{"Image":"alpine"}`, false},
		{"null HostConfig", `{"Image":"alpine","HostConfig":null}`, false},
		{"empty HostConfig", `{"Image":"alpine","HostConfig":{}}`, false},
		{"config fields at the root", `{"Image":"alpine","Hostname":"h","Env":["A=b"],"Labels":{"a":"b"},"Volumes":{"/data":{}},"NetworkingConfig":{},"MacAddress":"","User":"1000"}`, false},
		{"nested key named like a root key is not a root key", `{"Image":"alpine","Labels":{"Privileged":"true","Binds":"x"}}`, false},
		{"array body is left to the decode", `[]`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := inspectCreateBody(t, ContainerCreateOptions{}, tt.body)
			if tt.deny && reason == "" {
				t.Fatalf("body allowed: %s", tt.body)
			}
			if !tt.deny && reason != "" {
				t.Fatalf("body denied with %q: %s", reason, tt.body)
			}
		})
	}
}

// TestLegacyRootHostConfigKeysCoverTheInspectedHostConfig fails when a field
// is added to the HostConfig this inspector decodes without also being listed
// as a legacy root-level key, so the two inventories cannot drift apart.
func TestLegacyRootHostConfigKeysCoverTheInspectedHostConfig(t *testing.T) {
	typ := reflect.TypeOf(containerCreateHostConfig{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if name == "" {
			continue
		}
		if _, ok := legacyRootHostConfigKeySet[canonicalFoldKey(name)]; !ok {
			t.Errorf("HostConfig field %q is decoded by the inspector but is not in legacyRootHostConfigKeys", name)
		}
	}
}
