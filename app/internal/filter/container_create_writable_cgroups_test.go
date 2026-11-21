package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestContainerCreateDeniesWritableCgroups(t *testing.T) {
	const denied = "container create denied: writable-cgroups security option is not allowed"
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "bare", body: `{"HostConfig":{"SecurityOpt":["writable-cgroups"]}}`, want: denied},
		{name: "equals true", body: `{"HostConfig":{"SecurityOpt":["writable-cgroups=true"]}}`, want: denied},
		{name: "colon true", body: `{"HostConfig":{"SecurityOpt":["writable-cgroups:true"]}}`, want: denied},
		{name: "numeric one", body: `{"HostConfig":{"SecurityOpt":["writable-cgroups=1"]}}`, want: denied},
		{name: "T spelling", body: `{"HostConfig":{"SecurityOpt":["writable-cgroups=T"]}}`, want: denied},
		{name: "TRUE spelling", body: `{"HostConfig":{"SecurityOpt":["writable-cgroups=TRUE"]}}`, want: denied},
		{name: "upper-case key", body: `{"HostConfig":{"SecurityOpt":["Writable-Cgroups=true"]}}`, want: denied},
		{name: "padded", body: `{"HostConfig":{"SecurityOpt":["  writable-cgroups = true "]}}`, want: denied},
		{name: "unparseable value", body: `{"HostConfig":{"SecurityOpt":["writable-cgroups=maybe"]}}`, want: denied},
		{name: "empty value", body: `{"HostConfig":{"SecurityOpt":["writable-cgroups="]}}`, want: denied},
		{name: "enabling then disabling", body: `{"HostConfig":{"SecurityOpt":["writable-cgroups=true","writable-cgroups=false"]}}`, want: denied},
		{name: "disabling then enabling", body: `{"HostConfig":{"SecurityOpt":["writable-cgroups=false","writable-cgroups"]}}`, want: denied},
		{name: "with readonly rootfs", body: `{"HostConfig":{"ReadonlyRootfs":true,"SecurityOpt":["writable-cgroups=true"]}}`, want: denied},
		{name: "with private cgroupns", body: `{"HostConfig":{"CgroupnsMode":"private","SecurityOpt":["writable-cgroups=true"]}}`, want: denied},
		{name: "explicit false", body: `{"HostConfig":{"SecurityOpt":["writable-cgroups=false"]}}`},
		{name: "explicit 0", body: `{"HostConfig":{"SecurityOpt":["writable-cgroups:0"]}}`},
		{name: "unrelated option", body: `{"HostConfig":{"SecurityOpt":["no-new-privileges","writable-cgroupsx=true"]}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))
			reason, err := newContainerCreatePolicy(ContainerCreateOptions{AllowAllCapabilities: true}).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.want {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.want)
			}
		})
	}
}
