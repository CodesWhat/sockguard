package filter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContainerUpdateDeniesRestartPolicyByDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/update", strings.NewReader(`{"RestartPolicy":{"Name":"always"}}`))

	reason, err := newContainerUpdatePolicy(ContainerUpdateOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "container update denied: restart policy changes are not allowed" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestContainerUpdateDeniesResourceControlsByDefault(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "memory", body: `{"Memory":0}`},
		{name: "nano cpus", body: `{"NanoCpus":2000000000}`},
		{name: "pids limit", body: `{"PidsLimit":-1}`},
		{name: "cgroup parent", body: `{"CgroupParent":"/docker"}`},
		{name: "resources object", body: `{"Resources":{"Memory":0}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/abc/update", strings.NewReader(tt.body))

			reason, err := newContainerUpdatePolicy(ContainerUpdateOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "container update denied: resource control changes are not allowed" {
				t.Fatalf("reason = %q", reason)
			}
		})
	}
}

func TestContainerUpdateDeniesPrivilegedDeviceAndCapabilityFieldsByDefault(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{name: "privileged", body: `{"Privileged":true}`, wantReason: "container update denied: privileged mode changes are not allowed"},
		{name: "devices", body: `{"Devices":[{"PathOnHost":"/dev/kvm"}]}`, wantReason: "container update denied: device changes are not allowed"},
		{name: "device requests", body: `{"DeviceRequests":[{"Driver":"nvidia"}]}`, wantReason: "container update denied: device changes are not allowed"},
		{name: "device cgroup rules", body: `{"DeviceCgroupRules":["c 10:* rwm"]}`, wantReason: "container update denied: device changes are not allowed"},
		{name: "cap add", body: `{"CapAdd":["SYS_ADMIN"]}`, wantReason: "container update denied: capability changes are not allowed"},
		{name: "security opt", body: `{"SecurityOpt":["seccomp=unconfined"]}`, wantReason: "container update denied: capability changes are not allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/abc/update", strings.NewReader(tt.body))

			reason, err := newContainerUpdatePolicy(ContainerUpdateOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestContainerUpdateAllowsConfiguredEscalationFieldsAndPreservesBody(t *testing.T) {
	payload := []byte(`{"RestartPolicy":{"Name":"always"},"Memory":0,"Privileged":true,"Devices":[{"PathOnHost":"/dev/kvm"}],"CapAdd":["SYS_ADMIN"]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1.45/containers/abc/update", strings.NewReader(string(payload)))

	reason, err := newContainerUpdatePolicy(ContainerUpdateOptions{
		AllowPrivileged:      true,
		AllowDevices:         true,
		AllowCapabilities:    true,
		AllowRestartPolicy:   true,
		AllowResourceUpdates: true,
	}).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != string(payload) {
		t.Fatalf("body = %q, want %q", string(body), string(payload))
	}
}

func TestContainerUpdateOversizedBodyReturnsRequestEntityTooLarge(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/update", nil)
	req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}
	req.ContentLength = maxContainerUpdateBodyBytes + 1

	_, err := newContainerUpdatePolicy(ContainerUpdateOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
	rejection, ok := requestRejectionFromError(err)
	if !ok {
		t.Fatalf("inspect() error = %v, want request rejection", err)
	}
	if rejection.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rejection.status, http.StatusRequestEntityTooLarge)
	}
	if !strings.HasPrefix(rejection.reason, "container update denied: request body exceeds") {
		t.Fatalf("reason = %q", rejection.reason)
	}
}

func TestContainerUpdateInvalidJSONDefersToDockerAndPreservesBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/update", strings.NewReader("{"))

	reason, err := newContainerUpdatePolicy(ContainerUpdateOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "{" {
		t.Fatalf("body = %q, want %q", string(body), "{")
	}
}
