package filter

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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
		AllowAllDevices:      true,
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

func TestContainerUpdateInvalidJSONDeniesFailClosed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/update", strings.NewReader("{"))

	reason, err := newContainerUpdatePolicy(ContainerUpdateOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	// Malformed JSON must be denied (fail-closed).
	const wantReason = "container update denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("reason = %q, want %q", reason, wantReason)
	}
}

func TestContainerUpdateInspectSkipsNonUpdateRequestsAndNilBody(t *testing.T) {
	policy := newContainerUpdatePolicy(ContainerUpdateOptions{})

	tests := []struct {
		name           string
		req            *http.Request
		normalizedPath string
	}{
		{name: "wrong path", req: httptest.NewRequest(http.MethodPost, "/containers/abc/json", strings.NewReader(`{"Memory":0}`)), normalizedPath: "/containers/abc/json"},
		{name: "nil body", req: func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "/containers/abc/update", nil)
			req.Body = nil
			return req
		}(), normalizedPath: "/containers/abc/update"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, err := policy.inspect(nil, tt.req, tt.normalizedPath)
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "" {
				t.Fatalf("reason = %q, want empty", reason)
			}
		})
	}
}

func TestContainerUpdateReadBodyError(t *testing.T) {
	sentinel := errors.New("read failed")
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/update", nil)
	req.Body = &readErrorReadCloser{readErr: sentinel}

	reason, err := newContainerUpdatePolicy(ContainerUpdateOptions{}).inspect(nil, req, "/containers/abc/update")
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("inspect() error = %v, want wrapped %v", err, sentinel)
	}
}

func TestContainerUpdateEmptyBodyReturnsEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/update", strings.NewReader(""))

	reason, err := newContainerUpdatePolicy(ContainerUpdateOptions{}).inspect(nil, req, "/containers/abc/update")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestContainerUpdateInvalidJSONWithLogger(t *testing.T) {
	logs := &collectingHandler{}
	logger := slog.New(logs)
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/update%0Aforged=true", strings.NewReader("{bad json"))
	req.Method = "POST\r\nlevel=ERROR"

	reason, err := newContainerUpdatePolicy(ContainerUpdateOptions{}).inspect(logger, req, "/containers/abc/update")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	// Malformed JSON must be denied (fail-closed).
	const wantReason = "container update denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("reason = %q, want %q", reason, wantReason)
	}
	if records := logs.snapshot(); len(records) != 1 {
		t.Fatalf("log records = %d, want 1", len(records))
	} else {
		if records[0].attrs["method"] != `POST\r\nlevel=ERROR` {
			t.Fatalf("method attr = %q, want escaped control characters", records[0].attrs["method"])
		}
		if path, _ := records[0].attrs["path"].(string); strings.ContainsAny(path, "\r\n") {
			t.Fatalf("path attr contains a raw log delimiter: %q", path)
		}
	}
}

func TestContainerUpdatePolicyObjectsIncludeHostConfigResources(t *testing.T) {
	var root map[string]json.RawMessage
	if err := decodePolicySubsetJSON([]byte(`{
		"HostConfig": {
			"Resources": {
				"PidsLimit": 42
			}
		}
	}`), &root); err != nil {
		t.Fatalf("decodePolicySubsetJSON() error = %v", err)
	}

	objects := containerUpdatePolicyObjects(root)
	if !containerUpdateHasAnyField(objects, "PidsLimit") {
		t.Fatalf("containerUpdatePolicyObjects() = %#v, want nested HostConfig.Resources fields", objects)
	}
}

func TestContainerUpdatePolicyObjectHelpersCoverEmptyAndInvalidNestedFields(t *testing.T) {
	if got := containerUpdatePolicyObjects(nil); got != nil {
		t.Fatalf("containerUpdatePolicyObjects(nil) = %#v, want nil", got)
	}

	root := map[string]json.RawMessage{
		"HostConfig": json.RawMessage(`[]`),
		"Resources":  json.RawMessage(`{}`),
	}
	if nested, ok := decodeContainerUpdateObjectField(root, "HostConfig"); ok || nested != nil {
		t.Fatalf("decodeContainerUpdateObjectField(invalid) = %#v, %v; want nil, false", nested, ok)
	}
	if nested, ok := decodeContainerUpdateObjectField(root, "Resources"); ok || nested != nil {
		t.Fatalf("decodeContainerUpdateObjectField(empty) = %#v, %v; want nil, false", nested, ok)
	}
}

// TestContainerUpdateResourceControlFieldsCompleteness is a regression test
// for the guarded resource-control field set (Engine API 1.55). It pins the
// full expected set — including all five per-device blkio throttling arrays
// (BlkioDeviceReadBps/ReadIOps/WriteBps/WriteIOps, BlkioWeightDevice) and the
// MemorySwap/MemorySwappiness pair — so a future edit that silently drops a
// field is caught here rather than by a missing standalone deny test.
func TestContainerUpdateResourceControlFieldsCompleteness(t *testing.T) {
	want := []string{
		"BlkioDeviceReadBps",
		"BlkioDeviceReadIOps",
		"BlkioDeviceWriteBps",
		"BlkioDeviceWriteIOps",
		"BlkioWeight",
		"BlkioWeightDevice",
		"CgroupParent",
		"CgroupnsMode",
		"CpuCount",
		"CpuPercent",
		"CpuPeriod",
		"CpuQuota",
		"CpuRealtimePeriod",
		"CpuRealtimeRuntime",
		"CpuShares",
		"CpusetCpus",
		"CpusetMems",
		"IOMaximumBandwidth",
		"IOMaximumIOps",
		"KernelMemory",
		"KernelMemoryTCP",
		"Memory",
		"MemoryReservation",
		"MemorySwap",
		"MemorySwappiness",
		"NanoCpus",
		"OomKillDisable",
		"PidsLimit",
		"Resources",
		"Ulimits",
	}

	if len(containerUpdateResourceControlFields) != len(want) {
		t.Fatalf("containerUpdateResourceControlFields has %d fields, want %d: %v", len(containerUpdateResourceControlFields), len(want), containerUpdateResourceControlFields)
	}
	for i, field := range want {
		if containerUpdateResourceControlFields[i] != field {
			t.Fatalf("containerUpdateResourceControlFields[%d] = %q, want %q", i, containerUpdateResourceControlFields[i], field)
		}
	}

	// Each field independently trips the resource-control deny by default.
	for _, field := range want {
		t.Run(field, func(t *testing.T) {
			body := `{"` + field + `":1}`
			req := httptest.NewRequest(http.MethodPost, "/containers/abc/update", strings.NewReader(body))

			reason, err := newContainerUpdatePolicy(ContainerUpdateOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "container update denied: resource control changes are not allowed" {
				t.Fatalf("field %q: reason = %q, want resource control denial", field, reason)
			}
		})
	}
}
