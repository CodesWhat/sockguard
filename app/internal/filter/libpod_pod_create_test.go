package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLibpodPodCreateInspectAllowsDefaultBody(t *testing.T) {
	policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{})

	req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(`{"name":"my-pod"}`))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestLibpodPodCreateInspectIgnoresNonMatchingPathsAndMethods(t *testing.T) {
	policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{})

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"wrong method", http.MethodGet, "/libpod/pods/create"},
		{"docker container create", http.MethodPost, "/containers/create"},
		{"libpod container create", http.MethodPost, "/libpod/containers/create"},
		{"pod update, not create", http.MethodPost, "/libpod/pods/my-pod/start"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(`{"netns":{"nsmode":"host"}}`))
			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "" {
				t.Fatalf("inspect() reason = %q, want empty", reason)
			}
		})
	}
}

func TestLibpodPodCreateInspectHostNetworkGate(t *testing.T) {
	tests := []struct {
		name    string
		allow   bool
		body    string
		wantDen bool
	}{
		{"default denies host netns", false, `{"netns":{"nsmode":"host"}}`, true},
		{"allowed permits host netns", true, `{"netns":{"nsmode":"host"}}`, false},
		{"default allows non-host netns", false, `{"netns":{"nsmode":"bridge"}}`, false},
		{"default allows absent netns", false, `{}`, false},
		{"case-insensitive host match denied", false, `{"netns":{"nsmode":"Host"}}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{AllowHostNetwork: tt.allow})
			req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(tt.body))
			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if tt.wantDen && reason == "" {
				t.Fatal("inspect() reason = empty, want host-network denial")
			}
			if !tt.wantDen && reason != "" {
				t.Fatalf("inspect() reason = %q, want empty", reason)
			}
		})
	}
}

func TestLibpodPodCreateInspectSharedPIDNamespaceGate(t *testing.T) {
	tests := []struct {
		name    string
		allow   bool
		body    string
		wantDen bool
	}{
		{"default denies shared pid", false, `{"shared_namespaces":["ipc","net","uts","pid"]}`, true},
		{"allowed permits shared pid", true, `{"shared_namespaces":["ipc","net","uts","pid"]}`, false},
		{"default allows shares without pid", false, `{"shared_namespaces":["ipc","net","uts"]}`, false},
		{"default allows absent shares", false, `{}`, false},
		{"case-insensitive pid match denied", false, `{"shared_namespaces":["PID"]}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{AllowSharedPIDNamespace: tt.allow})
			req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(tt.body))
			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if tt.wantDen && reason == "" {
				t.Fatal("inspect() reason = empty, want shared-PID denial")
			}
			if !tt.wantDen && reason != "" {
				t.Fatalf("inspect() reason = %q, want empty", reason)
			}
		})
	}
}

func TestLibpodPodCreateInspectInfraImageRegistryGate(t *testing.T) {
	tests := []struct {
		name      string
		allowed   []string
		body      string
		wantDen   bool
		wantMatch string
	}{
		{"default denies any explicit infra image", nil, `{"infra_image":"quay.io/podman/pause:5.8.1"}`, true, `infra image registry "quay.io" is not allowlisted`},
		{"allowlisted registry permitted", []string{"quay.io"}, `{"infra_image":"quay.io/podman/pause:5.8.1"}`, false, ""},
		{"unlisted registry still denied", []string{"quay.io"}, `{"infra_image":"docker.io/library/pause:3.9"}`, true, `infra image registry "docker.io" is not allowlisted`},
		{"empty infra_image always allowed", nil, `{}`, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{AllowedInfraImageRegistries: tt.allowed})
			req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(tt.body))
			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if tt.wantDen {
				if reason == "" {
					t.Fatal("inspect() reason = empty, want infra-image denial")
				}
				if !strings.Contains(reason, tt.wantMatch) {
					t.Fatalf("inspect() reason = %q, want to contain %q", reason, tt.wantMatch)
				}
				return
			}
			if reason != "" {
				t.Fatalf("inspect() reason = %q, want empty", reason)
			}
		})
	}
}

// TestLibpodPodCreateInspectInfraConmonPidFileGate pins that a pod create
// naming infra_conmon_pid_file is refused, the way a container create naming
// conmon_pid_file is (TestLibpodContainerCreateConmonPidFileGate). Podman
// copies the field onto the infra container's ConmonPidFile (Podman 5.8.6 and
// 6.1.3 pkg/api/handlers/libpod/pods.go:72), and conmon writes its PID to
// that path as the daemon's user when the infra container starts. The
// inspector didn't decode the field before, so each valid non-empty path
// was forwarded.
//
// No option opens the gate, so each row runs with every option off and with
// every option on. encoding/json and both of Podman's decoders match a key in
// any letter case, and a key given twice never reaches the gate, because
// readBoundedBody refuses the body.
func TestLibpodPodCreateInspectInfraConmonPidFileGate(t *testing.T) {
	const (
		refused   = "libpod pod create denied: setting infra_conmon_pid_file is not allowed"
		undecoded = "libpod pod create denied: request body could not be inspected"
	)
	tests := []struct {
		name string
		body string
		want string
	}{
		{"a host path", `{"infra_conmon_pid_file":"/host/x.pid"}`, refused},
		// podman-remote sends a relative --infra-conmon-pidfile as typed.
		{"a relative path", `{"infra_conmon_pid_file":"x.pid"}`, refused},
		{"a whitespace-only path", `{"infra_conmon_pid_file":" "}`, refused},
		{"under an upper-case key", `{"INFRA_CONMON_PID_FILE":"/host/x.pid"}`, refused},
		// Podman creates no infra container for this pod and never uses the
		// field. It's refused all the same, like a host namespace is.
		{"on a pod with no infra", `{"no_infra":true,"infra_conmon_pid_file":"/host/x.pid"}`, refused},
		{"a value that isn't a string", `{"infra_conmon_pid_file":["/host/x.pid"]}`, undecoded},
		{"given twice", `{"infra_conmon_pid_file":"/host/x.pid","infra_conmon_pid_file":""}`, repeatedKeyReason("infra_conmon_pid_file", "infra_conmon_pid_file")},
		{"absent", `{"name":"my-pod"}`, ""},
		{"empty", `{"infra_conmon_pid_file":""}`, ""},
		{"null", `{"infra_conmon_pid_file":null}`, ""},
	}
	everyOptionOn := libpodPodGateOptions("")
	everyOptionOn.AllowSharedPIDNamespace = true
	everyOptionOn.AllowedInfraImageRegistries = []string{"quay.io"}
	options := []struct {
		name string
		opts LibpodPodCreateOptions
	}{
		{"every option off", LibpodPodCreateOptions{}},
		{"every option on", everyOptionOn},
	}
	for _, tt := range tests {
		for _, o := range options {
			t.Run(tt.name+"/"+o.name, func(t *testing.T) {
				policy := newLibpodPodCreatePolicy(o.opts)
				if reason := inspectLibpodPod(t, policy, []byte(tt.body)); reason != tt.want {
					t.Fatalf("inspect() reason = %q, want %q", reason, tt.want)
				}
			})
		}
	}
}

func TestLibpodPodCreateInfraConmonPidFileMiddleware(t *testing.T) {
	rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/libpod/pods/create", Action: ActionAllow})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/libpod/pods/create", "/v6.1.3/libpod/pods/create"} {
		for _, tt := range []struct {
			name string
			body string
			want int
		}{
			{"captured client body", string(loadLibpodFixture(t, "pods/infra_conmon_pid_file.json")), http.StatusForbidden},
			{"whitespace path", `{"infra_conmon_pid_file":" "}`, http.StatusForbidden},
			{"no infra", `{"no_infra":true,"infra_conmon_pid_file":"/host/x.pid"}`, http.StatusForbidden},
			{"ordinary create", `{"name":"my-pod"}`, http.StatusCreated},
		} {
			t.Run(path+"/"+tt.name, func(t *testing.T) {
				forwarded := false
				handler := MiddlewareWithOptions([]*CompiledRule{rule}, testLogger(), Options{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					forwarded = true
					w.WriteHeader(http.StatusCreated)
				}))
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, strings.NewReader(tt.body)))
				if recorder.Code != tt.want {
					t.Fatalf("status = %d, want %d: %s", recorder.Code, tt.want, recorder.Body.String())
				}
				if forwarded != (tt.want == http.StatusCreated) {
					t.Fatalf("forwarded = %t, want %t", forwarded, tt.want == http.StatusCreated)
				}
			})
		}
	}
}

func TestLibpodPodCreateInspectHandlesMalformedJSON(t *testing.T) {
	policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{})
	req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", bytes.NewBufferString("{"))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "libpod pod create denied: request body could not be inspected" {
		t.Fatalf("inspect() reason = %q, want malformed-body denial", reason)
	}
}

func TestLibpodPodCreateInspectHandlesEmptyAndNilBody(t *testing.T) {
	policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{})

	req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(""))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect(empty body) error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect(empty body) reason = %q, want empty", reason)
	}

	req = httptest.NewRequest(http.MethodPost, "/libpod/pods/create", nil)
	req.Body = nil
	reason, err = policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect(nil body) error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect(nil body) reason = %q, want empty", reason)
	}
}

func TestLibpodPodCreateInspectBodyTooLarge(t *testing.T) {
	policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{})
	oversized := strings.Repeat("a", int(maxLibpodPodCreateBodyBytes)+1)
	body := `{"name":"` + oversized + `"}`

	req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	_, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err == nil {
		t.Fatal("inspect() error = nil, want request-too-large rejection")
	}
	rejection, ok := requestRejectionFromError(err)
	if !ok {
		t.Fatalf("inspect() error = %v, want a request rejection error", err)
	}
	if rejection.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("rejection.status = %d, want %d", rejection.status, http.StatusRequestEntityTooLarge)
	}
}

// TestLibpodPodCreateAndContainerCreateDecodeShapesAreExclusive is the
// negative cross-shape test the #148 design doc calls out as the single
// most important test in this area: a body carrying a field that is
// dangerous under ONE inspector's shape but syntactically inert under the
// other's must never leak across. Here: {"netns":{"nsmode":"host"}} is the
// pod-create host-network signal; it has no meaning at all in Docker's
// containerCreateRequest (which only reads HostConfig.NetworkMode), so
// sending it to POST /containers/create must have zero effect on the
// Docker-shaped decision.
func TestLibpodPodCreateAndContainerCreateDecodeShapesAreExclusive(t *testing.T) {
	body := `{"netns":{"nsmode":"host"},"HostConfig":{}}`

	containerCreate := newContainerCreatePolicy(ContainerCreateOptions{})
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(body))
	reason, err := containerCreate.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("container-create inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("container-create inspect() reason = %q, want empty (netns must not leak into HostConfig decode)", reason)
	}

	podCreate := newLibpodPodCreatePolicy(LibpodPodCreateOptions{})
	req = httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(body))
	reason, err = podCreate.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("pod-create inspect() error = %v", err)
	}
	if reason != "libpod pod create denied: host network namespace is not allowed" {
		t.Fatalf("pod-create inspect() reason = %q, want host-network denial", reason)
	}
}

// TestContainerCreateHostNetworkNeverLeaksIntoPodCreateDecode is the
// opposite direction of the cross-shape test above: HostConfig.NetworkMode
// is Docker's host-network signal and has no meaning in Podman's
// libpodPodCreateRequest (which only reads the top-level "netns" field).
func TestContainerCreateHostNetworkNeverLeaksIntoPodCreateDecode(t *testing.T) {
	body := `{"HostConfig":{"NetworkMode":"host"}}`

	podCreate := newLibpodPodCreatePolicy(LibpodPodCreateOptions{})
	req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(body))
	reason, err := podCreate.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("pod-create inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("pod-create inspect() reason = %q, want empty (HostConfig.NetworkMode must not leak into netns decode)", reason)
	}

	containerCreate := newContainerCreatePolicy(ContainerCreateOptions{})
	req = httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(body))
	reason, err = containerCreate.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("container-create inspect() error = %v", err)
	}
	if reason == "" {
		t.Fatal("container-create inspect() reason = empty, want host-network denial")
	}
}
