package filter

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// libpodNamespaceGateCase is one namespace field a host gate covers, and the
// option that opens its gate.
type libpodNamespaceGateCase struct {
	field string
	kind  libpodNamespaceKind
	label string
	open  func(*LibpodContainerCreateOptions)
}

var libpodNamespaceGateCases = []libpodNamespaceGateCase{
	{"netns", libpodNetNS, "network", func(o *LibpodContainerCreateOptions) { o.AllowHostNetwork = true }},
	{"pidns", libpodPidNS, "PID", func(o *LibpodContainerCreateOptions) { o.AllowHostPID = true }},
	{"ipcns", libpodIpcNS, "IPC", func(o *LibpodContainerCreateOptions) { o.AllowHostIPC = true }},
	{"userns", libpodUserNS, "user", func(o *LibpodContainerCreateOptions) { o.AllowHostUserNS = true }},
	{"utsns", libpodUtsNS, "UTS", func(o *LibpodContainerCreateOptions) { o.AllowHostUTS = true }},
	{"cgroupns", libpodCgroupNS, "cgroup", func(o *LibpodContainerCreateOptions) { o.AllowHostCgroupNS = true }},
}

// libpodGateOptions opens every host gate but the one for skip, or every one
// when skip is "". systemd mode is always allowed so it can't answer first.
func libpodGateOptions(skip string) LibpodContainerCreateOptions {
	opts := LibpodContainerCreateOptions{AllowSystemdMode: true}
	for _, c := range libpodNamespaceGateCases {
		if c.field != skip {
			c.open(&opts)
		}
	}
	return opts
}

// TestLibpodNamespaceKindKnowsMode pins the modes each namespace passes while
// its host gate is off, against the lists Podman 5.8.6 validates with
// (pkg/specgen/namespaces.go:146-233). `host` and `path` are never among them.
// pidns, utsns and cgroupns go through validate alone
// (pkg/specgen/container_validate.go:134, 140 and 143), so they take only the
// modes every namespace takes.
func TestLibpodNamespaceKindKnowsMode(t *testing.T) {
	every := []string{
		"", "default", "private", "container", "pod",
		"none", "bridge", "slirp4netns", "pasta",
		"shareable",
		"auto", "keep-id", "no-map",
		"host", "path",
		"Private", "PRIVATE", " private", "private ", "Default", "Pod", "Container", "nomap", "ns", "hostns",
	}
	common := []string{"", "default", "private", "container", "pod"}
	known := map[libpodNamespaceKind][]string{
		libpodNetNS:    append([]string{"none", "bridge", "slirp4netns", "pasta"}, common...),
		libpodPidNS:    common,
		libpodIpcNS:    append([]string{"shareable", "none"}, common...),
		libpodUserNS:   append([]string{"auto", "keep-id", "no-map"}, common...),
		libpodUtsNS:    common,
		libpodCgroupNS: common,
	}
	for _, c := range libpodNamespaceGateCases {
		for _, mode := range every {
			want := false
			for _, k := range known[c.kind] {
				if k == mode {
					want = true
				}
			}
			if got := c.kind.knowsMode(mode); got != want {
				t.Errorf("%s knowsMode(%q) = %v, want %v", c.field, mode, got, want)
			}
		}
	}
}

func TestLibpodNamespaceKindLabel(t *testing.T) {
	for _, c := range libpodNamespaceGateCases {
		if got := c.kind.label(); got != c.label {
			t.Errorf("%s label() = %q, want %q", c.field, got, c.label)
		}
	}
}

// TestLibpodContainerCreateNamespaceHostGateIsAnAllowlist drives every
// namespace a host gate covers through `host`, `path` and a mode Podman
// doesn't have. Each is refused while its own gate is off, whatever the
// other gates say, and passes once its own gate is on.
func TestLibpodContainerCreateNamespaceHostGateIsAnAllowlist(t *testing.T) {
	modes := []struct {
		name       string
		namespace  string
		wantReason string // %s is the namespace label
	}{
		{"host", `{"nsmode":"host"}`, "libpod container create denied: host %s namespace is not allowed"},
		{"host in another case", `{"nsmode":" HOST "}`, "libpod container create denied: host %s namespace is not allowed"},
		{"path", `{"nsmode":"path","value":"/proc/1/ns/x"}`, "libpod container create denied: %s namespace joined by path is not allowed"},
		{"path with no value", `{"nsmode":"path"}`, "libpod container create denied: %s namespace joined by path is not allowed"},
		{"path in another case", `{"nsmode":" Path ","value":"/proc/1/ns/x"}`, "libpod container create denied: %s namespace joined by path is not allowed"},
		{"a mode Podman doesn't have", `{"nsmode":"hostns"}`, `libpod container create denied: %s namespace mode "hostns" is not recognized`},
		{"private in another case", `{"nsmode":"Private"}`, `libpod container create denied: %s namespace mode "Private" is not recognized`},
		{"the CLI spelling ns:", `{"nsmode":"ns","value":"/proc/1/ns/x"}`, `libpod container create denied: %s namespace mode "ns" is not recognized`},
		{"path as the last of two nsmodes", `{"nsmode":"private","nsmode":"path","value":"/proc/1/ns/x"}`, "libpod container create denied: %s namespace joined by path is not allowed"},
		{"path under upper-case keys", `{"NSMODE":"path","VALUE":"/proc/1/ns/x"}`, "libpod container create denied: %s namespace joined by path is not allowed"},
	}
	for _, c := range libpodNamespaceGateCases {
		for _, mode := range modes {
			body := []byte(fmt.Sprintf(`{%q:%s}`, c.field, mode.namespace))
			wantReason := fmt.Sprintf(mode.wantReason, c.label)

			t.Run(c.field+"/"+mode.name+"/only its own gate off", func(t *testing.T) {
				policy := newLibpodContainerCreatePolicy(libpodGateOptions(c.field))
				if reason := inspectLibpod(t, policy, body); reason != wantReason {
					t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
				}
			})
			t.Run(c.field+"/"+mode.name+"/every gate on", func(t *testing.T) {
				policy := newLibpodContainerCreatePolicy(libpodGateOptions(""))
				if reason := inspectLibpod(t, policy, body); reason != "" {
					t.Fatalf("inspect() reason = %q, want empty", reason)
				}
			})
		}
	}
}

// TestLibpodContainerCreateNamespaceModesThatPassWithEveryGateOff is the
// other half of the allowlist: the modes a client legitimately sends keep
// passing with no gate on.
func TestLibpodContainerCreateNamespaceModesThatPassWithEveryGateOff(t *testing.T) {
	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true})
	bodies := []string{
		`{}`,
		`{"netns":{},"pidns":{},"ipcns":{},"userns":{},"utsns":{},"cgroupns":{}}`,
		`{"netns":null,"pidns":null,"ipcns":null,"userns":null,"utsns":null,"cgroupns":null}`,
		`{"netns":{"nsmode":null},"pidns":{"nsmode":""},"utsns":{"nsmode":null},"cgroupns":{"nsmode":""}}`,
		`{"netns":{"nsmode":"default"},"pidns":{"nsmode":"default"},"ipcns":{"nsmode":"default"},"userns":{"nsmode":"default"},"utsns":{"nsmode":"default"},"cgroupns":{"nsmode":"default"}}`,
		`{"netns":{"nsmode":"private"},"pidns":{"nsmode":"private"},"ipcns":{"nsmode":"private"},"userns":{"nsmode":"private"},"utsns":{"nsmode":"private"},"cgroupns":{"nsmode":"private"}}`,
		`{"netns":{"nsmode":"container","value":"web"},"pidns":{"nsmode":"container","value":"web"},"ipcns":{"nsmode":"container","value":"web"},"userns":{"nsmode":"container","value":"web"},"utsns":{"nsmode":"container","value":"web"},"cgroupns":{"nsmode":"container","value":"web"}}`,
		`{"pod":"p","netns":{"nsmode":"pod"},"pidns":{"nsmode":"pod"},"ipcns":{"nsmode":"pod"},"userns":{"nsmode":"pod"},"utsns":{"nsmode":"pod"},"cgroupns":{"nsmode":"pod"}}`,
		`{"netns":{"nsmode":"bridge"}}`,
		`{"netns":{"nsmode":"none"}}`,
		`{"netns":{"nsmode":"slirp4netns","value":"cidr=10.0.3.0/24"}}`,
		`{"netns":{"nsmode":"pasta"}}`,
		`{"ipcns":{"nsmode":"shareable"}}`,
		`{"ipcns":{"nsmode":"none"}}`,
		`{"userns":{"nsmode":"auto","value":"size=4096"}}`,
		`{"userns":{"nsmode":"keep-id"}}`,
		`{"userns":{"nsmode":"no-map"}}`,
		// The last nsmode is the one Podman keeps.
		`{"pidns":{"nsmode":"path","nsmode":"private"}}`,
		`{"pidns":{"nsmode":"host"},"pidns":{"nsmode":"private"}}`,
		`{"utsns":{"nsmode":"host"},"utsns":{"nsmode":"private"}}`,
		`{"cgroupns":{"nsmode":"path","nsmode":"private"}}`,
	}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			if reason := inspectLibpod(t, policy, []byte(body)); reason != "" {
				t.Fatalf("inspect() reason = %q, want empty", reason)
			}
		})
	}
}

// TestLibpodContainerCreateNamespaceModeOfTheWrongNamespace pins that each
// namespace takes only its own extra modes: a network mode on pidns is a
// mode Podman refuses there.
func TestLibpodContainerCreateNamespaceModeOfTheWrongNamespace(t *testing.T) {
	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true})
	tests := []struct {
		body       string
		wantReason string
	}{
		{`{"pidns":{"nsmode":"bridge"}}`, `libpod container create denied: PID namespace mode "bridge" is not recognized`},
		{`{"pidns":{"nsmode":"shareable"}}`, `libpod container create denied: PID namespace mode "shareable" is not recognized`},
		{`{"pidns":{"nsmode":"auto"}}`, `libpod container create denied: PID namespace mode "auto" is not recognized`},
		{`{"ipcns":{"nsmode":"bridge"}}`, `libpod container create denied: IPC namespace mode "bridge" is not recognized`},
		{`{"ipcns":{"nsmode":"keep-id"}}`, `libpod container create denied: IPC namespace mode "keep-id" is not recognized`},
		{`{"userns":{"nsmode":"shareable"}}`, `libpod container create denied: user namespace mode "shareable" is not recognized`},
		{`{"userns":{"nsmode":"none"}}`, `libpod container create denied: user namespace mode "none" is not recognized`},
		{`{"netns":{"nsmode":"shareable"}}`, `libpod container create denied: network namespace mode "shareable" is not recognized`},
		{`{"netns":{"nsmode":"auto"}}`, `libpod container create denied: network namespace mode "auto" is not recognized`},
		{`{"utsns":{"nsmode":"bridge"}}`, `libpod container create denied: UTS namespace mode "bridge" is not recognized`},
		{`{"utsns":{"nsmode":"shareable"}}`, `libpod container create denied: UTS namespace mode "shareable" is not recognized`},
		{`{"utsns":{"nsmode":"none"}}`, `libpod container create denied: UTS namespace mode "none" is not recognized`},
		{`{"cgroupns":{"nsmode":"none"}}`, `libpod container create denied: cgroup namespace mode "none" is not recognized`},
		{`{"cgroupns":{"nsmode":"auto"}}`, `libpod container create denied: cgroup namespace mode "auto" is not recognized`},
		{`{"cgroupns":{"nsmode":"shareable"}}`, `libpod container create denied: cgroup namespace mode "shareable" is not recognized`},
	}
	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			if reason := inspectLibpod(t, policy, []byte(tt.body)); reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestLibpodContainerCreateNamespaceThatIsNotAnObjectIsDenied pins that a
// namespace field of the wrong JSON type never reaches the gates as an empty
// namespace: the typed decode fails and the create is denied, with the gates
// on or off. Podman's own decode fails on the same bodies.
func TestLibpodContainerCreateNamespaceThatIsNotAnObjectIsDenied(t *testing.T) {
	bodies := []string{
		`{"pidns":"host"}`,
		`{"pidns":["host"]}`,
		`{"pidns":1}`,
		`{"pidns":{"nsmode":["path"],"value":"/proc/1/ns/pid"}}`,
		`{"pidns":{"nsmode":{"nsmode":"path"}}}`,
		`{"pidns":{"nsmode":"path","value":["/proc/1/ns/pid"]}}`,
	}
	for _, opts := range []LibpodContainerCreateOptions{{AllowSystemdMode: true}, libpodGateOptions("")} {
		policy := newLibpodContainerCreatePolicy(opts)
		for _, body := range bodies {
			t.Run(fmt.Sprintf("allow_host_pid=%t/%s", opts.AllowHostPID, body), func(t *testing.T) {
				const want = "libpod container create denied: malformed JSON request body"
				if reason := inspectLibpod(t, policy, []byte(body)); reason != want {
					t.Fatalf("inspect() reason = %q, want %q", reason, want)
				}
			})
		}
	}
}

// TestLibpodContainerCreateNamespacePathWhileSharingIsRestricted pins the
// path branch of denyNamespaceSharingReason. With every host gate on, a path
// is still a namespace no container allowlist can vouch for.
func TestLibpodContainerCreateNamespacePathWhileSharingIsRestricted(t *testing.T) {
	tests := []struct {
		field      string
		wantReason string
	}{
		{"netns", "libpod container create denied: network namespace joined by path is not allowed while namespace sharing is restricted"},
		{"pidns", "libpod container create denied: PID namespace joined by path is not allowed while namespace sharing is restricted"},
		{"ipcns", "libpod container create denied: IPC namespace joined by path is not allowed while namespace sharing is restricted"},
		{"userns", "libpod container create denied: user namespace joined by path is not allowed while namespace sharing is restricted"},
		{"utsns", "libpod container create denied: UTS namespace joined by path is not allowed while namespace sharing is restricted"},
		{"cgroupns", "libpod container create denied: cgroup namespace joined by path is not allowed while namespace sharing is restricted"},
	}
	for _, tt := range tests {
		body := []byte(fmt.Sprintf(`{%q:{"nsmode":"path","value":"/proc/1/ns/x"}}`, tt.field))
		for _, restrict := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/restrict=%t", tt.field, restrict), func(t *testing.T) {
				opts := libpodGateOptions("")
				opts.RestrictNamespaceSharing = restrict
				opts.AllowedNamespaceSharingContainers = []string{"/proc/1/ns/x", "path"}
				wantReason := ""
				if restrict {
					wantReason = tt.wantReason
				}
				if reason := inspectLibpod(t, newLibpodContainerCreatePolicy(opts), body); reason != wantReason {
					t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
				}
			})
		}
	}
}

// TestLibpodContainerCreateNamespaceSharingGateCoversEveryNamespace pins the
// container branch of denyNamespaceSharingReason on each namespace a
// SpecGenerator can join another container's with. Podman resolves all six
// the same way, cgroupns included (Podman 5.8.6
// pkg/specgen/generate/namespaces.go:146-310).
func TestLibpodContainerCreateNamespaceSharingGateCoversEveryNamespace(t *testing.T) {
	fields := []struct{ field, label string }{
		{"netns", "network"},
		{"pidns", "PID"},
		{"ipcns", "IPC"},
		{"userns", "user"},
		{"utsns", "UTS"},
		{"cgroupns", "cgroup"},
	}
	for _, f := range fields {
		body := []byte(fmt.Sprintf(`{%q:{"nsmode":"container","value":"web"}}`, f.field))
		tests := []struct {
			name       string
			restrict   bool
			allowlist  []string
			wantReason string
		}{
			{name: "sharing unrestricted"},
			{
				name:       "restricted with no allowlist",
				restrict:   true,
				wantReason: fmt.Sprintf("libpod container create denied: %s namespace sharing with another container is not allowed", f.label),
			},
			{
				name:       "restricted with the target off the allowlist",
				restrict:   true,
				allowlist:  []string{"db"},
				wantReason: `libpod container create denied: namespace-sharing target "web" is not in the allowed list`,
			},
			{name: "restricted with the target on the allowlist", restrict: true, allowlist: []string{"web"}},
		}
		for _, tt := range tests {
			t.Run(f.field+"/"+tt.name, func(t *testing.T) {
				opts := libpodGateOptions("")
				opts.RestrictNamespaceSharing = tt.restrict
				opts.AllowedNamespaceSharingContainers = tt.allowlist
				if reason := inspectLibpod(t, newLibpodContainerCreatePolicy(opts), body); reason != tt.wantReason {
					t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
				}
			})
		}
	}
}

// libpodPodNamespaceGateCase is one namespace field a pod create's host gate
// covers, and the option that opens its gate. They are every namespace
// PodSpecGenerator has (Podman 5.8.6 pkg/specgen/podspecgen.go:58, 89, 93, 95
// and 111), and each is the infra container's.
type libpodPodNamespaceGateCase struct {
	field string
	label string
	open  func(*LibpodPodCreateOptions)
}

var libpodPodNamespaceGateCases = []libpodPodNamespaceGateCase{
	{"netns", "network", func(o *LibpodPodCreateOptions) { o.AllowHostNetwork = true }},
	{"pidns", "PID", func(o *LibpodPodCreateOptions) { o.AllowHostPID = true }},
	{"ipcns", "IPC", func(o *LibpodPodCreateOptions) { o.AllowHostIPC = true }},
	{"userns", "user", func(o *LibpodPodCreateOptions) { o.AllowHostUserNS = true }},
	{"utsns", "UTS", func(o *LibpodPodCreateOptions) { o.AllowHostUTS = true }},
}

// libpodPodGateOptions opens every pod host gate but the one for skip, or
// every one when skip is "".
func libpodPodGateOptions(skip string) LibpodPodCreateOptions {
	var opts LibpodPodCreateOptions
	for _, c := range libpodPodNamespaceGateCases {
		if c.field != skip {
			c.open(&opts)
		}
	}
	return opts
}

func inspectLibpodPod(t *testing.T, policy libpodPodCreatePolicy, body []byte) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v5.8.6/libpod/pods/create", strings.NewReader(string(body)))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	return reason
}

// TestLibpodPodCreateNamespaceHostGateIsAnAllowlist drives every namespace a
// pod has through `host`, `path` and a mode Podman doesn't have. Each is
// refused while its own gate is off, whatever the other gates say, and
// passes once its own gate is on. Only netns had a gate before 2.2.6, so a
// pod could be created in the host PID, IPC, user or UTS namespace with
// nothing in the way.
func TestLibpodPodCreateNamespaceHostGateIsAnAllowlist(t *testing.T) {
	modes := []struct {
		name       string
		namespace  string
		wantReason string // %s is the namespace label
	}{
		{"host", `{"nsmode":"host"}`, "libpod pod create denied: host %s namespace is not allowed"},
		{"host in another case", `{"nsmode":" HOST "}`, "libpod pod create denied: host %s namespace is not allowed"},
		{"path", `{"nsmode":"path","value":"/proc/1/ns/x"}`, "libpod pod create denied: %s namespace joined by path is not allowed"},
		{"path with no value", `{"nsmode":"path"}`, "libpod pod create denied: %s namespace joined by path is not allowed"},
		{"path in another case", `{"nsmode":" Path ","value":"/proc/1/ns/x"}`, "libpod pod create denied: %s namespace joined by path is not allowed"},
		{"a mode Podman doesn't have", `{"nsmode":"hostns"}`, `libpod pod create denied: %s namespace mode "hostns" is not recognized`},
		{"private in another case", `{"nsmode":"Private"}`, `libpod pod create denied: %s namespace mode "Private" is not recognized`},
		{"the CLI spelling ns:", `{"nsmode":"ns","value":"/proc/1/ns/x"}`, `libpod pod create denied: %s namespace mode "ns" is not recognized`},
		{"path as the last of two nsmodes", `{"nsmode":"private","nsmode":"path","value":"/proc/1/ns/x"}`, "libpod pod create denied: %s namespace joined by path is not allowed"},
		{"path under upper-case keys", `{"NSMODE":"path","VALUE":"/proc/1/ns/x"}`, "libpod pod create denied: %s namespace joined by path is not allowed"},
	}
	for _, c := range libpodPodNamespaceGateCases {
		for _, mode := range modes {
			wantReason := fmt.Sprintf(mode.wantReason, c.label)
			bodies := map[string]string{
				"":                         fmt.Sprintf(`{%q:%s}`, c.field, mode.namespace),
				" under an upper-case key": fmt.Sprintf(`{%q:%s}`, strings.ToUpper(c.field), mode.namespace),
				" as the last of two":      fmt.Sprintf(`{%q:{"nsmode":"private"},%q:%s}`, c.field, c.field, mode.namespace),
				" on a pod with no infra":  fmt.Sprintf(`{"no_infra":true,%q:%s}`, c.field, mode.namespace),
				" among podman-remote's":   fmt.Sprintf(`{"netns":{},"pidns":{"nsmode":"private"},"ipcns":{"nsmode":"private"},"userns":{},"utsns":{"nsmode":"private"},"shared_namespaces":["ipc","net","uts"],%q:%s}`, c.field, mode.namespace),
			}
			for spelling, body := range bodies {
				t.Run(c.field+"/"+mode.name+spelling+"/only its own gate off", func(t *testing.T) {
					policy := newLibpodPodCreatePolicy(libpodPodGateOptions(c.field))
					if reason := inspectLibpodPod(t, policy, []byte(body)); reason != wantReason {
						t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
					}
				})
				t.Run(c.field+"/"+mode.name+spelling+"/every gate on", func(t *testing.T) {
					policy := newLibpodPodCreatePolicy(libpodPodGateOptions(""))
					if reason := inspectLibpodPod(t, policy, []byte(body)); reason != "" {
						t.Fatalf("inspect() reason = %q, want empty", reason)
					}
				})
			}
		}
	}
}

// TestLibpodPodCreateNamespaceModesThatPassWithEveryGateOff is the other
// half of the allowlist: what a client legitimately sends keeps passing with
// no gate on. The first three bodies are the namespaces podman-remote sends
// for `pod create`, `run --pod new:NAME` and `pod create --infra=false`
// (testdata/libpod/pods, and Podman 5.8.6 pkg/domain/entities/pods.go:313-329
// and cmd/podman/containers/create.go:453).
func TestLibpodPodCreateNamespaceModesThatPassWithEveryGateOff(t *testing.T) {
	policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{})
	bodies := []string{
		`{"netns":{},"pidns":{"nsmode":"private"},"ipcns":{"nsmode":"private"},"userns":{},"utsns":{"nsmode":"private"},"shared_namespaces":["ipc","net","uts"]}`,
		`{"netns":{},"pidns":{"nsmode":"private"},"ipcns":{"nsmode":"private"},"userns":{"nsmode":"default"},"utsns":{"nsmode":"private"}}`,
		`{"no_infra":true,"netns":{},"pidns":{"nsmode":"private"},"ipcns":{"nsmode":"private"},"userns":{},"utsns":{"nsmode":"private"}}`,
		`{}`,
		`{"name":"p"}`,
		// What the Go bindings send for a zero PodSpecGenerator.
		`{"netns":{},"pidns":{},"ipcns":{},"userns":{},"utsns":{}}`,
		`{"netns":null,"pidns":null,"ipcns":null,"userns":null,"utsns":null}`,
		`{"netns":{"nsmode":null},"pidns":{"nsmode":""},"utsns":{"nsmode":null}}`,
		`{"netns":{"nsmode":"default"},"pidns":{"nsmode":"default"},"ipcns":{"nsmode":"default"},"userns":{"nsmode":"default"},"utsns":{"nsmode":"default"}}`,
		`{"netns":{"nsmode":"private"},"pidns":{"nsmode":"private"},"ipcns":{"nsmode":"private"},"userns":{"nsmode":"private"},"utsns":{"nsmode":"private"}}`,
		// Another container's namespace isn't the host gate's to refuse.
		// Owner isolation checks the container it names.
		`{"pidns":{"nsmode":"container","value":"web"},"ipcns":{"nsmode":"container","value":"web"},"userns":{"nsmode":"container","value":"web"},"utsns":{"nsmode":"container","value":"web"}}`,
		// Podman refuses `pod` on a pod's own namespaces: the infra
		// container has no pod to take them from.
		`{"pidns":{"nsmode":"pod"},"ipcns":{"nsmode":"pod"},"userns":{"nsmode":"pod"},"utsns":{"nsmode":"pod"}}`,
		`{"netns":{"nsmode":"bridge"}}`,
		`{"netns":{"nsmode":"none"}}`,
		`{"netns":{"nsmode":"slirp4netns"}}`,
		`{"netns":{"nsmode":"pasta"}}`,
		`{"ipcns":{"nsmode":"shareable"}}`,
		`{"ipcns":{"nsmode":"none"}}`,
		`{"userns":{"nsmode":"auto","value":"size=4096"}}`,
		`{"userns":{"nsmode":"keep-id"}}`,
		`{"userns":{"nsmode":"no-map"}}`,
		// The last nsmode is the one Podman keeps.
		`{"pidns":{"nsmode":"path","nsmode":"private"}}`,
		`{"pidns":{"nsmode":"host"},"pidns":{"nsmode":"private"}}`,
	}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			if reason := inspectLibpodPod(t, policy, []byte(body)); reason != "" {
				t.Fatalf("inspect() reason = %q, want empty", reason)
			}
		})
	}
}

// TestLibpodPodCreateNamespaceModeOfTheWrongNamespace pins that each of a
// pod's namespaces takes only its own extra modes, like a container's.
func TestLibpodPodCreateNamespaceModeOfTheWrongNamespace(t *testing.T) {
	policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{})
	tests := []struct {
		body       string
		wantReason string
	}{
		{`{"pidns":{"nsmode":"bridge"}}`, `libpod pod create denied: PID namespace mode "bridge" is not recognized`},
		{`{"pidns":{"nsmode":"shareable"}}`, `libpod pod create denied: PID namespace mode "shareable" is not recognized`},
		{`{"ipcns":{"nsmode":"keep-id"}}`, `libpod pod create denied: IPC namespace mode "keep-id" is not recognized`},
		{`{"userns":{"nsmode":"shareable"}}`, `libpod pod create denied: user namespace mode "shareable" is not recognized`},
		{`{"utsns":{"nsmode":"none"}}`, `libpod pod create denied: UTS namespace mode "none" is not recognized`},
		{`{"utsns":{"nsmode":"auto"}}`, `libpod pod create denied: UTS namespace mode "auto" is not recognized`},
		{`{"netns":{"nsmode":"shareable"}}`, `libpod pod create denied: network namespace mode "shareable" is not recognized`},
	}
	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			if reason := inspectLibpodPod(t, policy, []byte(tt.body)); reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestLibpodPodCreateNamespaceThatIsNotAnObjectIsDenied pins that a pod
// namespace of the wrong JSON type never reaches the gates as an empty
// namespace. The typed decode fails and the create is denied, with the gates
// on or off. Podman's own decode fails on the same bodies.
func TestLibpodPodCreateNamespaceThatIsNotAnObjectIsDenied(t *testing.T) {
	const want = "libpod pod create denied: request body could not be inspected"
	for _, c := range libpodPodNamespaceGateCases {
		bodies := []string{
			fmt.Sprintf(`{%q:"host"}`, c.field),
			fmt.Sprintf(`{%q:["host"]}`, c.field),
			fmt.Sprintf(`{%q:1}`, c.field),
			fmt.Sprintf(`{%q:{"nsmode":["host"]}}`, c.field),
			fmt.Sprintf(`{%q:{"nsmode":"path","value":["/proc/1/ns/x"]}}`, c.field),
		}
		for _, opts := range []LibpodPodCreateOptions{{}, libpodPodGateOptions("")} {
			policy := newLibpodPodCreatePolicy(opts)
			for _, body := range bodies {
				t.Run(fmt.Sprintf("gates_on=%t/%s", opts.AllowHostPID, body), func(t *testing.T) {
					if reason := inspectLibpodPod(t, policy, []byte(body)); reason != want {
						t.Fatalf("inspect() reason = %q, want %q", reason, want)
					}
				})
			}
		}
	}
}

// TestLibpodPodCreateHostGatesAreThePodsOwn pins that each pod gate opens one
// namespace and nothing else: not another of the pod's namespaces, and not
// "pid" in shared_namespaces, which allow_shared_pid_namespace still gates.
func TestLibpodPodCreateHostGatesAreThePodsOwn(t *testing.T) {
	for _, c := range libpodPodNamespaceGateCases {
		var only LibpodPodCreateOptions
		c.open(&only)
		policy := newLibpodPodCreatePolicy(only)
		for _, other := range libpodPodNamespaceGateCases {
			body := fmt.Sprintf(`{%q:{"nsmode":"host"}}`, other.field)
			wantReason := fmt.Sprintf("libpod pod create denied: host %s namespace is not allowed", other.label)
			if other.field == c.field {
				wantReason = ""
			}
			t.Run("only "+c.field+" open/"+other.field+" host", func(t *testing.T) {
				if reason := inspectLibpodPod(t, policy, []byte(body)); reason != wantReason {
					t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
				}
			})
		}
	}

	t.Run("allow_host_pid doesn't open a shared PID namespace", func(t *testing.T) {
		policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{AllowHostPID: true})
		const want = "libpod pod create denied: shared PID namespace is not allowed"
		if reason := inspectLibpodPod(t, policy, []byte(`{"pidns":{"nsmode":"host"},"shared_namespaces":["pid"]}`)); reason != want {
			t.Fatalf("inspect() reason = %q, want %q", reason, want)
		}
	})
	t.Run("allow_shared_pid_namespace doesn't open the host PID namespace", func(t *testing.T) {
		policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{AllowSharedPIDNamespace: true})
		const want = "libpod pod create denied: host PID namespace is not allowed"
		if reason := inspectLibpodPod(t, policy, []byte(`{"pidns":{"nsmode":"host"},"shared_namespaces":["pid"]}`)); reason != want {
			t.Fatalf("inspect() reason = %q, want %q", reason, want)
		}
	})
}

// TestLibpodPodCreateHasNoCgroupNamespaceToGate pins why there is no
// libpod_pod_create.allow_host_cgroupns. PodSpecGenerator has no cgroupns
// field (Podman 5.8.6 pkg/specgen/podspecgen.go:11-100 and 223-231), and the
// handler decodes the body into that struct alone before it builds the infra
// container's spec from it (pkg/api/handlers/libpod/pods.go:37-65). A
// `cgroupns` key in a pod create body is dropped there, so it passes here
// like any other key Podman doesn't read. The infra container's cgroup
// namespace is always the daemon's default.
func TestLibpodPodCreateHasNoCgroupNamespaceToGate(t *testing.T) {
	policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{})
	for _, body := range []string{
		`{"cgroupns":{"nsmode":"host"}}`,
		`{"cgroupns":{"nsmode":"path","value":"/proc/1/ns/cgroup"}}`,
		`{"shared_namespaces":["cgroup"]}`,
	} {
		t.Run(body, func(t *testing.T) {
			if reason := inspectLibpodPod(t, policy, []byte(body)); reason != "" {
				t.Fatalf("inspect() reason = %q, want empty", reason)
			}
		})
	}
}

// libpodPodFixtures are the pod create bodies captured off podman-remote
// (testdata/libpod/README.md), the reason each is refused with every option
// off, and the one option that lets it through.
var libpodPodFixtures = []struct {
	fixture    string
	wantReason string
	open       func(*LibpodPodCreateOptions)
}{
	{fixture: "default.json"},
	{fixture: "pod_new.json"},
	{fixture: "no_infra.json"},
	{"host_pid.json", "libpod pod create denied: host PID namespace is not allowed", func(o *LibpodPodCreateOptions) { o.AllowHostPID = true }},
	{"path_pid.json", "libpod pod create denied: PID namespace joined by path is not allowed", func(o *LibpodPodCreateOptions) { o.AllowHostPID = true }},
	{"host_uts.json", "libpod pod create denied: host UTS namespace is not allowed", func(o *LibpodPodCreateOptions) { o.AllowHostUTS = true }},
	{"host_userns.json", "libpod pod create denied: host user namespace is not allowed", func(o *LibpodPodCreateOptions) { o.AllowHostUserNS = true }},
	{"share_pid.json", "libpod pod create denied: shared PID namespace is not allowed", func(o *LibpodPodCreateOptions) { o.AllowSharedPIDNamespace = true }},
}

// TestLibpodPodCreateCapturedBodies runs every pod create body captured off
// podman-remote through the inspector. The three a client sends without
// asking for a host namespace pass with every option off, which is what
// keeps 2.2.6's new gates from refusing a pod create that worked on 2.2.5.
// The rest are refused by default and pass with the one option they need.
func TestLibpodPodCreateCapturedBodies(t *testing.T) {
	captured, err := filepath.Glob(filepath.Join("testdata", "libpod", "pods", "*.json"))
	if err != nil {
		t.Fatalf("glob pod fixtures: %v", err)
	}
	if len(captured) != len(libpodPodFixtures) {
		t.Fatalf("testdata/libpod/pods has %d bodies and this test knows %d; add the new one to libpodPodFixtures", len(captured), len(libpodPodFixtures))
	}
	for _, tt := range libpodPodFixtures {
		body := loadLibpodFixture(t, filepath.Join("pods", tt.fixture))
		t.Run(tt.fixture+"/every option off", func(t *testing.T) {
			policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{})
			if reason := inspectLibpodPod(t, policy, body); reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
		if tt.open == nil {
			continue
		}
		t.Run(tt.fixture+"/its option on", func(t *testing.T) {
			var opts LibpodPodCreateOptions
			tt.open(&opts)
			if reason := inspectLibpodPod(t, newLibpodPodCreatePolicy(opts), body); reason != "" {
				t.Fatalf("inspect() reason = %q, want empty", reason)
			}
		})
	}
}

// TestLibpodContainerCreateCapturedBodiesAndTheUTSAndCgroupGates runs every
// container create body captured off podman-remote through the inspector
// with allow_host_uts and allow_host_cgroupns off, then on. Every gate that
// answers before those two is open, so the two are always reached. Only the
// bodies that ask for the host UTS or cgroup namespace get a different
// answer, so a create that worked on 2.2.5 without those two flags still
// works on 2.2.6.
func TestLibpodContainerCreateCapturedBodiesAndTheUTSAndCgroupGates(t *testing.T) {
	captured, err := filepath.Glob(filepath.Join("testdata", "libpod", "*.json"))
	if err != nil {
		t.Fatalf("glob container fixtures: %v", err)
	}
	if len(captured) < 20 {
		t.Fatalf("found %d container create bodies in testdata/libpod, want at least the 20 captured for 2.0", len(captured))
	}
	gatesOff := LibpodContainerCreateOptions{
		AllowPrivileged:  true,
		AllowHostNetwork: true,
		AllowHostPID:     true,
		AllowHostIPC:     true,
		AllowHostUserNS:  true,
	}
	gatesOn := gatesOff
	gatesOn.AllowHostUTS = true
	gatesOn.AllowHostCgroupNS = true
	wantRefused := map[string]string{
		"host_uts.json":      "libpod container create denied: host UTS namespace is not allowed",
		"host_cgroupns.json": "libpod container create denied: host cgroup namespace is not allowed",
	}
	seen := 0
	for _, path := range captured {
		name := filepath.Base(path)
		body := loadLibpodFixture(t, name)
		t.Run(name, func(t *testing.T) {
			off := inspectLibpod(t, newLibpodContainerCreatePolicy(gatesOff), body)
			on := inspectLibpod(t, newLibpodContainerCreatePolicy(gatesOn), body)
			if want, refused := wantRefused[name]; refused {
				if off != want {
					t.Fatalf("with the gates off inspect() reason = %q, want %q", off, want)
				}
				if strings.Contains(on, "namespace") {
					t.Fatalf("with the gates on inspect() reason = %q, want one that isn't about a namespace", on)
				}
				return
			}
			if off != on {
				t.Fatalf("the UTS and cgroup gates changed the answer: off %q, on %q", off, on)
			}
			if strings.Contains(off, "UTS") || strings.Contains(off, "cgroup") {
				t.Fatalf("inspect() reason = %q, want one that isn't about the UTS or cgroup namespace", off)
			}
		})
		if _, refused := wantRefused[name]; refused {
			seen++
		}
	}
	if seen != len(wantRefused) {
		t.Fatalf("found %d of the %d host UTS and cgroup fixtures", seen, len(wantRefused))
	}
}
