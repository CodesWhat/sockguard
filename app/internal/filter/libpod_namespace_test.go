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

// TestLibpodPodCreateNetworkNamespaceHostGateIsAnAllowlist pins the pod's
// netns, which is the infra container's, to the same allowlist behind
// libpod_pod_create.allow_host_network.
func TestLibpodPodCreateNetworkNamespaceHostGateIsAnAllowlist(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{"host", `{"netns":{"nsmode":"host"}}`, "libpod pod create denied: host network namespace is not allowed"},
		{"path", `{"netns":{"nsmode":"path","value":"/proc/1/ns/net"}}`, "libpod pod create denied: network namespace joined by path is not allowed"},
		{"path in another case", `{"netns":{"nsmode":"PATH","value":"/proc/1/ns/net"}}`, "libpod pod create denied: network namespace joined by path is not allowed"},
		{"path under an upper-case key", `{"NetNS":{"NSMode":"path","Value":"/proc/1/ns/net"}}`, "libpod pod create denied: network namespace joined by path is not allowed"},
		{"path as the last of two netns", `{"netns":{"nsmode":"bridge"},"netns":{"nsmode":"path","value":"/proc/1/ns/net"}}`, "libpod pod create denied: network namespace joined by path is not allowed"},
		{"a mode Podman doesn't have", `{"netns":{"nsmode":"hostns"}}`, `libpod pod create denied: network namespace mode "hostns" is not recognized`},
		{"absent", `{"name":"p"}`, ""},
		{"empty", `{"netns":{}}`, ""},
		{"default", `{"netns":{"nsmode":"default"}}`, ""},
		{"private", `{"netns":{"nsmode":"private"}}`, ""},
		{"bridge", `{"netns":{"nsmode":"bridge"}}`, ""},
		{"none", `{"netns":{"nsmode":"none"}}`, ""},
		{"slirp4netns", `{"netns":{"nsmode":"slirp4netns"}}`, ""},
		{"pasta", `{"netns":{"nsmode":"pasta"}}`, ""},
	}
	for _, tt := range tests {
		for _, allow := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/allow_host_network=%t", tt.name, allow), func(t *testing.T) {
				policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{AllowHostNetwork: allow})
				req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(tt.body))
				reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
				if err != nil {
					t.Fatalf("inspect() error = %v", err)
				}
				wantReason := tt.wantReason
				if allow {
					wantReason = ""
				}
				if reason != wantReason {
					t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
				}
			})
		}
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
