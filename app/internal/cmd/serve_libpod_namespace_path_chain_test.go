package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/config"
)

// podmanChainNamespace is specgen.Namespace (pkg/specgen/namespaces.go:78-81).
// Podman compares NSMode byte for byte against its mode constants
// (namespaces.go:26-71), so "Host" is not "host".
type podmanChainNamespace struct {
	NSMode string `json:"nsmode,omitempty"`
	Value  string `json:"value,omitempty"`
}

// isDefault is Namespace.IsDefault (namespaces.go:85-87).
func (n podmanChainNamespace) isDefault() bool {
	return n.NSMode == "default" || n.NSMode == ""
}

// String is Namespace.String (namespaces.go:139-144).
func (n podmanChainNamespace) String() string {
	if n.Value != "" {
		return n.NSMode + ":" + n.Value
	}
	return n.NSMode
}

// podmanChainSpec is the part of specgen.SpecGenerator that picks a
// container's namespaces, under the JSON names Podman decodes them from
// (pkg/specgen/specgen.go:42, 141, 146, 325, 421, 425, 461, 478).
type podmanChainSpec struct {
	Pod        string               `json:"pod,omitempty"`
	PidNS      podmanChainNamespace `json:"pidns"`
	UtsNS      podmanChainNamespace `json:"utsns"`
	IpcNS      podmanChainNamespace `json:"ipcns"`
	UserNS     podmanChainNamespace `json:"userns"`
	IDMappings *json.RawMessage     `json:"idmappings,omitempty"`
	CgroupNS   podmanChainNamespace `json:"cgroupns"`
	NetNS      podmanChainNamespace `json:"netns"`
}

// podmanChainKinds is the order every namespace is reported in.
var podmanChainKinds = []string{"netns", "pidns", "ipcns", "userns", "utsns", "cgroupns"}

func (s *podmanChainSpec) namespace(kind string) podmanChainNamespace {
	switch kind {
	case "netns":
		return s.NetNS
	case "pidns":
		return s.PidNS
	case "ipcns":
		return s.IpcNS
	case "userns":
		return s.UserNS
	case "utsns":
		return s.UtsNS
	default:
		return s.CgroupNS
	}
}

// podmanChainPodSpec is the part of specgen.PodSpecGenerator that picks the
// infra container's namespaces (pkg/specgen/podspecgen.go:16, 33, 58, 66, 89,
// 93, 95, 111). A pod has no cgroupns field.
type podmanChainPodSpec struct {
	Name             string               `json:"name,omitempty"`
	NoInfra          bool                 `json:"no_infra,omitempty"`
	Ipc              podmanChainNamespace `json:"ipcns"`
	SharedNamespaces []string             `json:"shared_namespaces,omitempty"`
	Pid              podmanChainNamespace `json:"pidns"`
	Userns           podmanChainNamespace `json:"userns"`
	UtsNs            podmanChainNamespace `json:"utsns"`
	NetNS            podmanChainNamespace `json:"netns"`
}

// podmanChainPod is what a later container create reads off a pod: which
// namespace its infra container is in, and which of them the pod shares.
type podmanChainPod struct {
	infra  map[string]string
	shares map[string]bool
}

// podmanNamespaceChainDaemon creates containers and pods the way a rootful
// Podman 5.8.6 on cgroup v2 with a stock containers.conf picks their
// namespaces, and records which ones each container joined.
//
// POST /vX/libpod/containers/create decodes a SpecGenerator with
// encoding/json (pkg/api/handlers/libpod/containers_create.go:65), so a key
// matches in any letter case and a repeated one is applied again in order.
// generate.MakeContainer then replaces every default namespace
// (pkg/specgen/generate/container_create.go:98-148), validates the rest
// (container_create.go:220, pkg/specgen/container_validate.go:134-152) and
// hands them to namespaceOptions and specConfigureNamespaces. Mode `path`
// joins whatever namespace the value names, after checking only that the path
// exists (pkg/specgen/generate/namespaces_linux.go:20-151 for pid, ipc, uts,
// cgroup and net, pkg/specgen/namespaces.go:499-505 for user). `host` drops
// the namespace, `container` joins another container's and `pod` joins the
// pod infra container's without asking whether the pod shares it
// (pkg/specgen/generate/namespaces.go:146-165).
//
// POST /vX/libpod/pods/create decodes a PodSpecGenerator, marshals it, and
// unmarshals that over the infra container's SpecGenerator, so `pidns`,
// `ipcns`, `utsns`, `userns` and `netns` become the infra container's
// (pkg/api/handlers/libpod/pods.go:37-69). The infra container then goes
// through MakeContainer like any other (pkg/specgen/generate/pod_create.go:91).
//
// POST /containers/create, with or without a version, reads HostConfig's mode
// strings and parses them into the same Namespace values
// (pkg/api/handlers/compat/containers_create.go:298-308 and 453-485,
// pkg/specgenutil/specgen.go:197-243), then creates the container the same way.
//
// A path under /proc/1/ns/ or /run/netns/ exists, and "web" is the one
// container already there.
type podmanNamespaceChainDaemon struct {
	mu      sync.Mutex
	pods    map[string]podmanChainPod
	created []string
}

func newPodmanNamespaceChainDaemon() *podmanNamespaceChainDaemon {
	return &podmanNamespaceChainDaemon{pods: map[string]podmanChainPod{}}
}

func (d *podmanNamespaceChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	versioned := normPath != r.URL.Path
	w.Header().Set("Content-Type", "application/json")
	var err error
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
		return
	case r.Method == http.MethodPost && normPath == "/libpod/containers/create" && versioned:
		err = d.createLibpodContainer(r.Body)
	case r.Method == http.MethodPost && normPath == "/libpod/pods/create" && versioned:
		err = d.createPod(r.Body)
	case r.Method == http.MethodPost && normPath == "/containers/create":
		err = d.createCompatContainer(r.Body)
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"cause": err.Error(), "message": err.Error()})
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"Id": "c1"})
}

func (d *podmanNamespaceChainDaemon) createLibpodContainer(body io.Reader) error {
	var spec podmanChainSpec
	if err := json.NewDecoder(body).Decode(&spec); err != nil {
		return fmt.Errorf("decode(): %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	joined, err := d.makeContainerLocked(&spec)
	if err != nil {
		return err
	}
	d.created = append(d.created, "container: "+describePodmanChainJoins(joined))
	return nil
}

// createPod is libpod.PodCreate and generate.MakePod.
func (d *podmanNamespaceChainDaemon) createPod(body io.Reader) error {
	var psg podmanChainPodSpec
	if err := json.NewDecoder(body).Decode(&psg); err != nil {
		return fmt.Errorf("failed to decode specgen: %w", err)
	}
	var infra podmanChainSpec
	if !psg.NoInfra {
		// A userns the request set goes through its string form and
		// FillOutSpecGen before the pod spec is copied over the infra spec
		// (pods.go:48-59), so a mode ParseUserNamespace can't read ends here.
		if !psg.Userns.isDefault() {
			userns, err := podmanChainParseUserNamespace(psg.Userns.String())
			if err != nil {
				return fmt.Errorf("filling out specgen: %w", err)
			}
			infra.UserNS = userns
		}
		out, err := json.Marshal(psg)
		if err != nil {
			return fmt.Errorf("failed to decode specgen: %w", err)
		}
		if err := json.Unmarshal(out, &infra); err != nil {
			return fmt.Errorf("failed to decode specgen: %w", err)
		}
	}

	// PodSpecGenerator.Validate (pkg/specgen/pod_validate.go:19-43).
	if psg.NoInfra && len(psg.SharedNamespaces) > 0 {
		return errors.New("NoInfra and SharedNamespaces are mutually exclusive pod options")
	}
	if err := podmanChainValidate("netns", psg.NetNS); err != nil {
		return err
	}
	if psg.NoInfra && !psg.NetNS.isDefault() {
		return errors.New("NoInfra and network modes cannot be used together")
	}
	// MapSpec (pkg/specgen/generate/pod_create.go:188-234).
	switch psg.NetNS.NSMode {
	case "", "default", "bridge", "private", "host", "slirp4netns", "pasta", "path", "none":
	default:
		return fmt.Errorf("pods presently do not support network mode %s", psg.NetNS.NSMode)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	pod := podmanChainPod{infra: map[string]string{}, shares: map[string]bool{}}
	if psg.NoInfra {
		d.pods[psg.Name] = pod
		d.created = append(d.created, "pod "+psg.Name+": no infra container")
		return nil
	}
	shares, err := podmanChainSharedNamespaces(psg.SharedNamespaces)
	if err != nil {
		return err
	}
	joined, err := d.makeContainerLocked(&infra)
	if err != nil {
		return err
	}
	pod.infra, pod.shares = joined, shares
	// The pod shares its user namespace only when the infra container has
	// one of its own (pod_create.go:132-135).
	pod.shares["userns"] = infra.UserNS.NSMode != "host" && !infra.UserNS.isDefault()
	d.pods[psg.Name] = pod
	d.created = append(d.created, "pod "+psg.Name+" infra: "+describePodmanChainJoins(joined))
	return nil
}

// podmanChainSharedNamespaces is generate.GetNamespaceOptions
// (pkg/specgen/generate/namespaces.go:420-451).
func podmanChainSharedNamespaces(shared []string) (map[string]bool, error) {
	if shared == nil {
		shared = []string{"ipc", "net", "uts"}
	}
	shares := map[string]bool{}
	for _, toShare := range shared {
		switch toShare {
		case "cgroup", "net", "pid", "ipc", "uts":
			shares[toShare+"ns"] = true
		case "mnt":
			return nil, errors.New("mount sharing functionality not supported on pod level")
		case "user", "":
		case "none":
			return map[string]bool{}, nil
		default:
			return nil, fmt.Errorf("invalid kernel namespace to share: %s", toShare)
		}
	}
	return shares, nil
}

func (d *podmanNamespaceChainDaemon) createCompatContainer(body io.Reader) error {
	var cc struct {
		HostConfig struct {
			NetworkMode  string
			PidMode      string
			IpcMode      string
			UTSMode      string
			UsernsMode   string
			CgroupnsMode string
		}
	}
	if err := json.NewDecoder(body).Decode(&cc); err != nil {
		return fmt.Errorf("decode(): %w", err)
	}
	// The compat handler always fills in ID mappings (specgen.go:245-275).
	spec := podmanChainSpec{IDMappings: &json.RawMessage{}}
	netmode := cc.HostConfig.NetworkMode
	if netmode == "" || netmode == "default" {
		netmode = "bridge"
	}
	var err error
	if spec.NetNS, err = podmanChainParseNetworkFlag(netmode); err != nil {
		return fmt.Errorf("make cli opts(): %w", err)
	}
	modes := []struct {
		mode  string
		into  *podmanChainNamespace
		parse func(string) (podmanChainNamespace, error)
	}{
		{cc.HostConfig.PidMode, &spec.PidNS, podmanChainParseNamespace},
		{cc.HostConfig.IpcMode, &spec.IpcNS, podmanChainParseIPCNamespace},
		{cc.HostConfig.UTSMode, &spec.UtsNS, podmanChainParseNamespace},
		{cc.HostConfig.CgroupnsMode, &spec.CgroupNS, podmanChainParseNamespace},
		{cc.HostConfig.UsernsMode, &spec.UserNS, podmanChainParseUserNamespace},
	}
	for _, m := range modes {
		if m.mode == "" {
			continue
		}
		if *m.into, err = m.parse(m.mode); err != nil {
			return fmt.Errorf("fill out specgen: %w", err)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	joined, err := d.makeContainerLocked(&spec)
	if err != nil {
		return err
	}
	d.created = append(d.created, "container: "+describePodmanChainJoins(joined))
	return nil
}

// podmanChainParseNamespace is specgen.ParseNamespace (namespaces.go:238-260).
func podmanChainParseNamespace(ns string) (podmanChainNamespace, error) {
	switch ns {
	case "pod", "host":
		return podmanChainNamespace{NSMode: ns}, nil
	case "private", "":
		return podmanChainNamespace{NSMode: "private"}, nil
	}
	if value, ok := strings.CutPrefix(ns, "ns:"); ok {
		return podmanChainNamespace{NSMode: "path", Value: value}, nil
	}
	if value, ok := strings.CutPrefix(ns, "container:"); ok {
		return podmanChainNamespace{NSMode: "container", Value: value}, nil
	}
	return podmanChainNamespace{}, fmt.Errorf("unrecognized namespace mode %s passed", ns)
}

// podmanChainParseIPCNamespace is specgen.ParseIPCNamespace
// (namespaces.go:289-300).
func podmanChainParseIPCNamespace(ns string) (podmanChainNamespace, error) {
	switch ns {
	case "shareable", "":
		return podmanChainNamespace{NSMode: "shareable"}, nil
	case "none":
		return podmanChainNamespace{NSMode: "none"}, nil
	}
	return podmanChainParseNamespace(ns)
}

// podmanChainParseUserNamespace is specgen.ParseUserNamespace
// (namespaces.go:304-332).
func podmanChainParseUserNamespace(ns string) (podmanChainNamespace, error) {
	switch ns {
	case "auto", "keep-id":
		return podmanChainNamespace{NSMode: ns}, nil
	case "nomap":
		return podmanChainNamespace{NSMode: "no-map"}, nil
	case "":
		return podmanChainNamespace{NSMode: "host"}, nil
	}
	if value, ok := strings.CutPrefix(ns, "auto:"); ok {
		return podmanChainNamespace{NSMode: "auto", Value: value}, nil
	}
	if value, ok := strings.CutPrefix(ns, "keep-id:"); ok {
		return podmanChainNamespace{NSMode: "keep-id", Value: value}, nil
	}
	return podmanChainParseNamespace(ns)
}

// podmanChainParseNetworkFlag is the mode specgen.ParseNetworkFlag picks
// (namespaces.go:352-419). Network options aren't modeled: any other value
// is a network name, which runs in bridge mode.
func podmanChainParseNetworkFlag(ns string) (podmanChainNamespace, error) {
	switch {
	case ns == "slirp4netns", strings.HasPrefix(ns, "slirp4netns:"):
		return podmanChainNamespace{NSMode: "slirp4netns"}, nil
	case ns == "pod", ns == "none", ns == "host":
		return podmanChainNamespace{NSMode: ns}, nil
	case ns == "", ns == "default", ns == "private":
		return podmanChainNamespace{NSMode: "private"}, nil
	case ns == "bridge", strings.HasPrefix(ns, "bridge:"):
		return podmanChainNamespace{NSMode: "bridge"}, nil
	case strings.HasPrefix(ns, "ns:"):
		return podmanChainNamespace{NSMode: "path", Value: strings.TrimPrefix(ns, "ns:")}, nil
	case strings.HasPrefix(ns, "container:"):
		return podmanChainNamespace{NSMode: "container", Value: strings.TrimPrefix(ns, "container:")}, nil
	case ns == "pasta", strings.HasPrefix(ns, "pasta:"):
		return podmanChainNamespace{NSMode: "pasta"}, nil
	case strings.HasPrefix(ns, ":"):
		return podmanChainNamespace{}, errors.New("network name cannot be empty")
	}
	return podmanChainNamespace{NSMode: "bridge"}, nil
}

// podmanChainValidate is the check SpecGenerator.Validate runs on each
// namespace: validate, validateIPCNS, validateUserNS and validateNetNS
// (namespaces.go:146-233). The daemon is rootful, so pasta is refused.
func podmanChainValidate(kind string, n podmanChainNamespace) error {
	switch kind {
	case "ipcns":
		if n.NSMode == "shareable" || n.NSMode == "none" {
			return nil
		}
	case "userns":
		if n.NSMode == "auto" || n.NSMode == "keep-id" || n.NSMode == "no-map" {
			return nil
		}
	case "netns":
		switch n.NSMode {
		case "slirp4netns", "", "default", "host", "path", "container", "pod", "private", "none", "bridge":
		case "pasta":
			return errors.New("pasta networking is only supported for rootless mode or when inside a nested userns")
		default:
			return fmt.Errorf("invalid network %q", n.NSMode)
		}
		return podmanChainValidateValue(n, n.NSMode == "slirp4netns")
	}
	switch n.NSMode {
	case "", "default", "host", "path", "container", "pod", "private":
	case "none", "bridge", "slirp4netns", "pasta":
		return errors.New("cannot use network modes with non-network namespace")
	default:
		return fmt.Errorf("invalid namespace type %s specified", n.NSMode)
	}
	return podmanChainValidateValue(n, false)
}

func podmanChainValidateValue(n podmanChainNamespace, valueOptional bool) error {
	needsValue := n.NSMode == "path" || n.NSMode == "container"
	switch {
	case needsValue && n.Value == "":
		return fmt.Errorf("namespace mode %s requires a value", n.NSMode)
	case !needsValue && !valueOptional && n.Value != "":
		return fmt.Errorf("namespace value %s cannot be provided with namespace mode %s", n.Value, n.NSMode)
	}
	return nil
}

// makeContainerLocked is generate.MakeContainer as far as namespaces go. It
// returns the namespace each kind ends up in: "host", "path:<path>",
// "container:<name>", "pod:<name>=<the infra container's>", or "own" for one
// Podman makes for the container or picks from containers.conf.
func (d *podmanNamespaceChainDaemon) makeContainerLocked(spec *podmanChainSpec) (map[string]string, error) {
	var pod *podmanChainPod
	if spec.Pod != "" {
		found, ok := d.pods[spec.Pod]
		if !ok {
			return nil, fmt.Errorf("retrieving pod %s: no such pod", spec.Pod)
		}
		pod = &found
	}
	joined := map[string]string{}
	for _, kind := range podmanChainKinds {
		ns := spec.namespace(kind)
		if ns.isDefault() {
			// GetDefaultNamespaceMode
			// (pkg/specgen/generate/namespaces.go:42-115). Outside a pod
			// that shares the namespace, the default is containers.conf's.
			switch {
			case pod == nil || !pod.shares[kind]:
				joined[kind] = "own"
				continue
			case pod.infra[kind] == "host":
				ns = podmanChainNamespace{NSMode: "host"}
			default:
				ns = podmanChainNamespace{NSMode: "pod"}
			}
		}
		if err := podmanChainValidate(kind, ns); err != nil {
			return nil, fmt.Errorf("invalid config provided: %w", err)
		}
		where, err := d.joinLocked(kind, ns, spec, pod)
		if err != nil {
			return nil, err
		}
		joined[kind] = where
	}
	return joined, nil
}

func (d *podmanNamespaceChainDaemon) joinLocked(kind string, ns podmanChainNamespace, spec *podmanChainSpec, pod *podmanChainPod) (string, error) {
	switch ns.NSMode {
	case "host":
		return "host", nil
	case "path":
		if !strings.HasPrefix(ns.Value, "/proc/1/ns/") && !strings.HasPrefix(ns.Value, "/run/netns/") {
			return "", fmt.Errorf("cannot find specified %s path: %s", kind, ns.Value)
		}
		return "path:" + ns.Value, nil
	case "container":
		if ns.Value != "web" {
			return "", fmt.Errorf("looking up container to share %s with: no such container %s", kind, ns.Value)
		}
		return "container:" + ns.Value, nil
	case "pod":
		if pod == nil || len(pod.infra) == 0 {
			return "", errors.New("cannot use pod namespace as container is not joining a pod or pod has no infra container")
		}
		return "pod:" + spec.Pod + "=" + pod.infra[kind], nil
	case "private":
		// container_validate.go:91-93.
		if kind == "userns" && spec.IDMappings == nil {
			return "", errors.New("invalid config provided: IDMappings are required when not creating a User namespace")
		}
	case "no-map":
		// pkg/util/utils.go:260-263.
		return "", errors.New("nomap is only supported in rootless mode")
	}
	return "own", nil
}

func describePodmanChainJoins(joined map[string]string) string {
	var parts []string
	for _, kind := range podmanChainKinds {
		if where := joined[kind]; where != "own" {
			parts = append(parts, kind+"="+where)
		}
	}
	if len(parts) == 0 {
		return "own namespaces"
	}
	return strings.Join(parts, " ")
}

func (d *podmanNamespaceChainDaemon) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.created)
}

// TestServeChainNamespaceJoinedByPathNeedsTheHostGate sends container and pod
// creates through the production chain to a daemon that picks namespaces the
// way Podman does, and asserts on the namespaces each container it made is in.
//
// The host namespace gates only matched nsmode `host`. Podman's `path` mode
// joins whatever namespace the path names, and /proc/1/ns/pid is the host's,
// so a create could put a container in the host PID namespace with
// allow_host_pid off. The same went for netns, ipcns and userns, for a pod's
// netns, and for `ns:<path>` on every HostConfig mode of the compat create.
// A namespace joined by path now needs the gate `host` needs, and while a
// gate is off its namespace takes only the modes Podman has that keep the
// container out of the host's.
//
// The cases still named "joins" with every gate off are the ones no gate
// reads yet: utsns and cgroupns on the native create, and a pod's pidns,
// ipcns, utsns and userns.
func TestServeChainNamespaceJoinedByPathNeedsTheHostGate(t *testing.T) {
	const (
		libpodCreate = "/v5.8.6/libpod/containers/create"
		podCreate    = "/v5.8.6/libpod/pods/create"
		compatCreate = "/v1.41/containers/create"
	)
	type request struct{ target, body string }
	libpod := func(fields string) request {
		return request{libpodCreate, `{"image":"alpine","systemd":"false",` + fields + `}`}
	}
	pod := func(fields string) request {
		return request{podCreate, `{"name":"p",` + fields + `}`}
	}
	compat := func(hostConfig string) request {
		return request{compatCreate, `{"Image":"alpine","HostConfig":{` + hostConfig + `}}`}
	}
	created := func(joins ...string) []string {
		out := make([]string, 0, len(joins))
		for _, join := range joins {
			out = append(out, "container: "+join)
		}
		return out
	}
	infra := func(joins string) []string { return []string{"pod p infra: " + joins} }
	type gates = config.RequestBodyConfig
	hostPID := func(body *gates) {
		body.ContainerCreate.AllowHostPID = true
		body.LibpodContainerCreate.AllowHostPID = true
	}

	tests := []struct {
		name        string
		configure   func(*gates)
		first       *request
		send        request
		wantStatus  int
		wantReason  string
		wantCreated []string
	}{
		// Native container create, every gate off.
		{
			// What podman-remote create sends: every namespace present and
			// empty (internal/filter/testdata/libpod/basic_create.json).
			name:        "libpod create with podman-remote's empty namespaces",
			send:        libpod(`"netns":{},"pidns":{},"ipcns":{},"userns":{},"utsns":{},"cgroupns":{}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("own namespaces"),
		},
		{name: "libpod netns host", send: libpod(`"netns":{"nsmode":"host"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: host network namespace is not allowed"},
		{name: "libpod pidns host", send: libpod(`"pidns":{"nsmode":"host"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: host PID namespace is not allowed"},
		{name: "libpod ipcns host", send: libpod(`"ipcns":{"nsmode":"host"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: host IPC namespace is not allowed"},
		{name: "libpod userns host", send: libpod(`"userns":{"nsmode":"host"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: host user namespace is not allowed"},
		{name: "libpod utsns host joins", send: libpod(`"utsns":{"nsmode":"host"}`), wantStatus: http.StatusCreated, wantCreated: created("utsns=host")},
		{name: "libpod cgroupns host joins", send: libpod(`"cgroupns":{"nsmode":"host"}`), wantStatus: http.StatusCreated, wantCreated: created("cgroupns=host")},
		{name: "libpod netns path", send: libpod(`"netns":{"nsmode":"path","value":"/proc/1/ns/net"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: network namespace joined by path is not allowed"},
		{name: "libpod netns path to a named netns", send: libpod(`"netns":{"nsmode":"path","value":"/run/netns/other"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: network namespace joined by path is not allowed"},
		{name: "libpod pidns path", send: libpod(`"pidns":{"nsmode":"path","value":"/proc/1/ns/pid"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: PID namespace joined by path is not allowed"},
		{name: "libpod ipcns path", send: libpod(`"ipcns":{"nsmode":"path","value":"/proc/1/ns/ipc"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: IPC namespace joined by path is not allowed"},
		{name: "libpod userns path", send: libpod(`"userns":{"nsmode":"path","value":"/proc/1/ns/user"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: user namespace joined by path is not allowed"},
		{name: "libpod utsns path joins", send: libpod(`"utsns":{"nsmode":"path","value":"/proc/1/ns/uts"}`), wantStatus: http.StatusCreated, wantCreated: created("utsns=path:/proc/1/ns/uts")},
		{name: "libpod cgroupns path joins", send: libpod(`"cgroupns":{"nsmode":"path","value":"/proc/1/ns/cgroup"}`), wantStatus: http.StatusCreated, wantCreated: created("cgroupns=path:/proc/1/ns/cgroup")},
		{
			name:       "libpod every namespace by path",
			send:       libpod(`"netns":{"nsmode":"path","value":"/proc/1/ns/net"},"pidns":{"nsmode":"path","value":"/proc/1/ns/pid"},"ipcns":{"nsmode":"path","value":"/proc/1/ns/ipc"},"userns":{"nsmode":"path","value":"/proc/1/ns/user"}`),
			wantStatus: http.StatusForbidden,
			wantReason: "libpod container create denied: network namespace joined by path is not allowed",
		},

		// The keys the way encoding/json matches them.
		{name: "libpod pidns path under an upper-case key", send: libpod(`"PIDNS":{"NSMode":"path","Value":"/proc/1/ns/pid"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: PID namespace joined by path is not allowed"},
		{
			// encoding/json folds U+017F, the long s, onto s.
			name:       "libpod pidns path under a key with a long s",
			send:       libpod("\"pidn\u017f\":{\"nsmode\":\"path\",\"value\":\"/proc/1/ns/pid\"}"),
			wantStatus: http.StatusForbidden,
			wantReason: "libpod container create denied: PID namespace joined by path is not allowed",
		},
		{name: "libpod pidns path as the last of two nsmodes", send: libpod(`"pidns":{"nsmode":"private","nsmode":"path","value":"/proc/1/ns/pid"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: PID namespace joined by path is not allowed"},
		{name: "libpod pidns path as the last of two pidns", send: libpod(`"pidns":{"nsmode":"private"},"pidns":{"nsmode":"path","value":"/proc/1/ns/pid"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: PID namespace joined by path is not allowed"},
		{
			// A repeated key decodes into the same struct, so the mode of one
			// and the value of the other add up.
			name:       "libpod pidns path split across two spellings",
			send:       libpod(`"pidns":{"value":"/proc/1/ns/pid"},"PidNS":{"nsmode":"path"}`),
			wantStatus: http.StatusForbidden,
			wantReason: "libpod container create denied: PID namespace joined by path is not allowed",
		},
		{
			// The last nsmode wins, and Podman refuses a value on `private`.
			name:       "libpod pidns path as the first of two nsmodes",
			send:       libpod(`"pidns":{"nsmode":"path","value":"/proc/1/ns/pid","nsmode":"private"}`),
			wantStatus: http.StatusInternalServerError,
		},

		// Modes Podman doesn't have, and namespaces that aren't objects. Podman
		// answers the first three with a 500, and they don't get that far.
		{name: "libpod pidns Path in another case", send: libpod(`"pidns":{"nsmode":"Path","value":"/proc/1/ns/pid"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: PID namespace joined by path is not allowed"},
		{name: "libpod pidns with a mode Podman doesn't have", send: libpod(`"pidns":{"nsmode":"hostns"}`), wantStatus: http.StatusForbidden, wantReason: `libpod container create denied: PID namespace mode "hostns" is not recognized`},
		{name: "libpod pidns with a network mode", send: libpod(`"pidns":{"nsmode":"bridge"}`), wantStatus: http.StatusForbidden, wantReason: `libpod container create denied: PID namespace mode "bridge" is not recognized`},
		{name: "libpod pidns as a string", send: libpod(`"pidns":"host"`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: malformed JSON request body"},
		{name: "libpod pidns with an nsmode that isn't a string", send: libpod(`"pidns":{"nsmode":["path"],"value":"/proc/1/ns/pid"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: malformed JSON request body"},

		// Modes that don't join a host namespace.
		{name: "libpod namespaces private", send: libpod(`"netns":{"nsmode":"private"},"pidns":{"nsmode":"private"},"ipcns":{"nsmode":"private"},"utsns":{"nsmode":"private"},"cgroupns":{"nsmode":"private"}`), wantStatus: http.StatusCreated, wantCreated: created("own namespaces")},
		{name: "libpod namespaces default", send: libpod(`"netns":{"nsmode":"default"},"pidns":{"nsmode":"default"},"ipcns":{"nsmode":"default"},"userns":{"nsmode":"default"},"utsns":{"nsmode":"default"},"cgroupns":{"nsmode":"default"}`), wantStatus: http.StatusCreated, wantCreated: created("own namespaces")},
		{name: "libpod ipcns shareable", send: libpod(`"ipcns":{"nsmode":"shareable"}`), wantStatus: http.StatusCreated, wantCreated: created("own namespaces")},
		{name: "libpod ipcns none", send: libpod(`"ipcns":{"nsmode":"none"}`), wantStatus: http.StatusCreated, wantCreated: created("own namespaces")},
		{name: "libpod netns bridge", send: libpod(`"netns":{"nsmode":"bridge"}`), wantStatus: http.StatusCreated, wantCreated: created("own namespaces")},
		{name: "libpod netns none", send: libpod(`"netns":{"nsmode":"none"}`), wantStatus: http.StatusCreated, wantCreated: created("own namespaces")},
		{name: "libpod netns slirp4netns with options", send: libpod(`"netns":{"nsmode":"slirp4netns","value":"cidr=10.0.3.0/24"}`), wantStatus: http.StatusCreated, wantCreated: created("own namespaces")},
		{
			// Rootless only, so this daemon answers 500, but it has to get there.
			name:       "libpod netns pasta",
			send:       libpod(`"netns":{"nsmode":"pasta"}`),
			wantStatus: http.StatusInternalServerError,
		},
		{name: "libpod userns auto", send: libpod(`"userns":{"nsmode":"auto","value":"size=4096"}`), wantStatus: http.StatusCreated, wantCreated: created("own namespaces")},
		{name: "libpod userns keep-id", send: libpod(`"userns":{"nsmode":"keep-id"}`), wantStatus: http.StatusCreated, wantCreated: created("own namespaces")},
		{
			// Rootless only as well.
			name:       "libpod userns no-map",
			send:       libpod(`"userns":{"nsmode":"no-map"}`),
			wantStatus: http.StatusInternalServerError,
		},
		{
			// Another container's namespace has its own gate,
			// restrict_namespace_sharing, which is off by default.
			name:        "libpod pidns of another container joins",
			send:        libpod(`"pidns":{"nsmode":"container","value":"web"}`),
			wantStatus:  http.StatusCreated,
			wantCreated: created("pidns=container:web"),
		},
		{
			name:        "libpod pidns of the pod joins the infra container's",
			first:       &request{podCreate, `{"name":"p","pidns":{"nsmode":"private"},"ipcns":{"nsmode":"private"},"utsns":{"nsmode":"private"},"userns":{},"netns":{},"shared_namespaces":["ipc","net","uts"]}`},
			send:        libpod(`"pod":"p","pidns":{"nsmode":"pod"}`),
			wantStatus:  http.StatusCreated,
			wantCreated: []string{"pod p infra: own namespaces", "container: netns=pod:p=own pidns=pod:p=own ipcns=pod:p=own utsns=pod:p=own"},
		},

		// Native container create with a gate on.
		{name: "libpod pidns host with allow_host_pid", configure: hostPID, send: libpod(`"pidns":{"nsmode":"host"}`), wantStatus: http.StatusCreated, wantCreated: created("pidns=host")},
		{name: "libpod pidns path with allow_host_pid", configure: hostPID, send: libpod(`"pidns":{"nsmode":"path","value":"/proc/1/ns/pid"}`), wantStatus: http.StatusCreated, wantCreated: created("pidns=path:/proc/1/ns/pid")},
		{name: "libpod netns path with only allow_host_pid", configure: hostPID, send: libpod(`"netns":{"nsmode":"path","value":"/proc/1/ns/net"}`), wantStatus: http.StatusForbidden, wantReason: "libpod container create denied: network namespace joined by path is not allowed"},
		{
			// A path can name another container's namespace as easily as
			// the host's, and no allowlist of containers can vouch for it.
			name: "libpod pidns path with allow_host_pid and sharing restricted",
			configure: func(body *gates) {
				hostPID(body)
				body.LibpodContainerCreate.RestrictNamespaceSharing = true
				body.LibpodContainerCreate.AllowedNamespaceSharingContainers = []string{"web"}
			},
			send:       libpod(`"pidns":{"nsmode":"path","value":"/proc/1/ns/pid"}`),
			wantStatus: http.StatusForbidden,
			wantReason: "libpod container create denied: PID namespace joined by path is not allowed while namespace sharing is restricted",
		},

		// Pod create, every gate off. The namespaces are the infra container's.
		{
			// What podman-remote pod create sends (pkg/domain/entities/pods.go:309-329).
			name:        "pod create with podman-remote's namespaces",
			send:        pod(`"pidns":{"nsmode":"private"},"ipcns":{"nsmode":"private"},"utsns":{"nsmode":"private"},"userns":{},"netns":{},"shared_namespaces":["ipc","net","uts"]`),
			wantStatus:  http.StatusCreated,
			wantCreated: infra("own namespaces"),
		},
		{
			// What podman-remote run --pod new:p sends for the user
			// namespace (cmd/podman/containers/create.go:453).
			name:        "pod create with a default userns",
			send:        pod(`"userns":{"nsmode":"default"}`),
			wantStatus:  http.StatusCreated,
			wantCreated: infra("own namespaces"),
		},
		{name: "pod netns host", send: pod(`"netns":{"nsmode":"host"}`), wantStatus: http.StatusForbidden, wantReason: "libpod pod create denied: host network namespace is not allowed"},
		{name: "pod netns path", send: pod(`"netns":{"nsmode":"path","value":"/proc/1/ns/net"}`), wantStatus: http.StatusForbidden, wantReason: "libpod pod create denied: network namespace joined by path is not allowed"},
		{name: "pod pidns host joins", send: pod(`"pidns":{"nsmode":"host"}`), wantStatus: http.StatusCreated, wantCreated: infra("pidns=host")},
		{name: "pod pidns path joins", send: pod(`"pidns":{"nsmode":"path","value":"/proc/1/ns/pid"}`), wantStatus: http.StatusCreated, wantCreated: infra("pidns=path:/proc/1/ns/pid")},
		{name: "pod ipcns host joins", send: pod(`"ipcns":{"nsmode":"host"}`), wantStatus: http.StatusCreated, wantCreated: infra("ipcns=host")},
		{name: "pod ipcns path joins", send: pod(`"ipcns":{"nsmode":"path","value":"/proc/1/ns/ipc"}`), wantStatus: http.StatusCreated, wantCreated: infra("ipcns=path:/proc/1/ns/ipc")},
		{name: "pod utsns host joins", send: pod(`"utsns":{"nsmode":"host"}`), wantStatus: http.StatusCreated, wantCreated: infra("utsns=host")},
		{name: "pod utsns path joins", send: pod(`"utsns":{"nsmode":"path","value":"/proc/1/ns/uts"}`), wantStatus: http.StatusCreated, wantCreated: infra("utsns=path:/proc/1/ns/uts")},
		{name: "pod userns host joins", send: pod(`"userns":{"nsmode":"host"}`), wantStatus: http.StatusCreated, wantCreated: infra("userns=host")},
		{
			// The string form "path:/proc/1/ns/user" is one
			// ParseUserNamespace can't read, so Podman refuses this itself.
			name:       "pod userns path",
			send:       pod(`"userns":{"nsmode":"path","value":"/proc/1/ns/user"}`),
			wantStatus: http.StatusInternalServerError,
		},
		{name: "pod pidns host in another case", send: pod(`"pidns":{"nsmode":"Host"}`), wantStatus: http.StatusInternalServerError},
		{name: "pod pidns of another container joins", send: pod(`"pidns":{"nsmode":"container","value":"web"}`), wantStatus: http.StatusCreated, wantCreated: infra("pidns=container:web")},
		{
			// A container in the pod asks for the pod's PID namespace, and
			// Podman hands it the infra container's whether or not the pod
			// shares it.
			name:        "container in a host-PID pod joins the host PID namespace",
			first:       &request{podCreate, `{"name":"p","pidns":{"nsmode":"host"}}`},
			send:        libpod(`"pod":"p","pidns":{"nsmode":"pod"}`),
			wantStatus:  http.StatusCreated,
			wantCreated: []string{"pod p infra: pidns=host", "container: netns=pod:p=own pidns=pod:p=host ipcns=pod:p=own utsns=pod:p=own"},
		},
		{
			name:        "pod netns path with allow_host_network",
			configure:   func(body *gates) { body.LibpodPodCreate.AllowHostNetwork = true },
			send:        pod(`"netns":{"nsmode":"path","value":"/proc/1/ns/net"}`),
			wantStatus:  http.StatusCreated,
			wantCreated: infra("netns=path:/proc/1/ns/net"),
		},
		{name: "pod pidns host with the container allow_host_pid", configure: hostPID, send: pod(`"pidns":{"nsmode":"host"}`), wantStatus: http.StatusCreated, wantCreated: infra("pidns=host")},

		// Docker-compatible create on the same Podman, every gate off.
		{name: "compat create with no modes", send: compat(``), wantStatus: http.StatusCreated, wantCreated: created("own namespaces")},
		{name: "compat NetworkMode host", send: compat(`"NetworkMode":"host"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: host network mode is not allowed"},
		{name: "compat PidMode host", send: compat(`"PidMode":"host"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: host PID mode is not allowed"},
		{name: "compat IpcMode host", send: compat(`"IpcMode":"host"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: host IPC mode is not allowed"},
		{name: "compat UsernsMode host", send: compat(`"UsernsMode":"host"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: host user namespace mode is not allowed"},
		{name: "compat CgroupnsMode host", send: compat(`"CgroupnsMode":"host"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: host cgroup namespace mode is not allowed"},
		{name: "compat UTSMode host", send: compat(`"UTSMode":"host"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: host UTS mode is not allowed"},
		{name: "compat NetworkMode ns:", send: compat(`"NetworkMode":"ns:/proc/1/ns/net"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: network namespace joined by path is not allowed"},
		{name: "compat PidMode ns:", send: compat(`"PidMode":"ns:/proc/1/ns/pid"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: PID namespace joined by path is not allowed"},
		{name: "compat IpcMode ns:", send: compat(`"IpcMode":"ns:/proc/1/ns/ipc"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: IPC namespace joined by path is not allowed"},
		{name: "compat UsernsMode ns:", send: compat(`"UsernsMode":"ns:/proc/1/ns/user"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: user namespace joined by path is not allowed"},
		{name: "compat CgroupnsMode ns:", send: compat(`"CgroupnsMode":"ns:/proc/1/ns/cgroup"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: cgroup namespace joined by path is not allowed"},
		{name: "compat UTSMode ns:", send: compat(`"UTSMode":"ns:/proc/1/ns/uts"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: UTS namespace joined by path is not allowed"},
		{name: "compat PidMode ns: under a lower-case key", send: compat(`"pidmode":"ns:/proc/1/ns/pid"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: PID namespace joined by path is not allowed"},
		{
			// deny_namespace_path_mode still refuses it once host network is allowed.
			name: "compat NetworkMode ns: with allow_host_network and deny_namespace_path_mode",
			configure: func(body *gates) {
				body.ContainerCreate.AllowHostNetwork = true
				body.ContainerCreate.DenyNamespacePathMode = true
			},
			send:       compat(`"NetworkMode":"ns:/proc/1/ns/net"`),
			wantStatus: http.StatusForbidden,
			wantReason: "container create denied: ns: namespace path mode is not allowed",
		},
		{
			// Podman matches the prefix byte for byte and would refuse this one.
			name:       "compat PidMode NS: in another case",
			send:       compat(`"PidMode":"NS:/proc/1/ns/pid"`),
			wantStatus: http.StatusForbidden,
			wantReason: "container create denied: PID namespace joined by path is not allowed",
		},
		{name: "compat PidMode Host in another case", send: compat(`"PidMode":"Host"`), wantStatus: http.StatusForbidden, wantReason: "container create denied: host PID mode is not allowed"},
		{name: "compat PidMode private", send: compat(`"PidMode":"private"`), wantStatus: http.StatusCreated, wantCreated: created("own namespaces")},
		{name: "compat PidMode of another container joins", send: compat(`"PidMode":"container:web"`), wantStatus: http.StatusCreated, wantCreated: created("pidns=container:web")},
		{name: "compat NetworkMode naming a network", send: compat(`"NetworkMode":"backend"`), wantStatus: http.StatusCreated, wantCreated: created("own namespaces")},
		{name: "compat PidMode host with allow_host_pid", configure: hostPID, send: compat(`"PidMode":"host"`), wantStatus: http.StatusCreated, wantCreated: created("pidns=host")},
		{name: "compat PidMode ns: with allow_host_pid", configure: hostPID, send: compat(`"PidMode":"ns:/proc/1/ns/pid"`), wantStatus: http.StatusCreated, wantCreated: created("pidns=path:/proc/1/ns/pid")},
		{
			name: "compat PidMode ns: with allow_host_pid and sharing restricted",
			configure: func(body *gates) {
				hostPID(body)
				body.ContainerCreate.RestrictNamespaceSharing = true
				body.ContainerCreate.AllowedNamespaceSharingContainers = []string{"web"}
			},
			send:       compat(`"PidMode":"ns:/proc/1/ns/pid"`),
			wantStatus: http.StatusForbidden,
			wantReason: "container create denied: PID namespace joined by path is not allowed while namespace sharing is restricted",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newPodmanNamespaceChainDaemon()
			addr := newEngineChain(t, "ns-path", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/pods/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				if tt.configure != nil {
					tt.configure(&cfg.RequestBody)
				}
			})

			if tt.first != nil {
				sendNamespaceChainRequest(t, "http://"+addr+tt.first.target, tt.first.body)
			}
			status, body := sendNamespaceChainRequest(t, "http://"+addr+tt.send.target, tt.send.body)
			if got := daemon.seen(); !slices.Equal(got, tt.wantCreated) {
				t.Errorf("daemon created %q, want %q", got, tt.wantCreated)
			}
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
			if tt.wantStatus == http.StatusForbidden && tt.wantReason == "" {
				t.Fatal("a denied case must name the reason it is denied for")
			}
			if tt.wantReason != "" {
				var denial struct {
					Reason string `json:"reason"`
				}
				if err := json.Unmarshal(body, &denial); err != nil || denial.Reason != tt.wantReason {
					t.Errorf("body = %s, want reason %q", body, tt.wantReason)
				}
			}
		})
	}
}

func sendNamespaceChainRequest(t *testing.T, target, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}
