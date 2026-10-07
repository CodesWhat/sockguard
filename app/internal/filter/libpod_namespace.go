package filter

import (
	"fmt"
	"strings"
)

// libpod_namespace.go holds the host-namespace gate the libpod container
// create and pod create inspectors share. Both decode the same
// specgen.Namespace object, {"nsmode": "...", "value": "..."}, into
// libpodNamespace (libpod_container_create_types.go).
//
// The gate is an allowlist. While it is off, a namespace object passes only
// when its nsmode is one Podman accepts for that namespace and that keeps
// the container out of the host's namespace. `host` is refused, and so is
// `path`: Podman joins whatever namespace the path names, and it can name
// the host's. Anything else is a mode this file doesn't know, refused
// because nothing here can say where it puts the container.

// libpodNamespaceKind names one of the namespace fields SpecGenerator and
// PodSpecGenerator carry. Podman accepts a different set of modes for each.
type libpodNamespaceKind int

const (
	libpodNetNS libpodNamespaceKind = iota
	libpodPidNS
	libpodIpcNS
	libpodUserNS
	libpodUtsNS
	libpodCgroupNS
)

// label is how deny reasons name the namespace.
func (k libpodNamespaceKind) label() string {
	switch k {
	case libpodNetNS:
		return "network"
	case libpodPidNS:
		return "PID"
	case libpodIpcNS:
		return "IPC"
	case libpodUtsNS:
		return "UTS"
	case libpodCgroupNS:
		return "cgroup"
	default:
		return "user"
	}
}

// knowsMode reports whether mode is one Podman accepts for this namespace
// other than `host` and `path`. The lists are the ones specgen validates
// against in Podman 5.8.6 (pkg/specgen/namespaces.go: validate,
// validateIPCNS, validateUserNS and validateNetNS). Podman compares the mode
// byte for byte, so this does too: "Private" is not a mode it has.
//
// pidns, utsns and cgroupns go through validate alone
// (pkg/specgen/container_validate.go:134, 140 and 143), so they take the
// shared modes and nothing else. A pod's namespaces are held to the same
// lists: the pod create handler copies them onto the infra container's
// SpecGenerator, which is validated like any other
// (pkg/api/handlers/libpod/pods.go:60-65).
//
// An empty mode and `default` take the daemon's containers.conf setting.
// `container` joins another container's namespace, which
// restrict_namespace_sharing gates, and `pod` joins the namespace of the
// pod's infra container, which pod create gates.
func (k libpodNamespaceKind) knowsMode(mode string) bool {
	switch mode {
	case "", "default", "private", "container", "pod":
		return true
	}
	switch k {
	case libpodNetNS:
		return mode == "none" || mode == "bridge" || mode == "slirp4netns" || mode == "pasta"
	case libpodIpcNS:
		return mode == "shareable" || mode == "none"
	case libpodUserNS:
		return mode == "auto" || mode == "keep-id" || mode == "no-map"
	}
	return false
}

// isPath reports whether this namespace object joins a namespace by path.
// Matched loosely, like isHost, so a spelling Podman would refuse is
// refused here first.
func (n libpodNamespace) isPath() bool {
	return strings.EqualFold(strings.TrimSpace(n.NSMode), "path")
}

// hostGateDenyReason is why this namespace object is refused while the host
// gate for its namespace is off, or "" when it passes.
func (n libpodNamespace) hostGateDenyReason(subject string, kind libpodNamespaceKind) string {
	switch {
	case n.isHost():
		return fmt.Sprintf("%s denied: host %s namespace is not allowed", subject, kind.label())
	case n.isPath():
		return fmt.Sprintf("%s denied: %s namespace joined by path is not allowed", subject, kind.label())
	case !kind.knowsMode(n.NSMode):
		return fmt.Sprintf("%s denied: %s namespace mode %q is not recognized", subject, kind.label(), n.NSMode)
	}
	return ""
}
