package filter

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

// local_volume_bind.go holds the one policy that decides whether a local
// volume driver options map reaches a host path the bind allowlist is
// supposed to govern.
//
// Docker's and Podman's built-in "local" driver forwards its type/o/device
// options straight to mount(2), so `{"type":"none","o":"bind","device":"/"}`
// bind-mounts an arbitrary host path into the container. That reaches the
// filesystem a HostConfig.Binds entry or a Type: "bind" mount would reach,
// but it arrives as a volume — through Mount.VolumeOptions.DriverConfig on
// POST /containers/create, or through DriverOpts on POST /volumes/create for
// a volume that is then mounted by name later — so none of the bind-mount
// allowlist checks used to see it.
//
// The same options map reaches the host a second way, without asking for a
// bind at all: `{"type":"ext4","device":"/dev/sda1"}` hands the kernel a raw
// block device and a filesystem driver, which mounts the whole device into
// the container. That is host-root-equivalent for the same reason a bind of
// "/" is — it is the host's own storage, read and written outside every
// namespace boundary — so it is checked against the same allowlist rather
// than a second one. Every caller here runs each device through the same
// bindPathAllowed the bind checks use, so there is a single allowlist and a
// single place an operator widens it.

// localVolumeDriverName is the volume driver Docker and Podman fall back to
// when a create request names none, so an empty driver name selects it. The
// checks below therefore treat "" and "local" identically.
const localVolumeDriverName = "local"

// localVolumeBindMountOptions are the "o" tokens that set MS_BIND. Both
// daemons split "o" on commas and look each token up in a flag table keyed by
// the exact strings below, so matching whole tokens rather than a substring
// keeps an NFS option string like "addr=bind.example.com" from reading as a
// bind request.
var localVolumeBindMountOptions = map[string]bool{
	"bind":  true,
	"rbind": true,
}

// localVolumeBindFilesystemTypes are the "type" values that name a bind
// rather than a real filesystem. "none" is the conventional spelling
// (`--opt type=none --opt o=bind`); "bind" is included so a request that
// names it directly is treated the same way.
var localVolumeBindFilesystemTypes = map[string]bool{
	"none": true,
	"bind": true,
}

// localVolumeRemoteFilesystemTypes are the "type" values whose device is not
// a host path at all. The network filesystems take a server export
// ("nfs-server:/exports", "//host/share") and tmpfs ignores the device
// entirely, so a device under one of these types never names local storage
// and is left alone. Every other type — ext4, xfs, btrfs, vfat, and any
// other kernel filesystem driver, plus a type the request omits — mounts
// whatever the device points at, which is why the device-path check below
// applies to all of them rather than to an enumerated block-device list that
// a new filesystem name would fall out of.
var localVolumeRemoteFilesystemTypes = map[string]bool{
	"nfs":   true,
	"nfs4":  true,
	"cifs":  true,
	"smb3":  true,
	"tmpfs": true,
}

// localVolumeOptions is the decoded view of a local driver options map: every
// device it names, every filesystem type it names, and whether it asks for a
// bind. Types and devices are plural because the map is keyed
// case-insensitively here (the two daemons do not agree on whether they
// lowercase keys before dispatch, and a key spelled in a case this check
// missed would be a hole rather than a rejected request), so "device" and
// "Device" are two live entries whose relative precedence is a Go map
// iteration order neither daemon promises. Collecting them all and checking
// each one is the only answer that does not depend on that order.
type localVolumeOptions struct {
	types   []string
	devices []string
	bind    bool
}

// parseLocalVolumeOptions decodes a local driver options map. It reports
// false when the driver is not the local one or the map is empty — a
// third-party driver's options mean whatever that plugin decides, and an
// empty map asks for nothing.
func parseLocalVolumeOptions(driver string, options map[string]string) (localVolumeOptions, bool) {
	var parsed localVolumeOptions

	if len(options) == 0 {
		return parsed, false
	}
	if name := strings.TrimSpace(driver); name != "" && !strings.EqualFold(name, localVolumeDriverName) {
		return parsed, false
	}

	for key, value := range options {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "device":
			if device := strings.TrimSpace(value); device != "" {
				parsed.devices = append(parsed.devices, device)
			}
		case "type":
			fsType := strings.ToLower(strings.TrimSpace(value))
			parsed.types = append(parsed.types, fsType)
			if localVolumeBindFilesystemTypes[fsType] {
				parsed.bind = true
			}
		case "o":
			for _, option := range strings.Split(value, ",") {
				option = strings.TrimSpace(option)
				if localVolumeBindMountOptions[strings.ToLower(option)] {
					parsed.bind = true
					continue
				}
				// btrfs takes extra members of a multi-device
				// filesystem as "device=" entries in the mount data
				// rather than as the mount source, and both daemons
				// pass "o" through to mount(2) verbatim, so a device
				// spelled there reaches the kernel exactly as the
				// "device" option does.
				name, deviceValue, hasValue := strings.Cut(option, "=")
				if !hasValue || !strings.EqualFold(strings.TrimSpace(name), "device") {
					continue
				}
				if device := strings.TrimSpace(deviceValue); device != "" {
					parsed.devices = append(parsed.devices, device)
				}
			}
		}
	}

	slices.Sort(parsed.devices)
	return parsed, true
}

// mountsHostFilesystem reports whether the options ask the kernel to mount a
// filesystem off whatever the device names. That is every type other than the
// network filesystems and tmpfs, and it is also the absent-type case: the
// local driver with a device and no type builds a mount request the daemon
// rejects, so denying it costs a working configuration nothing and keeps the
// gate from turning on a field the request can simply omit.
func (o localVolumeOptions) mountsHostFilesystem() bool {
	for _, fsType := range o.types {
		if !localVolumeRemoteFilesystemTypes[fsType] {
			return true
		}
	}
	return len(o.types) == 0
}

// localVolumeBindDevices reports the host paths a local volume driver options
// map would bind-mount, sorted so a map carrying more than one spelling of
// the device key denies on a stable path. It returns nil when the driver is
// not the local one, when the options request no bind, or when they name no
// device — a non-bind local volume (tmpfs, nfs, cifs, a quota-only size opt)
// and a third-party driver's options are both left entirely alone.
func localVolumeBindDevices(driver string, options map[string]string) []string {
	parsed, ok := parseLocalVolumeOptions(driver, options)
	if !ok || !parsed.bind {
		return nil
	}
	return parsed.devices
}

// normalizeLocalVolumeDevice resolves a device the way the daemon's mount(2)
// call does, which is not the same as normalizeBindMount: mount(2) resolves a
// relative source against the daemon's working directory, and every packaged
// unit file leaves that at "/", so "dev/sda1" reaches the node "/dev/sda1"
// names. The value is rooted and then cleaned, which collapses "//dev/sda1",
// "/dev/./sda1" and "/dev/../dev/sda1" onto the same "/dev/sda1" the plain
// spelling produces. It reports false only for an empty device, which asks
// for nothing.
func normalizeLocalVolumeDevice(device string) (string, bool) {
	trimmed := strings.TrimSpace(device)
	if trimmed == "" {
		return "", false
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return path.Clean(trimmed), true
}

// isHostDevicePath reports whether a normalized device path names a node
// under /dev, the directory both daemons' host block and character devices
// live in.
func isHostDevicePath(device string) bool {
	return device == "/dev" || strings.HasPrefix(device, "/dev/")
}

// denyLocalVolumeBindDeviceReason checks every host path a local volume driver
// options map reaches against allowedBindMounts, using the same prefix rule
// (bindPathAllowed) a HostConfig.Binds entry or a Type: "bind" mount is
// checked against. The allowlist is a path allowlist only, so a read-only
// request is neither required nor consulted here, exactly as it is not for a
// "/host:/ctr:ro" bind.
//
// There are two ways in and they are checked in order, so a map that asks for
// both keeps the bind wording it has always had. A bind normalizes with
// normalizeBindMount, so "/srv/../etc" is compared as "/etc", and a device
// that is not an absolute path is denied rather than skipped — the one place
// this differs from the bind checks, which skip a source normalizeBindMount
// rejects because a relative source in Binds is a named volume and not a host
// path at all, whereas an options map that has already asked for a bind is
// naming a device the daemon resolves against its own working directory.
//
// A filesystem type over a /dev path is the second way: it is not a bind, so
// nothing above sees it, but mounting the host's own block device inside the
// container reaches the same data an allowlisted bind is there to bound. An
// operator who genuinely wants one lists the device path in the same
// allowed_bind_mounts. subject names the endpoint for the denial message so
// it matches the wording each inspector's other denials use.
func denyLocalVolumeBindDeviceReason(driver string, options map[string]string, allowedBindMounts []string, subject string) string {
	parsed, local := parseLocalVolumeOptions(driver, options)
	if !local {
		return ""
	}

	if parsed.bind {
		for _, device := range parsed.devices {
			source, ok := normalizeBindMount(device)
			if !ok {
				return fmt.Sprintf("%s denied: bind mount source %q is not allowlisted", subject, device)
			}
			if !bindPathAllowed(source, allowedBindMounts) {
				return fmt.Sprintf("%s denied: bind mount source %q is not allowlisted", subject, source)
			}
		}
	}

	if !parsed.mountsHostFilesystem() {
		return ""
	}
	for _, device := range parsed.devices {
		source, ok := normalizeLocalVolumeDevice(device)
		if !ok || !isHostDevicePath(source) {
			continue
		}
		if !bindPathAllowed(source, allowedBindMounts) {
			return fmt.Sprintf("%s denied: local volume device %q is not allowlisted", subject, source)
		}
	}

	return ""
}
