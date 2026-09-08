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
// The same options map reaches the host without asking for a bind at all,
// and it does so in more than one shape, which is why the gate is a type
// ALLOWLIST rather than an enumerated list of dangerous spellings:
//
//   - `{"type":"ext4","device":"/dev/sda1"}` hands the kernel a raw block
//     device and a filesystem driver, which mounts the host's own storage
//     into the container.
//   - `{"type":"proc","device":"proc"}` (and sysfs, cgroup, debugfs, bpf,
//     tracefs, securityfs, and every other pseudo-filesystem) ignores the
//     device entirely and mounts host kernel state. Host /proc alone carries
//     /proc/1/root, which is the host's root filesystem.
//   - `{"type":"overlay","device":"overlay","o":"lowerdir=/,upperdir=…"}`
//     names its host paths in the mount data rather than in `device`, so a
//     check that only reads `device` never sees them.
//
// All three are host-root-equivalent for the same reason a bind of "/" is:
// they are the host's own storage or its own kernel state, read and written
// outside every namespace boundary. So the rule is not "which types are
// dangerous" — a list like that loses to the next filesystem name — but
// "which types provably do not name a local host path". That set is
// localVolumeAllowedRemoteTypes: the network filesystems, whose device is a
// server export, and tmpfs, which ignores the device and allocates its own
// pages. Everything else, including a request that declares no type at all,
// has to name a device that passes bindPathAllowed, and the overlay-style
// directory options in "o" are checked against the same allowlist whatever
// the type says. Every caller here runs each path through the same
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

// localVolumeAllowedRemoteTypes is the type allowlist: the "type" values
// whose device provably is not a local host path. The network filesystems
// take a server export ("nfs-server:/exports", "//host/share") and tmpfs
// ignores the device entirely and allocates its own pages, so a device under
// one of these never names local storage and is left alone.
//
// It is an allowlist and not a denylist on purpose. Every other type — ext4,
// xfs, btrfs and vfat over a block device, proc and sysfs and cgroup and
// every other pseudo-filesystem that ignores the device and mounts host
// kernel state, overlay, and any kernel filesystem driver that does not exist
// yet — mounts something of the host's, so all of them fall to the device
// check below. A type this set does not name is denied unless its device is
// allowlisted, which is the direction a new filesystem name has to fail in.
//
// The cost of the narrow set is a false deny: a working `type=9p` or
// `type=virtiofs` volume now needs its device spelled in
// allowed_bind_mounts. That is the fail-closed side, and an operator clears
// it with one allowlist entry.
var localVolumeAllowedRemoteTypes = map[string]bool{
	"nfs":   true,
	"nfs4":  true,
	"cifs":  true,
	"smb3":  true,
	"tmpfs": true,
}

// localVolumeHostPathOptions are the "o" keys whose value is a host path (or
// a colon-separated list of them) rather than a flag or a tunable. They are
// overlayfs's layer directories, which is the one filesystem in wide use that
// takes its sources in the mount data instead of in the mount source, so a
// check that reads only "device" sees nothing at all for
// `{"type":"overlay","o":"lowerdir=/,upperdir=/u,workdir=/w"}` while the
// kernel mounts the host's root.
//
// The "+" spellings are the kernel's append forms (data-only lower layers),
// listed because they reach the same parser and leaving them out would be a
// hole of exactly the shape this closes.
var localVolumeHostPathOptions = map[string]bool{
	"lowerdir":  true,
	"lowerdir+": true,
	"datadir+":  true,
	"upperdir":  true,
	"workdir":   true,
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
	// hostPaths are the paths named by an "o" key in
	// localVolumeHostPathOptions, each carrying the key it came from so the
	// denial can say which option reached the host.
	hostPaths []localVolumeHostPath
	bind      bool
}

// localVolumeHostPath is one path an "o" option names, with the option key
// that named it.
type localVolumeHostPath struct {
	option string
	path   string
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
				name, optionValue, hasValue := strings.Cut(option, "=")
				if !hasValue {
					continue
				}
				name = strings.ToLower(strings.TrimSpace(name))
				if name == "device" {
					if device := strings.TrimSpace(optionValue); device != "" {
						parsed.devices = append(parsed.devices, device)
					}
					continue
				}
				// overlayfs names its layer directories here rather than in
				// the mount source, so these reach the host exactly as
				// "device" does and are checked against the same allowlist
				// whatever the type says.
				if !localVolumeHostPathOptions[name] {
					continue
				}
				for _, dir := range splitOverlayDirList(optionValue) {
					if dir = strings.TrimSpace(dir); dir != "" {
						parsed.hostPaths = append(parsed.hostPaths, localVolumeHostPath{option: name, path: dir})
					}
				}
			}
		}
	}

	slices.Sort(parsed.devices)
	slices.SortFunc(parsed.hostPaths, func(a, b localVolumeHostPath) int {
		if c := strings.Compare(a.option, b.option); c != 0 {
			return c
		}
		return strings.Compare(a.path, b.path)
	})
	return parsed, true
}

// splitOverlayDirList splits an overlayfs directory list the way the kernel's
// own option parser does: on ":" only when it is unescaped, with "\" escaping
// the byte that follows it. A path carrying a literal colon is spelled "\:"
// and has to stay one path, because splitting it would compare two prefixes
// that are not the directory the kernel mounts.
//
// A trailing backslash escapes nothing, so it is kept as itself rather than
// dropped: the value that gets checked has to be the value the kernel sees.
func splitOverlayDirList(value string) []string {
	var (
		dirs    []string
		current strings.Builder
		escaped bool
	)
	for i := range len(value) {
		c := value[i]
		switch {
		case escaped:
			current.WriteByte(c)
			escaped = false
		case c == '\\':
			escaped = true
		case c == ':':
			dirs = append(dirs, current.String())
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	if escaped {
		current.WriteByte('\\')
	}
	return append(dirs, current.String())
}

// mountsHostFilesystem reports whether the options ask the kernel to mount
// something of the host's — its storage over a block device, or its kernel
// state through a pseudo-filesystem that ignores the device. That is every
// type localVolumeAllowedRemoteTypes does not name, and it is also the
// absent-type case: the local driver with a device and no type builds a mount
// request the daemon rejects, so denying it costs a working configuration
// nothing and keeps the gate from turning on a field the request can simply
// omit.
//
// A map carrying two spellings of the type key ("type" and "Type") is one
// request with two live entries whose precedence neither daemon promises, so
// a single non-allowlisted type among them is enough. That is the
// conservative direction: the request is denied unless every type it names is
// one this build can prove reaches no local path.
func (o localVolumeOptions) mountsHostFilesystem() bool {
	for _, fsType := range o.types {
		if !localVolumeAllowedRemoteTypes[fsType] {
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

// denyLocalVolumeBindDeviceReason checks every host path a local volume driver
// options map reaches against allowedBindMounts, using the same prefix rule
// (bindPathAllowed) a HostConfig.Binds entry or a Type: "bind" mount is
// checked against. The allowlist is a path allowlist only, so a read-only
// request is neither required nor consulted here, exactly as it is not for a
// "/host:/ctr:ro" bind.
//
// There are three ways in and they are checked in order, so a map that asks
// for more than one keeps the wording of the first.
//
// A bind ("type":"none"/"bind", or an "o" carrying bind/rbind) normalizes
// with normalizeBindMount, so "/srv/../etc" is compared as "/etc", and a
// device that is not an absolute path is denied rather than skipped — the one
// place this differs from the bind checks, which skip a source
// normalizeBindMount rejects because a relative source in Binds is a named
// volume and not a host path at all, whereas an options map that has already
// asked for a bind is naming a device the daemon resolves against its own
// working directory.
//
// A type outside localVolumeAllowedRemoteTypes is the second way: it is not a
// bind, so nothing above sees it, but it mounts the host's own storage
// (ext4/xfs/btrfs over a block node) or the host's own kernel state (proc,
// sysfs, cgroup, debugfs and the rest, which ignore the device entirely and
// mount it anyway), and both reach the data an allowlisted bind is there to
// bound. The device is compared as a path whatever it spells, so a bare
// "proc" is checked as "/proc" and denied unless the allowlist names it.
//
// An overlay-style "o" directory is the third, and it runs whatever the type
// says because "lowerdir=/" reaches the host's root under any type name that
// gets it past the second check. An operator who genuinely wants any of the
// three lists the path in the same allowed_bind_mounts. subject names the
// endpoint for the denial message so it matches the wording each inspector's
// other denials use.
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

	if parsed.mountsHostFilesystem() {
		for _, device := range parsed.devices {
			// normalizeLocalVolumeDevice only refuses an empty value, which
			// parseLocalVolumeOptions already drops. Reporting the raw
			// spelling in that case keeps the message honest rather than
			// quoting an empty path.
			source, ok := normalizeLocalVolumeDevice(device)
			if !ok {
				source = device
			}
			if !ok || !bindPathAllowed(source, allowedBindMounts) {
				return fmt.Sprintf("%s denied: local volume device %q is not allowlisted", subject, source)
			}
		}
	}

	for _, hostPath := range parsed.hostPaths {
		source, ok := normalizeLocalVolumeDevice(hostPath.path)
		if !ok {
			source = hostPath.path
		}
		if !ok || !bindPathAllowed(source, allowedBindMounts) {
			return fmt.Sprintf("%s denied: local volume %s path %q is not allowlisted", subject, hostPath.option, source)
		}
	}

	return ""
}
