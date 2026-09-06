package filter

import (
	"fmt"
	"slices"
	"strings"
)

// local_volume_bind.go holds the one policy that decides whether a local
// volume driver options map is really a bind mount wearing a volume's name.
//
// Docker's and Podman's built-in "local" driver forwards its type/o/device
// options straight to mount(2), so `{"type":"none","o":"bind","device":"/"}`
// bind-mounts an arbitrary host path into the container. That reaches the
// filesystem a HostConfig.Binds entry or a Type: "bind" mount would reach,
// but it arrives as a volume — through Mount.VolumeOptions.DriverConfig on
// POST /containers/create, or through DriverOpts on POST /volumes/create for
// a volume that is then mounted by name later — so none of the bind-mount
// allowlist checks used to see it. Every caller here runs the device through
// normalizeBindMount and bindPathAllowed, the same two helpers the bind
// checks use, so there is a single allowlist and a single denial shape.

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

// localVolumeBindDevices reports the host paths a local volume driver options
// map would bind-mount, sorted so a map carrying more than one spelling of
// the device key denies on a stable path. It returns nil when the driver is
// not the local one, when the options request no bind, or when they name no
// device — a non-bind local volume (tmpfs, nfs, cifs, a quota-only size opt)
// and a third-party driver's options are both left entirely alone.
//
// Option keys are matched case-insensitively because the two daemons do not
// agree on whether they lowercase them before dispatch, and a key spelled in
// a case this check missed would be a hole rather than a rejected request.
func localVolumeBindDevices(driver string, options map[string]string) []string {
	if len(options) == 0 {
		return nil
	}
	if name := strings.TrimSpace(driver); name != "" && !strings.EqualFold(name, localVolumeDriverName) {
		return nil
	}

	var devices []string
	bind := false
	for key, value := range options {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "device":
			if device := strings.TrimSpace(value); device != "" {
				devices = append(devices, device)
			}
		case "type":
			if localVolumeBindFilesystemTypes[strings.ToLower(strings.TrimSpace(value))] {
				bind = true
			}
		case "o":
			for _, option := range strings.Split(value, ",") {
				if localVolumeBindMountOptions[strings.ToLower(strings.TrimSpace(option))] {
					bind = true
				}
			}
		}
	}

	if !bind {
		return nil
	}
	slices.Sort(devices)
	return devices
}

// denyLocalVolumeBindDeviceReason checks every host path a local volume driver
// options map would bind-mount against allowedBindMounts, using the same
// normalization (normalizeBindMount, so "/srv/../etc" is compared as "/etc")
// and the same prefix rule (bindPathAllowed) a HostConfig.Binds entry or a
// Type: "bind" mount is checked against. The allowlist is a path allowlist
// only, so a read-only request is neither required nor consulted here, exactly
// as it is not for a "/host:/ctr:ro" bind.
//
// A device that is not an absolute path is denied rather than skipped, which
// is the one place this differs from the bind checks: those skip a source
// normalizeBindMount rejects because a relative source in Binds is a named
// volume and not a host path at all, whereas an options map that has already
// asked for a bind is naming a device the daemon resolves against its own
// working directory. subject names the endpoint for the denial message so it
// matches the wording each inspector's other denials use.
func denyLocalVolumeBindDeviceReason(driver string, options map[string]string, allowedBindMounts []string, subject string) string {
	for _, device := range localVolumeBindDevices(driver, options) {
		source, ok := normalizeBindMount(device)
		if !ok {
			return fmt.Sprintf("%s denied: bind mount source %q is not allowlisted", subject, device)
		}
		if !bindPathAllowed(source, allowedBindMounts) {
			return fmt.Sprintf("%s denied: bind mount source %q is not allowlisted", subject, source)
		}
	}
	return ""
}
