package filter

import (
	"fmt"
	"strings"
)

// overlay_mount_options.go gates the host paths a Podman overlay mount takes
// from somewhere other than a source field. Podman builds one overlay option
// string per mount, "lowerdir=<source>,upperdir=<dir>,workdir=<dir>,private",
// and two things reach it that an allowlist check of the source alone never
// reads.
//
// The first is the upper and work directory. Podman 5.8.6 lifts them out of the
// mount's own option list (getOverlayUpperAndWorkDir,
// libpod/container_internal_common.go:153-180): any option that starts with
// "upperdir" or "workdir" counts, so "upperdirX=/etc" does too, and the value
// is whatever follows the first "=". buildah 1.43.2 then uses the value as
// written when it's absolute and joins it under the container's own overlay
// directory when it isn't, so "../" walks back out, and it chmods and chowns
// the upper directory to match the source before mounting
// (pkg/overlay/overlay_linux.go:44-67). The option list comes from three
// places: a native create's overlay_volumes[].options
// (container_internal_common.go:466-481), a native create's volumes[].Options
// once one of them is "O" (container_internal_common.go:320-351), and the
// option field of a Docker-compatible HostConfig.Binds entry, which Podman
// parses as a "-v" argument (pkg/api/handlers/compat/containers_create.go:516-517,
// pkg/specgen/volumes.go:89-231). Podman 6.1.3 reads the options the same way.
//
// The second is the option string itself. buildah escapes ":" in the source
// and nothing else, and it writes the upper and work directory in unescaped,
// so a "," in any of the three starts a new overlay option, and a second
// "lowerdir=" replaces the first. A "\" is the overlay escape character: the
// kernel strips it from an upper or work directory before resolving the path
// (ovl_unescape in fs/overlayfs/params.c), so "/srv/roots/..\/etc" cleans to a
// path under /srv/roots here and resolves to /etc there, and in a source it
// turns the "\:" buildah wrote into an escaped backslash followed by a real
// layer separator.
//
// So every upper and work directory is held to the same allowed_bind_mounts
// list the source is, and a path bound for an overlay option string is refused
// when it carries a "," or a "\". dockerd refuses the "O", "upperdir" and
// "workdir" bind options itself (linuxValidMountMode in
// volume/mounts/linux_parser.go), so on a Docker upstream none of this changes
// which creates work.

// overlayOptionMetacharacters are the characters an overlay option string gives
// a meaning that a path doesn't have: "," ends an option and "\" escapes the
// character after it.
const overlayOptionMetacharacters = `,\`

// hasOverlayOptionMetacharacter reports whether path would change the overlay
// option string it's written into. It has to see the path as the client sent
// it, because Podman writes that spelling and not a cleaned one:
// "/srv/a,lowerdir=/etc/../d" cleans to a path with no comma in it.
func hasOverlayOptionMetacharacter(path string) bool {
	return strings.ContainsAny(path, overlayOptionMetacharacters)
}

// isOverlayDirOption reports whether Podman reads option as an overlay upper or
// work directory. The match is Podman's own: a case-sensitive prefix test with
// no trimming.
func isOverlayDirOption(option string) bool {
	return strings.HasPrefix(option, "upperdir") || strings.HasPrefix(option, "workdir")
}

// denyOverlayDirOptionReason holds one mount option to allowedBindMounts when
// Podman would read it as an overlay upper or work directory, and returns ""
// for every other option. The directory has to be an absolute path with no
// overlay metacharacter in it that is an allowlist entry or sits under one. An
// option that names no directory, or a relative one, is refused whatever the
// allowlist holds: Podman rejects an empty value and ignores a missing one,
// and a relative value resolves against a directory this proxy can't see.
// subject names the endpoint for the denial message.
func denyOverlayDirOptionReason(option string, allowedBindMounts []string, subject string) string {
	if !isOverlayDirOption(option) {
		return ""
	}
	_, dir, _ := strings.Cut(option, "=")
	normalized, ok := normalizeBindMount(dir)
	switch {
	case !ok:
		return fmt.Sprintf("%s denied: overlay option %q does not name an absolute path", subject, option)
	case hasOverlayOptionMetacharacter(dir):
		return fmt.Sprintf("%s denied: overlay option %q contains a comma or backslash", subject, option)
	case !bindPathAllowed(normalized, allowedBindMounts):
		return fmt.Sprintf("%s denied: overlay option %q is not allowlisted (add its directory to allowed_bind_mounts)", subject, option)
	}
	return ""
}

// denyOverlayDirOptionsReason runs denyOverlayDirOptionReason over a mount's
// option list and returns the first denial. Every option is checked rather than
// the last one Podman would keep, so a list can't hide a directory behind a
// later, allowlisted one.
func denyOverlayDirOptionsReason(options []string, allowedBindMounts []string, subject string) string {
	for _, option := range options {
		if denyReason := denyOverlayDirOptionReason(option, allowedBindMounts, subject); denyReason != "" {
			return denyReason
		}
	}
	return ""
}

// denyBindOverlayReason gates the overlay parts of one HostConfig.Binds entry.
// Podman splits the entry on ":" into source, destination and options and the
// options on "," (SplitVolumeString and GenVolumeMounts in
// pkg/specgen/volumes.go). Everything after the second ":" is read as options
// here and split on both, so an entry Podman would re-split for a Windows
// drive letter still has every option looked at. Each upper and work directory
// is held to allowedBindMounts, for a named volume as much as for a host path:
// "myvol:/d:O,upperdir=/etc,workdir=/mnt" overlays the volume with its
// writable layer in /etc. A host-path source mounted with "O" becomes the
// overlay's lowerdir, so a source mounted that way is refused when it carries
// an overlay metacharacter. A volume name can't hold one, so the test isn't
// narrowed to sources that look like paths. The source's own allowlist check
// stays with the caller.
func denyBindOverlayReason(bind string, allowedBindMounts []string, subject string) string {
	source, rest, ok := strings.Cut(bind, ":")
	if !ok {
		return ""
	}
	_, options, ok := strings.Cut(rest, ":")
	if !ok {
		return ""
	}
	overlay := false
	for options != "" {
		option := options
		if end := strings.IndexAny(options, ":,"); end >= 0 {
			option, options = options[:end], options[end+1:]
		} else {
			options = ""
		}
		if option == "O" {
			overlay = true
		}
		if denyReason := denyOverlayDirOptionReason(option, allowedBindMounts, subject); denyReason != "" {
			return denyReason
		}
	}
	if overlay && hasOverlayOptionMetacharacter(source) {
		return fmt.Sprintf("%s denied: overlay bind source %q contains a comma or backslash", subject, source)
	}
	return ""
}
