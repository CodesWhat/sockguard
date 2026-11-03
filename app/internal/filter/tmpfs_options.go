package filter

import (
	"fmt"
	"path"
	"strings"
)

// tmpfs_options.go holds the one reading of tmpfs mount option text that every
// tmpfs gate shares: HostConfig.Tmpfs, HostConfig.Mounts[].TmpfsOptions, the
// libpod mounts[] array, swarm service tmpfs mounts and a local volume of
// type tmpfs. Each carries the same kernel flags, so each answers to
// allow_tmpfs_privileged_options and reads the text the same way.

// tmpfsFlagState is where one exec/dev/suid pair stands after reading an
// option list.
type tmpfsFlagState uint8

const (
	tmpfsFlagUnset tmpfsFlagState = iota
	tmpfsFlagEnabled
	tmpfsFlagRestricted
)

// tmpfsPosture is the effective exec, dev and suid state of a tmpfs option
// list. Each pair is last-wins, matching the order the runtime applies mount
// flags in.
type tmpfsPosture struct {
	exec, dev, suid tmpfsFlagState
	// execBare is set when the last token to touch exec was the bare
	// "noexec", the spelling Podman's own tmpfs parsing recognizes.
	execBare bool
}

// apply folds one option token into the posture. A token is "key" or
// "key=value", matched exactly: the runtimes look a flag up by its lowercase
// name, so "EXEC" and " dev" are options they reject and not ones they apply.
// An enabling key (exec, dev, suid) enables unless its value is explicitly
// falsy, so "suid=1", "suid=true" and a bare "suid=" all enable. A
// restricting key (noexec, nodev, nosuid) restricts, except that "noexec=0"
// is read as enabling exec.
func (t *tmpfsPosture) apply(token string) {
	name, value, hasValue := strings.Cut(token, "=")
	falsy := hasValue && tmpfsValueIsFalsy(value)
	switch name {
	case "exec":
		t.exec = tmpfsEnablingState(falsy)
		t.execBare = false
	case "dev":
		t.dev = tmpfsEnablingState(falsy)
	case "suid":
		t.suid = tmpfsEnablingState(falsy)
	case "noexec":
		t.exec = tmpfsRestrictingState(hasValue, falsy)
		t.execBare = !hasValue
	case "nodev":
		t.dev = tmpfsRestrictingState(hasValue, falsy)
	case "nosuid":
		t.suid = tmpfsRestrictingState(hasValue, falsy)
	}
}

func tmpfsEnablingState(falsy bool) tmpfsFlagState {
	if falsy {
		return tmpfsFlagRestricted
	}
	return tmpfsFlagEnabled
}

func tmpfsRestrictingState(hasValue, falsy bool) tmpfsFlagState {
	if hasValue && falsy {
		return tmpfsFlagEnabled
	}
	return tmpfsFlagRestricted
}

func tmpfsValueIsFalsy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "false", "no", "off":
		return true
	}
	return false
}

// enablesPrivilege reports whether the list ends with exec, dev or suid on.
func (t tmpfsPosture) enablesPrivilege() bool {
	return t.exec == tmpfsFlagEnabled || t.dev == tmpfsFlagEnabled || t.suid == tmpfsFlagEnabled
}

// tmpfsPostureOfList reads comma-separated option lists (one string or
// several) into one posture.
func tmpfsPostureOfList(lists ...string) tmpfsPosture {
	var posture tmpfsPosture
	for _, list := range lists {
		for token := range strings.SplitSeq(list, ",") {
			posture.apply(token)
		}
	}
	return posture
}

// tmpfsStructuredVerdict is what reading a structured TmpfsOptions.Options
// list found.
type tmpfsStructuredVerdict uint8

const (
	tmpfsStructuredOK tmpfsStructuredVerdict = iota
	tmpfsStructuredMalformed
	tmpfsStructuredPrivileged
)

// tmpfsPrivilegeEscalatingOptions are the tmpfs mount option keywords that
// override Docker's default noexec/nodev/nosuid tmpfs posture. Matched
// case-insensitively against the first token of each
// TmpfsOptions.Options entry.
var tmpfsPrivilegeEscalatingOptions = map[string]bool{
	"exec": true,
	"dev":  true,
	"suid": true,
}

// checkStructuredTmpfsOptions reads a Mount.TmpfsOptions.Options list (Engine
// API 1.46+, and the swarm ContainerSpec mount): each entry must be a
// well-formed 1-or-2-element list (a malformed one is refused fail-closed
// rather than ignored), and an entry that names exec, dev or suid as its key,
// or whose comma-joined text ends with one on, is privileged. Entries are
// judged one at a time, so a later "noexec" entry doesn't clear an earlier
// "exec". The returned string is the entry's first element, for the denial.
func checkStructuredTmpfsOptions(options [][]string) (tmpfsStructuredVerdict, string) {
	for _, option := range options {
		if len(option) == 0 || len(option) > 2 || strings.TrimSpace(option[0]) == "" {
			return tmpfsStructuredMalformed, ""
		}
		key := strings.ToLower(strings.TrimSpace(option[0]))
		if tmpfsPrivilegeEscalatingOptions[key] || tmpfsPostureOfList(strings.Join(option, "=")).enablesPrivilege() {
			return tmpfsStructuredPrivileged, option[0]
		}
	}
	return tmpfsStructuredOK, ""
}

// fullyRestricted reports whether the list explicitly ends with noexec, nodev
// and nosuid all set. Podman mounts a tmpfs executable, and gives /dev no
// default options at all, so on a Podman upstream only an explicit list is
// safe.
func (t tmpfsPosture) fullyRestricted() bool {
	return t.exec == tmpfsFlagRestricted && t.dev == tmpfsFlagRestricted && t.suid == tmpfsFlagRestricted
}

// podmanSafe reports whether a tmpfs at dest is safe on a Podman upstream.
// Podman mounts a tmpfs executable, so the bare token noexec is required (a
// "noexec=1" or "exec=0" spelling is not what its parser looks for). It adds
// nosuid and nodev itself everywhere but /dev, which gets no default options,
// so only /dev has to spell those out.
func (t tmpfsPosture) podmanSafe(dest string) bool {
	if t.exec != tmpfsFlagRestricted || !t.execBare {
		return false
	}
	if path.Clean("/"+dest) == "/dev" {
		return t.dev == tmpfsFlagRestricted && t.suid == tmpfsFlagRestricted
	}
	return true
}

// tmpfsPodmanRefusal names what a Podman tmpfs at dest has to add, and the
// key that opts out.
func tmpfsPodmanRefusal(dest, optOutKey string) string {
	fix := "noexec"
	if path.Clean("/"+dest) == "/dev" {
		fix = "noexec,nosuid,nodev"
	}
	return fmt.Sprintf("a tmpfs on a Podman upstream must set %s: use --tmpfs %s:%s or set %s", fix, dest, fix, optOutKey)
}
