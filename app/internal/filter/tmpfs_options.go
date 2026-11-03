package filter

import "strings"

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
}

// apply folds one option token into the posture. A token is "key" or
// "key=value". An enabling key (exec, dev, suid) is read case-insensitively,
// so an odd spelling can't hide one, and it enables unless its value is
// explicitly falsy: "suid=1", "suid=true" and a bare "suid=" all enable. A
// restricting key (noexec, nodev, nosuid) counts only in its exact lowercase
// spelling, because a spelling the daemon doesn't recognize restricts nothing,
// and "noexec=0" is read as enabling exec.
func (t *tmpfsPosture) apply(token string) {
	name, value, hasValue := strings.Cut(strings.TrimSpace(token), "=")
	name = strings.TrimSpace(name)
	falsy := hasValue && tmpfsValueIsFalsy(value)
	switch strings.ToLower(name) {
	case "exec":
		t.exec = tmpfsEnablingState(falsy)
	case "dev":
		t.dev = tmpfsEnablingState(falsy)
	case "suid":
		t.suid = tmpfsEnablingState(falsy)
	}
	switch name {
	case "noexec":
		t.exec = tmpfsRestrictingState(hasValue, falsy)
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
