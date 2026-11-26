package filter

import (
	"fmt"
	"path"
	"strings"
)

// mutation_bind.go implements the remap_bind_source admission mutation for
// Docker-out-of-Docker runners. A runner container sees its workspace at one
// path (say /builds) while the daemon's host knows the same directory at
// another (say /srv/runner/builds), and every bind the runner asks for names
// the path the runner sees. The rule rewrites a matching source to the host
// path before the container-create inspector runs, so the rewritten source is
// checked against allowed_bind_mounts exactly like a client-authored one: the
// rewrite can only make a request mean something different, never exempt it
// from the allowlist.
//
// It is lexical only. It cleans paths and compares path components; it never
// touches a filesystem, so it cannot see a symlink under the mapped tree. The
// host directory a rule maps to must not contain links that point outside it.

// BindSourceRemapMutationOptions rewrites a bind-mount source prefix.
type BindSourceRemapMutationOptions struct {
	From string
	To   string
}

// remapBindSourcePath returns the rewritten source and whether the rule
// matched. A source that is not absolute (a named volume, an anonymous
// volume, a relative path) is never rewritten and is left for the downstream
// inspector to judge. A source that matches but carries a ".." component, or a
// control character, is refused rather than rewritten: "/builds/../../etc"
// would otherwise step out of the mapped tree after the prefix swap.
//
// Matching is on path-component boundaries, so from "/builds" matches
// "/builds" and "/builds/x" but never "/builds2". The match is tried on both
// the raw and the cleaned source, so a spelling that only matches after
// cleaning ("/x/../builds") and one that only matches before ("/builds/../x")
// both reach the traversal refusal instead of slipping past it.
func remapBindSourcePath(source, from, to string) (string, bool, error) {
	if !strings.HasPrefix(source, "/") {
		return source, false, nil
	}
	cleaned := path.Clean(source)
	if !bindPathHasPrefix(source, from) && !bindPathHasPrefix(cleaned, from) {
		return source, false, nil
	}
	if hasDotDotSegment(source) {
		return "", false, fmt.Errorf("bind source %q contains a '..' component", source)
	}
	for _, r := range source {
		if r < 0x20 || r == 0x7f {
			return "", false, fmt.Errorf("bind source contains a control character")
		}
	}
	if !bindPathHasPrefix(cleaned, from) {
		return source, false, nil
	}
	return to + strings.TrimPrefix(cleaned, from), true, nil
}

func bindPathHasPrefix(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

func hasDotDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// remapBindSpec rewrites the source of one HostConfig.Binds entry
// ("source:target[:options]"). An entry with no ":" is an anonymous volume and
// is left alone. Only the source is replaced; target and options are
// preserved byte for byte.
func remapBindSpec(spec, from, to string) (string, bool, error) {
	source, rest, ok := strings.Cut(spec, ":")
	if !ok {
		return spec, false, nil
	}
	next, matched, err := remapBindSourcePath(source, from, to)
	if err != nil || !matched {
		return spec, false, err
	}
	return next + ":" + rest, true, nil
}

// applyRemapBindSource applies one remap_bind_source rule to a container
// create body. container_create rewrites HostConfig.Binds entries and
// HostConfig.Mounts entries of Type "bind"; libpod_container_create rewrites
// the top-level "mounts" entries Podman treats as host binds. Volume
// (named-volume) driver options, libpod overlay_volumes and rootfs are not
// rewritten, so a request naming a host path there is checked against
// allowed_bind_mounts unchanged.
func applyRemapBindSource(doc map[string]any, surface string, rule compiledMutationRule) (string, error) {
	var (
		changed bool
		err     error
	)
	switch surface {
	case mutationSurfaceContainerCreate:
		hostConfig, ok := navigateFoldedObjectPath(doc, "HostConfig")
		if !ok {
			return mutationOutcomeNoop, nil
		}
		changed, err = remapDockerBinds(hostConfig, rule)
	case mutationSurfaceLibpodContainerCreate:
		changed, err = remapMountEntries(doc, "mounts", rule, libpodMountIsBind)
	default:
		return mutationOutcomeNoop, nil
	}
	if err != nil {
		return "", err
	}
	if changed {
		return mutationOutcomeApplied, nil
	}
	return mutationOutcomeNoop, nil
}

func remapDockerBinds(hostConfig map[string]any, rule compiledMutationRule) (bool, error) {
	changed := false
	for key, value := range hostConfig {
		if !strings.EqualFold(key, "Binds") || value == nil {
			continue
		}
		binds, ok := value.([]any)
		if !ok {
			return false, fmt.Errorf("HostConfig.Binds must be an array")
		}
		for i, entry := range binds {
			spec, ok := entry.(string)
			if !ok {
				return false, fmt.Errorf("HostConfig.Binds entry must be a string")
			}
			next, matched, err := remapBindSpec(spec, rule.bindFrom, rule.bindTo)
			if err != nil {
				return false, err
			}
			if matched && next != spec {
				binds[i] = next
				changed = true
			}
		}
	}
	mountsChanged, err := remapMountEntries(hostConfig, "Mounts", rule, dockerMountIsBind)
	return changed || mountsChanged, err
}

func dockerMountIsBind(mount map[string]any) bool {
	typ, present, isString := foldedStringLeaf(mount, "Type")
	return present && isString && strings.EqualFold(typ, "bind")
}

// libpodMountIsBind mirrors libpodContainerCreatePolicy.denyBindMountReason:
// an entry is a host bind when its type is bind or its options carry bind or
// rbind, whatever the type says.
func libpodMountIsBind(mount map[string]any) bool {
	if typ, present, isString := foldedStringLeaf(mount, "type"); present && isString && strings.EqualFold(typ, "bind") {
		return true
	}
	for key, value := range mount {
		if !strings.EqualFold(key, "options") {
			continue
		}
		options, _ := value.([]any)
		for _, option := range options {
			if s, ok := option.(string); ok && (s == "bind" || s == "rbind") {
				return true
			}
		}
	}
	return false
}

func remapMountEntries(parent map[string]any, field string, rule compiledMutationRule, isBind func(map[string]any) bool) (bool, error) {
	changed := false
	for key, value := range parent {
		if !strings.EqualFold(key, field) || value == nil {
			continue
		}
		mounts, ok := value.([]any)
		if !ok {
			return false, fmt.Errorf("%s must be an array", field)
		}
		for _, entry := range mounts {
			mount, ok := entry.(map[string]any)
			if !ok {
				return false, fmt.Errorf("%s entry must be an object", field)
			}
			if !isBind(mount) {
				continue
			}
			source, present, isString := foldedStringLeaf(mount, "Source")
			if !present {
				continue
			}
			if !isString {
				return false, fmt.Errorf("%s source must be a string", field)
			}
			next, matched, err := remapBindSourcePath(source, rule.bindFrom, rule.bindTo)
			if err != nil {
				return false, err
			}
			if matched && next != source {
				setFoldedStringLeafKeepingCase(mount, "Source", next)
				changed = true
			}
		}
	}
	return changed, nil
}

// setFoldedStringLeafKeepingCase sets the sole case-variant of name in m to
// newValue under the key spelling already present, so a libpod "source" stays
// "source" and a Docker "Source" stays "Source".
func setFoldedStringLeafKeepingCase(m map[string]any, name, newValue string) {
	for k := range m {
		if strings.EqualFold(k, name) {
			m[k] = newValue
			return
		}
	}
	m[name] = newValue
}
