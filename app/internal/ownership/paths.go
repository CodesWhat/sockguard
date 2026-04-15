package ownership

import "strings"

func needsOwnerFilter(normPath string) bool {
	switch normPath {
	case "/events", "/containers/json", "/containers/prune", "/images/json", "/images/prune", "/networks", "/networks/prune", "/volumes", "/volumes/prune", "/services", "/tasks", "/secrets", "/configs", "/nodes":
		return true
	default:
		return false
	}
}

func containerIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/containers/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/containers/"), "/")
	switch identifier {
	case "", "create", "json", "prune":
		return "", false
	default:
		return identifier, true
	}
}

func execIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/exec/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/exec/"), "/")
	if identifier == "" {
		return "", false
	}
	return identifier, true
}

func networkIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/networks/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/networks/"), "/")
	switch identifier {
	case "", "create", "prune":
		return "", false
	default:
		return identifier, true
	}
}

func volumeIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/volumes/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/volumes/"), "/")
	switch identifier {
	case "", "create", "prune":
		return "", false
	default:
		return identifier, true
	}
}

func imageIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/images/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/images/")
	switch rest {
	case "", "json", "create", "search", "get", "load", "prune":
		return "", false
	}

	for _, suffix := range []string{"/json", "/history", "/push", "/tag"} {
		if strings.HasSuffix(rest, suffix) {
			return strings.TrimSuffix(rest, suffix), true
		}
	}
	return rest, true
}

func serviceIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/services/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/services/"), "/")
	switch identifier {
	case "", "create":
		return "", false
	default:
		return identifier, true
	}
}

func isServiceUpdatePath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/services/") {
		return false
	}
	identifier, tail, ok := strings.Cut(strings.TrimPrefix(normPath, "/services/"), "/")
	return ok && identifier != "" && identifier != "create" && tail == "update"
}

func taskIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/tasks/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/tasks/"), "/")
	if identifier == "" {
		return "", false
	}
	return identifier, true
}

func secretIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/secrets/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/secrets/"), "/")
	switch identifier {
	case "", "create":
		return "", false
	default:
		return identifier, true
	}
}

func configIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/configs/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/configs/"), "/")
	switch identifier {
	case "", "create":
		return "", false
	default:
		return identifier, true
	}
}

func nodeIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/nodes/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/nodes/"), "/")
	if identifier == "" {
		return "", false
	}
	return identifier, true
}

func isNodeUpdatePath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/nodes/") {
		return false
	}
	identifier, tail, ok := strings.Cut(strings.TrimPrefix(normPath, "/nodes/"), "/")
	return ok && identifier != "" && tail == "update"
}

func isSwarmPath(normPath string) bool {
	return normPath == "/swarm"
}

func isSwarmUpdatePath(normPath string) bool {
	return normPath == "/swarm/update"
}

func ownerFilterKey(normPath string) string {
	if normPath == "/nodes" {
		return "node.label"
	}
	return "label"
}
