package filter

// GetBaseHostFile in go.podman.io/common v0.67.1 and v0.69.2 recognizes
// exactly these selectors. Every other value names a file the daemon opens
// to populate the container's /etc/hosts, including a relative or padded value.
func isLibpodHostsFileSelector(value string) bool {
	switch value {
	case "", "image", "none":
		return true
	default:
		return false
	}
}
