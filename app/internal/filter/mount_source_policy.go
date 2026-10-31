package filter

import "fmt"

// Podman applies these options to the daemon's source, before mounting it.
// Named volumes use the same explicit grant, without trusting unseen volume
// metadata or doing daemon lookups. On an exact tmpfs type U sets uid/gid
// mount options instead of chowning a host source.
func denyMountSourceMutationReason(options []string, tmpfs, allow bool, subject string) string {
	if allow {
		return ""
	}
	for _, option := range options {
		if option == "z" || option == "Z" || (option == "U" && !tmpfs) {
			return fmt.Sprintf("%s denied: mount option %q mutates its source and requires allow_mount_source_mutation", subject, option)
		}
	}
	return ""
}
