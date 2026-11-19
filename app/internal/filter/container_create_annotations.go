package filter

import (
	"fmt"
	"slices"
	"strings"
)

// runtimeAnnotationPrefix is the annotation namespace that changes what the
// container runs with: crun reads its behavior switches from run.oci.*
// (keep_original_groups, handler, seccomp_bpf_data and the like). Any other
// key is plain metadata and passes.
const runtimeAnnotationPrefix = "run.oci."

// podmanActedAnnotations are the io.podman.annotations.* keys Podman acts on
// instead of only reading back. cid-file names a host path Podman removes
// with os.Remove when the container is removed, and autoremove and
// autoremove-image make Podman remove the container, and its image, when it
// exits. They are refused with the run.oci. keys; the rest of
// io.podman.annotations.* passes.
var podmanActedAnnotations = [...]string{
	"io.podman.annotations.cid-file",
	"io.podman.annotations.autoremove",
	"io.podman.annotations.autoremove-image",
}

// runtimeAnnotationsDenyReason refuses an annotation key under
// runtimeAnnotationPrefix, or one of podmanActedAnnotations, unless allow is
// set. Keys are matched in any letter case, so a spelling the runtime would
// not act on is refused too, and checked in sorted order so the reason is
// stable.
func runtimeAnnotationsDenyReason(annotations map[string]string, allow bool, subject string) string {
	if allow || len(annotations) == 0 {
		return ""
	}
	keys := make([]string, 0, len(annotations))
	for key := range annotations {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		folded := strings.ToLower(strings.TrimSpace(key))
		if strings.HasPrefix(folded, runtimeAnnotationPrefix) || slices.Contains(podmanActedAnnotations[:], folded) {
			return fmt.Sprintf("%s denied: runtime annotation %q is not allowed (set allow_runtime_annotations: true)", subject, key)
		}
	}
	return ""
}
