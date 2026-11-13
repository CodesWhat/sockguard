package ownership

import (
	"strings"
	"testing"
)

// A bare name completes to library/<name> on dockerd and to
// docker.io/library/<name> on Podman's compat lookup, so the room left for it
// differs by engine. Past it the inspect would answer with an invalid
// reference error, which surfaced as a 502 instead of a refusal.
func TestImageDestinationForBoundsABareNameByTheEnginesCompletion(t *testing.T) {
	t.Parallel()
	name := func(n int) string { return strings.Repeat("a", n) }

	tests := []struct {
		name   string
		repo   string
		naming imageTagNaming
		want   imageDestinationProblem
	}{
		{"podman compat at the bound", name(imageTagPodmanBareRepoMaxLen), imageTagNamedEitherWay, imageDestinationReadable},
		{"podman compat 238 characters", name(238), imageTagNamedEitherWay, imageDestinationNameTooLong},
		{"podman compat 245 characters", name(245), imageTagNamedEitherWay, imageDestinationNameTooLong},
		{"podman compat past dockerd's bound", name(imageTagBareRepoMaxLen + 1), imageTagNamedEitherWay, imageDestinationBadName},
		{"podman compat with its tag carried", name(238) + ":v1", imageTagNamedEitherWay, imageDestinationNameTooLong},
		{"podman compat slash name is bounded by localhost/", "team/" + name(imageTagRepoMaxLen-len("localhost/team/")), imageTagNamedEitherWay, imageDestinationReadable},
		{"dockerd keeps the longer bound", name(imageTagBareRepoMaxLen), imageTagNamedAsSpelled, imageDestinationReadable},
		{"native route is bounded by localhost/", name(imageTagRepoMaxLen - len("localhost/")), imageTagNamedAsStored, imageDestinationReadable},
		{"native route one past localhost/", name(imageTagRepoMaxLen - len("localhost/") + 1), imageTagNamedAsStored, imageDestinationBadName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, got := imageDestinationFor(tt.repo, "", tt.naming); got != tt.want {
				t.Fatalf("problem = %v, want %v", got, tt.want)
			}
		})
	}

	reason := imageTagRoute.refusal(imageDestinationNameTooLong)
	if !strings.Contains(reason, "docker.io/library/<name>") {
		t.Fatalf("reason = %q", reason)
	}
}
