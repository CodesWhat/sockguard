package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	got := String()

	if !strings.Contains(got, "sockguard "+Version) {
		t.Fatalf("version string = %q, want version %q", got, Version)
	}
	if !strings.Contains(got, "commit: "+Commit) {
		t.Fatalf("version string = %q, want commit %q", got, Commit)
	}
	if !strings.Contains(got, "built: "+BuildDate) {
		t.Fatalf("version string = %q, want build date %q", got, BuildDate)
	}
	if !strings.Contains(got, "go: "+runtime.Version()) {
		t.Fatalf("version string = %q, want runtime %q", got, runtime.Version())
	}
}
