package cmd

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
)

// warnLabelACLOnce must fire only when container-label ACLs are enabled, and
// only once per Once even though the handler chain (and therefore the call
// site) is rebuilt on every config hot-reload.
func TestWarnLabelACLOnce(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var once sync.Once

	disabled := config.Defaults()
	warnLabelACLOnce(&disabled, logger, &once)
	if buf.Len() != 0 {
		t.Fatalf("disabled config logged: %q", buf.String())
	}

	enabled := config.Defaults()
	enabled.Clients.ContainerLabels.Enabled = true
	warnLabelACLOnce(&enabled, logger, &once)
	if got := strings.Count(buf.String(), "container-label ACLs are enabled"); got != 1 {
		t.Fatalf("warning count after first enabled build = %d, want 1; log: %q", got, buf.String())
	}

	// Simulate the chain rebuild a hot-reload performs: same process, same
	// Once, enabled again — must NOT log a second time.
	warnLabelACLOnce(&enabled, logger, &once)
	if got := strings.Count(buf.String(), "container-label ACLs are enabled"); got != 1 {
		t.Fatalf("warning count after reload rebuild = %d, want still 1; log: %q", got, buf.String())
	}

	// A fresh Once (fresh process) with the feature enabled warns again.
	var fresh sync.Once
	buf.Reset()
	warnLabelACLOnce(&enabled, logger, &fresh)
	if got := strings.Count(buf.String(), "container-label ACLs are enabled"); got != 1 {
		t.Fatalf("warning count with fresh Once = %d, want 1; log: %q", got, buf.String())
	}
}
