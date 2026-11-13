package cmd

import (
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestServeChainLibpodTmpfsOptionsNeedTheirOption pins that a native
// POST /libpod/containers/create tmpfs mount answers to
// allow_tmpfs_privileged_options like the compat routes do. Before the gate
// the options of a mounts[] entry were decoded and never read.
func TestServeChainLibpodTmpfsOptionsNeedTheirOption(t *testing.T) {
	const create = "/v6.1.3/libpod/containers/create"
	libpod := func(mounts string) string {
		return `{"systemd":"false","image":"alpine","mounts":[` + mounts + `]}`
	}
	tmpfs := func(options string) string {
		return `{"type":"tmpfs","source":"tmpfs","destination":"/scratch","options":[` + options + `]}`
	}
	const denied = "tmpfs mount enables exec, dev, or suid"
	on := func(body *config.RequestBodyConfig) { body.LibpodContainerCreate.AllowTmpfsPrivilegedOptions = true }

	runTmpfsChainCases(t, []tmpfsChainCase{
		{name: "noexec tmpfs reaches the daemon", podman: true, path: create, body: libpod(tmpfs(`"noexec","nosuid","nodev"`)), wantReach: true},
		{name: "size-only tmpfs is not an escalation here", podman: true, path: create, body: libpod(tmpfs(`"size=64m"`)), wantReach: true, configure: on},
		{name: "exec is refused", podman: true, path: create, body: libpod(tmpfs(`"exec"`)), wantReason: denied},
		{name: "suid is refused", podman: true, path: create, body: libpod(tmpfs(`"suid"`)), wantReason: denied},
		{name: "dev is refused", podman: true, path: create, body: libpod(tmpfs(`"dev"`)), wantReason: denied},
		{name: "exec in one comma element is refused", podman: true, path: create, body: libpod(tmpfs(`"nosuid,exec"`)), wantReason: denied},
		{name: "exec after noexec is refused", podman: true, path: create, body: libpod(tmpfs(`"noexec","exec"`)), wantReason: denied},
		{name: "noexec after exec reaches the daemon (last wins)", podman: true, path: create, body: libpod(tmpfs(`"exec","noexec","nosuid","nodev"`)), wantReach: true},
		{name: "suid=1 token is refused", podman: true, path: create, body: libpod(tmpfs(`"suid=1"`)), wantReason: denied},
		{name: "tmpfs type in capitals is refused", podman: true, path: create, body: libpod(`{"type":"TMPFS","source":"tmpfs","destination":"/s","options":["exec"]}`), wantReason: denied},
		{name: "exec reaches the daemon with the option on", podman: true, path: create, body: libpod(tmpfs(`"exec","suid","dev"`)), configure: on, wantReach: true},
		{name: "the compat option does not open the native route", podman: true, path: create, body: libpod(tmpfs(`"exec"`)),
			configure: func(body *config.RequestBodyConfig) { body.ContainerCreate.AllowTmpfsPrivilegedOptions = true }, wantReason: denied},
	})
}
