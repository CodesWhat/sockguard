package cmd

import (
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestServeChainPodmanTmpfsMustBeRestricted pins the Podman half of
// allow_tmpfs_privileged_options. dockerd mounts a tmpfs noexec,nosuid,nodev
// unless asked otherwise, so refusing exec, dev and suid is the whole job
// there. Podman mounts one nosuid,nodev but executable, and a /dev tmpfs gets
// no default options at all, so with the option off a Podman tmpfs has to say
// noexec, nosuid and nodev itself. Read from Podman 5.8.6 and 6.1.3 source:
// getTmpfsMounts splits "path[:options]", and the --mount parser appends the
// defaults only for flags it was not given.
func TestServeChainPodmanTmpfsMustBeRestricted(t *testing.T) {
	const (
		compat = "/v1.41/containers/create"
		libpod = "/v6.1.3/libpod/containers/create"
	)
	legacy := func(tmpfs string) string { return `{"Image":"alpine","HostConfig":{"Tmpfs":` + tmpfs + `}}` }
	mounts := func(mount string) string { return `{"Image":"alpine","HostConfig":{"Mounts":[` + mount + `]}}` }
	native := func(mount string) string { return `{"systemd":"false","image":"alpine","mounts":[` + mount + `]}` }
	const (
		safe          = "noexec,nosuid,nodev"
		podmanOn      = "must set noexec"
		mountsIgnored = "ignores TmpfsOptions.Options"
		denied        = "enables exec, dev, or suid"
	)
	on := func(body *config.RequestBodyConfig) {
		body.ContainerCreate.AllowTmpfsPrivilegedOptions = true
		body.LibpodContainerCreate.AllowTmpfsPrivilegedOptions = true
	}

	runTmpfsChainCases(t, []tmpfsChainCase{
		// Podman, compat HostConfig.Tmpfs.
		{name: "podman legacy tmpfs with no options is refused", podman: true, path: compat, body: legacy(`{"/scratch":""}`), wantReason: podmanOn},
		{name: "podman legacy /dev tmpfs with no options is refused", podman: true, path: compat, body: legacy(`{"/dev":""}`), wantReason: podmanOn},
		{name: "podman legacy tmpfs with only noexec reaches the daemon", podman: true, path: compat, body: legacy(`{"/scratch":"noexec"}`), wantReach: true},
		{name: "podman legacy tmpfs with exec=0 is refused", podman: true, path: compat, body: legacy(`{"/scratch":"exec=0"}`), wantReason: podmanOn},
		{name: "podman legacy tmpfs with noexec=1 is refused", podman: true, path: compat, body: legacy(`{"/scratch":"noexec=1"}`), wantReason: podmanOn},
		{name: "podman legacy tmpfs with nosuid,nodev only is refused", podman: true, path: compat, body: legacy(`{"/scratch":"nosuid,nodev"}`), wantReason: podmanOn},
		{name: "podman legacy /dev tmpfs with only noexec is refused", podman: true, path: compat, body: legacy(`{"/dev":"noexec"}`), wantReason: "must set noexec,nosuid,nodev"},
		{name: "podman legacy tmpfs with noexec and a size reaches the daemon", podman: true, path: compat, body: legacy(`{"/scratch":"noexec,size=64m"}`), wantReach: true},
		{name: "podman legacy tmpfs with all three reaches the daemon", podman: true, path: compat, body: legacy(`{"/scratch":"rw,` + safe + `,size=64m"}`), wantReach: true},
		{name: "podman legacy /dev tmpfs with nodev,nosuid,noexec reaches the daemon", podman: true, path: compat, body: legacy(`{"/dev":"` + safe + `"}`), wantReach: true},
		{name: "podman legacy options in the key reach the daemon", podman: true, path: compat, body: legacy(`{"/scratch:` + safe + `":""}`), wantReach: true},
		{name: "podman legacy key options are the ones read", podman: true, path: compat, body: legacy(`{"/scratch:nosuid":"noexec"}`), wantReason: podmanOn},
		{name: "podman legacy suid=1 after all three is refused", podman: true, path: compat, body: legacy(`{"/scratch":"` + safe + `,suid=1"}`), wantReason: "legacy tmpfs mount enables exec, dev, or suid"},
		{name: "podman legacy dev=1 is refused", podman: true, path: compat, body: legacy(`{"/scratch":"` + safe + `,dev=1"}`), wantReason: "legacy tmpfs mount enables exec, dev, or suid"},
		{name: "podman legacy tmpfs with no options reaches the daemon with the option on", podman: true, path: compat, body: legacy(`{"/scratch":""}`), configure: on, wantReach: true},

		// Podman, compat HostConfig.Mounts.
		{name: "podman Mounts tmpfs with no TmpfsOptions is refused", podman: true, path: compat, body: mounts(`{"Type":"tmpfs","Target":"/scratch"}`), wantReason: mountsIgnored},
		{name: "podman Mounts tmpfs with a size only is refused", podman: true, path: compat, body: mounts(`{"Type":"tmpfs","Target":"/scratch","TmpfsOptions":{"SizeBytes":1048576}}`), wantReason: mountsIgnored},
		{name: "podman Mounts tmpfs listing noexec is still refused, Podman drops the list", podman: true, path: compat, body: mounts(`{"Type":"tmpfs","Target":"/scratch","TmpfsOptions":{"Options":[["noexec"],["nosuid"],["nodev"]]}}`), wantReason: mountsIgnored},
		{name: "podman Mounts tmpfs with a trailing exec is refused", podman: true, path: compat, body: mounts(`{"Type":"tmpfs","Target":"/scratch","TmpfsOptions":{"Options":[["` + safe + `"],["exec"]]}}`), wantReason: "tmpfs mount option"},
		{name: "podman Mounts tmpfs with suid=1 is refused", podman: true, path: compat, body: mounts(`{"Type":"tmpfs","Target":"/scratch","TmpfsOptions":{"Options":[["` + safe + `"],["suid","1"]]}}`), wantReason: "tmpfs mount option"},
		{name: "podman Mounts tmpfs with no options reaches the daemon with the option on", podman: true, path: compat, body: mounts(`{"Type":"tmpfs","Target":"/scratch"}`), configure: on, wantReach: true},
		{name: "podman Mounts volume is untouched", podman: true, path: compat, body: mounts(`{"Type":"volume","Source":"data","Target":"/d"}`), wantReach: true},

		// A Docker upstream already defaults to noexec,nosuid,nodev, so a bare tmpfs is fine.
		{name: "docker legacy tmpfs with no options reaches the daemon", path: compat, body: legacy(`{"/scratch":""}`), wantReach: true},
		{name: "docker Mounts tmpfs with no options reaches the daemon", path: compat, body: mounts(`{"Type":"tmpfs","Target":"/scratch"}`), wantReach: true},
		{name: "docker legacy suid=1 is refused", path: compat, body: legacy(`{"/scratch":"suid=1"}`), wantReason: "legacy tmpfs mount enables exec, dev, or suid"},
		{name: "docker legacy dev=true is refused", path: compat, body: legacy(`{"/scratch":"nodev,dev=true"}`), wantReason: "legacy tmpfs mount enables exec, dev, or suid"},
		{name: "docker legacy exec=0 reaches the daemon", path: compat, body: legacy(`{"/scratch":"exec=0"}`), wantReach: true},

		// Podman, native mounts[].
		{name: "podman native tmpfs with no options is refused", podman: true, path: libpod, body: native(`{"type":"tmpfs","source":"tmpfs","destination":"/scratch"}`), wantReason: podmanOn},
		{name: "podman native /dev tmpfs with no options is refused", podman: true, path: libpod, body: native(`{"type":"tmpfs","source":"tmpfs","destination":"/dev"}`), wantReason: podmanOn},
		{name: "podman native tmpfs with only noexec reaches the daemon", podman: true, path: libpod, body: native(`{"type":"tmpfs","source":"tmpfs","destination":"/s","options":["noexec"]}`), wantReach: true},
		{name: "podman native tmpfs with exec=0 is refused", podman: true, path: libpod, body: native(`{"type":"tmpfs","source":"tmpfs","destination":"/s","options":["exec=0"]}`), wantReason: podmanOn},
		{name: "podman native /dev tmpfs missing nosuid is refused", podman: true, path: libpod, body: native(`{"type":"tmpfs","source":"tmpfs","destination":"/dev","options":["noexec","nodev"]}`), wantReason: "must set noexec,nosuid,nodev"},
		{name: "podman native /dev tmpfs with all three reaches the daemon", podman: true, path: libpod, body: native(`{"type":"tmpfs","source":"tmpfs","destination":"/dev/","options":["noexec","nosuid","nodev"]}`), wantReach: true},
		{name: "podman native image_volume_mode tmpfs is refused", podman: true, path: libpod, body: `{"systemd":"false","image":"alpine","image_volume_mode":"tmpfs"}`, wantReason: "image_volume_mode"},
		{name: "podman native image_volume_mode TMPFS is refused", podman: true, path: libpod, body: `{"systemd":"false","image":"alpine","image_volume_mode":"TMPFS"}`, wantReason: "image_volume_mode"},
		{name: "podman native image_volume_mode bind reaches the daemon", podman: true, path: libpod, body: `{"systemd":"false","image":"alpine","image_volume_mode":"bind"}`, wantReach: true},
		{name: "podman native image_volume_mode tmpfs reaches the daemon with the option on", podman: true, path: libpod, body: `{"systemd":"false","image":"alpine","image_volume_mode":"tmpfs"}`, configure: on, wantReach: true},
		{name: "podman native tmpfs with all three reaches the daemon", podman: true, path: libpod, body: native(`{"type":"tmpfs","source":"tmpfs","destination":"/s","options":["noexec","nosuid","nodev","size=64m"]}`), wantReach: true},
		{name: "podman native dev=1 is refused", podman: true, path: libpod, body: native(`{"type":"tmpfs","source":"tmpfs","destination":"/s","options":["noexec","nosuid","nodev","dev=1"]}`), wantReason: denied},
		{name: "podman native tmpfs with no options reaches the daemon with the option on", podman: true, path: libpod, body: native(`{"type":"tmpfs","source":"tmpfs","destination":"/s"}`), configure: on, wantReach: true},
	})
}
