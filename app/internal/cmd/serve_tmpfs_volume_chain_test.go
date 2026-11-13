package cmd

import (
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestServeChainTmpfsVolumeOptionsNeedTheirOption pins that a local volume of
// type tmpfs answers to allow_tmpfs_privileged_options. The local driver hands
// type and o to mount(2), so {"type":"tmpfs","o":"exec,suid,dev"} was a
// tmpfs with the flags the option refuses, and allow_driver_opts (or, on
// container create, nothing at all) was the only gate on it.
func TestServeChainTmpfsVolumeOptionsNeedTheirOption(t *testing.T) {
	const (
		volumeCreate = "/v1.45/volumes/create"
		libpodVolume = "/v6.1.3/libpod/volumes/create"
		containerRun = "/v1.45/containers/create"
		serviceMake  = "/v1.45/services/create"
	)
	driverOpts := func(opts string) string { return `{"Name":"v","Driver":"local","DriverOpts":` + opts + `}` }
	libpodOpts := func(opts string) string { return `{"Name":"v","Driver":"local","Options":` + opts + `}` }
	driverConfig := func(opts string) string {
		return `{"Type":"volume","Target":"/v","VolumeOptions":{"DriverConfig":{"Name":"local","Options":` + opts + `}}}`
	}
	container := func(opts string) string {
		return `{"Image":"alpine","HostConfig":{"Mounts":[` + driverConfig(opts) + `]}}`
	}
	service := func(opts string) string {
		return `{"Name":"web","TaskTemplate":{"ContainerSpec":{"Image":"alpine","Mounts":[` + driverConfig(opts) + `]}}}`
	}
	driverOptsOn := func(body *config.RequestBodyConfig) {
		body.Volume.AllowDriverOpts = true
		body.LibpodVolume.AllowDriverOpts = true
	}
	allOn := func(body *config.RequestBodyConfig) {
		driverOptsOn(body)
		body.ContainerCreate.AllowTmpfsPrivilegedOptions = true
		body.LibpodContainerCreate.AllowTmpfsPrivilegedOptions = true
	}
	const denied = "local tmpfs volume options enable exec, dev, or suid"

	runTmpfsChainCases(t, []tmpfsChainCase{
		// Controls.
		{name: "tmpfs volume with a size and all three reaches the daemon", path: volumeCreate, body: driverOpts(`{"type":"tmpfs","device":"tmpfs","o":"size=64m,uid=1000,noexec,nosuid,nodev"}`), configure: driverOptsOn, wantReach: true},
		{name: "tmpfs volume with a size only is refused, the kernel default is exec", path: volumeCreate, body: driverOpts(`{"type":"tmpfs","device":"tmpfs","o":"size=64m"}`), configure: driverOptsOn, wantReason: "unless o lists noexec,nosuid,nodev"},
		{name: "tmpfs volume with no o is refused", path: volumeCreate, body: driverOpts(`{"type":"tmpfs","device":"tmpfs"}`), configure: driverOptsOn, wantReason: "unless o lists noexec,nosuid,nodev"},
		{name: "tmpfs volume with noexec only is refused", path: volumeCreate, body: driverOpts(`{"type":"tmpfs","device":"tmpfs","o":"noexec"}`), configure: driverOptsOn, wantReason: "unless o lists noexec,nosuid,nodev"},
		{name: "tmpfs volume with no o reaches the daemon with the option on", path: volumeCreate, body: driverOpts(`{"type":"tmpfs","device":"tmpfs"}`), configure: allOn, wantReach: true},
		{name: "tmpfs volume with noexec,nosuid,nodev reaches the daemon", path: volumeCreate, body: driverOpts(`{"type":"tmpfs","device":"tmpfs","o":"noexec,nosuid,nodev"}`), configure: driverOptsOn, wantReach: true},
		{name: "exec,suid,dev on an nfs volume is not a tmpfs", path: volumeCreate, body: driverOpts(`{"type":"nfs","device":":/x","o":"addr=1.2.3.4,exec,suid,dev"}`), configure: driverOptsOn, wantReach: true},
		{name: "exec on a tmpfs volume with last noexec reaches the daemon", path: volumeCreate, body: driverOpts(`{"type":"tmpfs","device":"tmpfs","o":"exec,noexec,nosuid,nodev"}`), configure: driverOptsOn, wantReach: true},

		// POST /volumes/create.
		{name: "volume create exec is refused", path: volumeCreate, body: driverOpts(`{"type":"tmpfs","device":"tmpfs","o":"size=1m,exec"}`), configure: driverOptsOn, wantReason: denied},
		{name: "volume create suid is refused", path: volumeCreate, body: driverOpts(`{"type":"tmpfs","device":"tmpfs","o":"suid"}`), configure: driverOptsOn, wantReason: denied},
		{name: "volume create dev is refused", path: volumeCreate, body: driverOpts(`{"type":"tmpfs","device":"tmpfs","o":"dev"}`), configure: driverOptsOn, wantReason: denied},
		{name: "volume create exec,suid,dev is refused", path: volumeCreate, body: driverOpts(`{"type":"tmpfs","device":"tmpfs","o":"exec,suid,dev"}`), configure: driverOptsOn, wantReason: denied},
		{name: "volume create suid=1 is refused", path: volumeCreate, body: driverOpts(`{"type":"tmpfs","device":"tmpfs","o":"suid=1"}`), configure: driverOptsOn, wantReason: denied},
		{name: "volume create keys in capitals are refused", path: volumeCreate, body: driverOpts(`{"TYPE":"TMPFS","device":"tmpfs","O":"exec"}`), configure: driverOptsOn, wantReason: denied},
		{name: "volume create via Opts is refused", path: volumeCreate, body: `{"Name":"v","Driver":"local","Opts":{"type":"tmpfs","device":"tmpfs","o":"exec"}}`, configure: driverOptsOn, wantReason: denied},
		{name: "volume create with no driver named is refused", path: volumeCreate, body: `{"Name":"v","DriverOpts":{"type":"tmpfs","device":"tmpfs","o":"exec"}}`, configure: driverOptsOn, wantReason: denied},
		{name: "volume create exec reaches the daemon with the option on", path: volumeCreate, body: driverOpts(`{"type":"tmpfs","device":"tmpfs","o":"exec,suid,dev"}`), configure: allOn, wantReach: true},

		// POST /libpod/volumes/create.
		{name: "libpod volume create exec is refused", podman: true, path: libpodVolume, body: libpodOpts(`{"type":"tmpfs","device":"tmpfs","o":"exec"}`), configure: driverOptsOn, wantReason: denied},
		{name: "libpod volume create with no o is refused", podman: true, path: libpodVolume, body: libpodOpts(`{"type":"tmpfs","device":"tmpfs"}`), configure: driverOptsOn, wantReason: "unless o lists noexec,nosuid,nodev"},
		{name: "libpod volume create noexec reaches the daemon", podman: true, path: libpodVolume, body: libpodOpts(`{"type":"tmpfs","device":"tmpfs","o":"noexec,nosuid,nodev"}`), configure: driverOptsOn, wantReach: true},
		{name: "libpod volume create exec reaches the daemon with the option on", podman: true, path: libpodVolume, body: libpodOpts(`{"type":"tmpfs","device":"tmpfs","o":"exec"}`), configure: allOn, wantReach: true},
		{name: "the compat option does not open the libpod volume route", podman: true, path: libpodVolume, body: libpodOpts(`{"type":"tmpfs","device":"tmpfs","o":"exec"}`),
			configure: func(body *config.RequestBodyConfig) {
				driverOptsOn(body)
				body.ContainerCreate.AllowTmpfsPrivilegedOptions = true
			}, wantReason: denied},

		// A volume created through the mount that names its driver.
		{name: "container create DriverConfig exec is refused", path: containerRun, body: container(`{"type":"tmpfs","device":"tmpfs","o":"exec"}`), wantReason: denied},
		{name: "container create DriverConfig noexec alone is refused", path: containerRun, body: container(`{"type":"tmpfs","device":"tmpfs","o":"noexec"}`), wantReason: "unless o lists noexec,nosuid,nodev"},
		{name: "container create DriverConfig all three reaches the daemon", path: containerRun, body: container(`{"type":"tmpfs","device":"tmpfs","o":"noexec,nosuid,nodev"}`), wantReach: true},
		{name: "container create DriverConfig exec reaches the daemon with the option on", path: containerRun, body: container(`{"type":"tmpfs","device":"tmpfs","o":"exec"}`), configure: allOn, wantReach: true},
		{name: "service DriverConfig exec is refused", path: serviceMake, body: service(`{"type":"tmpfs","device":"tmpfs","o":"exec"}`), wantReason: denied},
		{name: "service DriverConfig exec reaches the daemon with the option on", path: serviceMake, body: service(`{"type":"tmpfs","device":"tmpfs","o":"exec"}`), configure: allOn, wantReach: true},
	})
}
