package cmd

import (
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestServeChainServiceTmpfsOptionsNeedTheirOption pins that a swarm service
// mount's TmpfsOptions answer to allow_tmpfs_privileged_options on create and
// update. serviceMount didn't decode the field, so the options passed unread.
func TestServeChainServiceTmpfsOptionsNeedTheirOption(t *testing.T) {
	const (
		create = "/v1.45/services/create"
		update = "/v1.45/services/web/update?version=1"
	)
	service := func(tmpfsOptions string) string {
		return `{"Name":"web","TaskTemplate":{"ContainerSpec":{"Image":"alpine","Mounts":[{"Type":"tmpfs","Target":"/scratch","TmpfsOptions":` + tmpfsOptions + `}]}}}`
	}
	on := func(body *config.RequestBodyConfig) { body.ContainerCreate.AllowTmpfsPrivilegedOptions = true }
	const denied = "tmpfs mount option"

	runTmpfsChainCases(t, []tmpfsChainCase{
		{name: "create with no TmpfsOptions reaches the daemon", path: create, body: `{"Name":"web","TaskTemplate":{"ContainerSpec":{"Image":"alpine","Mounts":[{"Type":"tmpfs","Target":"/scratch"}]}}}`, wantReach: true},
		{name: "create with a size reaches the daemon", path: create, body: service(`{"SizeBytes":1048576,"Options":[["size","64m"]]}`), wantReach: true},
		{name: "create with noexec reaches the daemon", path: create, body: service(`{"Options":[["noexec"]]}`), wantReach: true},
		{name: "create exec is refused", path: create, body: service(`{"Options":[["exec"]]}`), wantReason: denied},
		{name: "create suid is refused", path: create, body: service(`{"Options":[["suid"]]}`), wantReason: denied},
		{name: "create dev in capitals is refused", path: create, body: service(`{"Options":[["DEV"]]}`), wantReason: denied},
		{name: "create exec as key and value is refused", path: create, body: service(`{"Options":[["exec","1"]]}`), wantReason: denied},
		{name: "create suid=1 token is refused", path: create, body: service(`{"Options":[["suid=1"]]}`), wantReason: denied},
		{name: "create malformed entry is refused", path: create, body: service(`{"Options":[["a","b","c"]]}`), wantReason: "malformed tmpfs mount option"},
		{name: "create exec reaches the daemon with the option on", path: create, body: service(`{"Options":[["exec"],["suid"]]}`), configure: on, wantReach: true},
		{name: "update exec is refused", path: update, body: service(`{"Options":[["exec"]]}`), wantReason: denied},
		{name: "update noexec reaches the daemon", path: update, body: service(`{"Options":[["noexec"]]}`), wantReach: true},
		{name: "update exec reaches the daemon with the option on", path: update, body: service(`{"Options":[["exec"]]}`), configure: on, wantReach: true},
	})
}
