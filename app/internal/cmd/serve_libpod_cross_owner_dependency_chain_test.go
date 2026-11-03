package cmd

import (
	"net/http"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestServeChainLibpodCreateCannotDependOnAnotherOwnersContainer pins the
// premise behind the `depend` gate on a libpod container remove (S65): a
// container of another owner can't come to depend on team-a's.
//
// DELETE /libpod/containers/{name}?depend=true removes every container that
// lists the target in its Dependencies(), and owner isolation checks only the
// target. That is safe only while a create can't make one owner's container
// depend on another's. Podman 5.8.1 libpod/container.go Dependencies() is the
// complete list of what a create can put there: the container each of the IPC,
// mount, net, PID, user, UTS and cgroup namespaces joins, and
// config.Dependencies, which `dependencyContainers` and `volumes_from` fill.
// The mount namespace isn't settable from a create body, and joining a pod
// makes the infra container the net, IPC and PID target. Every other way to
// name a container is checked below; each one must be refused before the
// daemon creates anything. If Podman adds a field that makes a container
// depend on another, this is the list to extend.
//
// This is the create body side only. The remove gate itself is covered by
// TestServeChainLibpodContainerRemoveAppliesTheRemoveGates.
func TestServeChainLibpodCreateCannotDependOnAnotherOwnersContainer(t *testing.T) {
	fields := map[string]string{
		"dependencyContainers": `"dependencyContainers":["theirs-ctr"]`,
		"volumes_from":         `"volumes_from":["theirs-ctr"]`,
		"netns":                `"netns":{"nsmode":"container","value":"theirs-ctr"}`,
		"pidns":                `"pidns":{"nsmode":"container","value":"theirs-ctr"}`,
		"ipcns":                `"ipcns":{"nsmode":"container","value":"theirs-ctr"}`,
		"utsns":                `"utsns":{"nsmode":"container","value":"theirs-ctr"}`,
		"userns":               `"userns":{"nsmode":"container","value":"theirs-ctr"}`,
		"cgroupns":             `"cgroupns":{"nsmode":"container","value":"theirs-ctr"}`,
		"pod":                  `"pod":"theirs-pod"`,
	}
	for name, field := range fields {
		t.Run(name, func(t *testing.T) {
			daemon := newLibpodCreateRefChainDaemon()
			addr := newEngineChain(t, "cross-dep", daemon, func(cfg *config.Config) {
				cfg.Ownership.Owner = "team-a"
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			})
			status, body := postLibpodCreateRefChainJSON(t, "http://"+addr+"/v5.0.0/libpod/containers/create",
				`{"image":"alpine","systemd":"false",`+field+`}`)
			if status != http.StatusForbidden {
				t.Errorf("status = %d, want %d; body: %s", status, http.StatusForbidden, body)
			}
			if created := daemon.made(); len(created) != 0 {
				t.Errorf("daemon created %+v, want nothing", created)
			}
		})
	}
}
