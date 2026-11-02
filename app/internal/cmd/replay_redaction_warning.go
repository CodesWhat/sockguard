package cmd

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

// replayCreatePaths are the container-create endpoints a replaying client
// (inspect, then create from the inspect output) posts to.
var replayCreatePaths = []string{"/containers/create", "/libpod/containers/create"}

// warnIfCreateAllowedWithResponseRedaction warns when any rule set (the
// default rules or a client profile) allows container create while a response
// redaction that rewrites inspect output is on. Clients that replay inspect
// output into create (Portainer Recreate, drydock, watchtower) write the
// redaction placeholders back into the new container and silently lose the
// redacted data. Redaction settings are global, so one warning covers every
// client. The shipped drydock, watchtower, portwing and portainer presets turn
// the three keys off and stay silent.
func warnIfCreateAllowedWithResponseRedaction(cfg *config.Config, logger *slog.Logger) {
	if cfg == nil || logger == nil {
		return
	}
	var keys []string
	if cfg.Response.RedactContainerEnv {
		keys = append(keys, "response.redact_container_env")
	}
	if cfg.Response.RedactMountPaths {
		keys = append(keys, "response.redact_mount_paths")
	}
	if cfg.Response.RedactNetworkTopology {
		keys = append(keys, "response.redact_network_topology")
	}
	if len(keys) == 0 {
		return
	}

	scope := ""
	if rulesAllowReplayCreate(cfg.Rules) {
		scope = "rules"
	}
	if scope == "" {
		for _, profile := range cfg.Clients.Profiles {
			if rulesAllowReplayCreate(profile.Rules) {
				scope = "clients.profiles[" + profile.Name + "].rules"
				break
			}
		}
	}
	if scope == "" {
		return
	}

	logger.Warn("container create is allowed while response redaction is on: clients that replay container inspect output into create (Portainer Recreate, drydock, watchtower) will lose data, because the redacted Env, Binds/Mounts and network fields are written back into the new container as placeholders or empty values; set these keys to false for those clients, or use their shipped presets",
		"keys", strings.Join(keys, ", "),
		"allowed_by", scope,
	)
}

func rulesAllowReplayCreate(rules []config.RuleConfig) bool {
	if len(rules) == 0 {
		return false
	}
	compiled, err := compileConfiguredRules(rules)
	if err != nil {
		return false
	}
	for _, path := range replayCreatePaths {
		if policyAllowsPath(http.MethodPost, path, compiled) {
			return true
		}
	}
	return false
}
