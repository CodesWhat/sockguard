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

	// A non-empty clients.default_profile resolves every client that no more
	// specific selector matched, so the top-level rules are never evaluated.
	var scopes []string
	if strings.TrimSpace(cfg.Clients.DefaultProfile) == "" && rulesAllowReplayCreate(cfg.Rules) {
		scopes = append(scopes, "rules")
	}
	for _, profile := range cfg.Clients.Profiles {
		if rulesAllowReplayCreate(profile.Rules) {
			scopes = append(scopes, "clients.profiles["+profile.Name+"].rules")
		}
	}
	if len(scopes) == 0 {
		return
	}

	logger.Warn("container create is allowed while response redaction is on: clients that replay container inspect output into create (Portainer Recreate/Duplicate, drydock and watchtower updates) will lose the redacted Env, Binds/Mounts and network fields, which are written back into the new container as placeholders or empty values; other clients can ignore this. Set these keys to false for replaying clients, or use their shipped presets",
		"keys", strings.Join(keys, ", "),
		"allowed_by", scopes[0],
		"other_allowing_scopes", len(scopes)-1,
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
