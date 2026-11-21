package cmd

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// replayCreatePaths are the container-create endpoints a replaying client
// (inspect, then create from the inspect output) posts to.
var replayCreatePaths = []string{"/containers/create", "/libpod/containers/create"}

// warnIfCreateAllowedWithResponseRedaction warns when any rule set (the
// default rules or a selectable client profile) allows container create while a response
// redaction that rewrites inspect output is on. Clients that replay inspect
// output into create (Portainer Recreate, drydock, watchtower) write the
// redaction placeholders back into the new container and silently lose the
// redacted data. Each scope is judged on the redaction it is served under (the
// root, or a profile's root-merged view), and one warning covers all of them.
// The shipped drydock, watchtower, portwing and portainer presets turn
// the three keys off and stay silent.
func warnIfCreateAllowedWithResponseRedaction(cfg *config.Config, logger *slog.Logger) {
	if cfg == nil || logger == nil {
		return
	}
	root := cfg.Response.RedactionSettings()

	// Each scope is judged on the redaction it is served under: the root for
	// the top-level rules, the profile's root-merged view for a profile.
	type scope struct {
		name string
		keys []string
	}
	var scopes []scope
	replayKeys := func(s config.RedactionSettings) []string {
		var keys []string
		if s.ContainerEnv {
			keys = append(keys, "response.redact_container_env")
		}
		if s.MountPaths {
			keys = append(keys, "response.redact_mount_paths")
		}
		if s.NetworkTopology {
			keys = append(keys, "response.redact_network_topology")
		}
		return keys
	}

	// A non-empty clients.default_profile resolves every client that no more
	// specific selector matched, so the top-level rules are never evaluated.
	if strings.TrimSpace(cfg.Clients.DefaultProfile) == "" && rulesAllowReplayCreate(cfg.Rules) {
		if keys := replayKeys(root); len(keys) > 0 {
			scopes = append(scopes, scope{"rules", keys})
		}
	}
	assigned := replayAssignedProfiles(cfg.Clients)
	for _, profile := range cfg.Clients.Profiles {
		if _, ok := assigned[strings.TrimSpace(profile.Name)]; !ok {
			continue
		}
		if !rulesAllowReplayCreate(profile.Rules) {
			continue
		}
		if keys := replayKeys(profile.Response.ApplyRedaction(root)); len(keys) > 0 {
			scopes = append(scopes, scope{"clients.profiles[" + profile.Name + "].rules", keys})
		}
	}
	if len(scopes) == 0 {
		return
	}

	logger.Warn("container create is allowed while response redaction is on: replaying inspect responses into create copies placeholders or empty Env, mount and network values into recreated containers. The root redaction settings are global and apply to every client unless a profile overrides them with clients.profiles[].response.redact_*; disabling them exposes the original fields to every client allowed to read them. Use a dedicated instance and the shipped replay-client presets when other clients still need redaction",
		"keys", strings.Join(scopes[0].keys, ", "),
		"allowed_by", scopes[0].name,
		"other_allowing_scopes", len(scopes)-1,
	)
}

// warnIfProfileDisablesRedaction logs one warning per client profile that
// turns off a redaction the root enables, naming the profile and the keys.
// A profile that turns a redaction on is never warned about.
func warnIfProfileDisablesRedaction(cfg *config.Config, logger *slog.Logger) {
	if cfg == nil || logger == nil {
		return
	}
	root := cfg.Response.RedactionSettings()
	for _, profile := range cfg.Clients.Profiles {
		disabled := profile.Response.ApplyRedaction(root).DisabledRelativeTo(root)
		if len(disabled) == 0 {
			continue
		}
		prefix := "clients.profiles[" + profile.Name + "].response."
		for i, key := range disabled {
			disabled[i] = prefix + key
		}
		logger.Warn("client profile turns off response redaction the root enables: this profile sees the original fields on every read it is allowed",
			"profile", profile.Name,
			"keys", strings.Join(disabled, ", "),
		)
	}
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

func replayAssignedProfiles(clients config.ClientsConfig) map[string]struct{} {
	assigned := make(map[string]struct{}, len(clients.Profiles))
	if name := strings.TrimSpace(clients.DefaultProfile); name != "" {
		assigned[name] = struct{}{}
	}
	for _, assignment := range clients.ClientCertificateProfiles {
		assigned[strings.TrimSpace(assignment.Profile)] = struct{}{}
	}
	for _, assignment := range clients.UnixPeerProfiles {
		assigned[strings.TrimSpace(assignment.Profile)] = struct{}{}
	}
	for _, assignment := range clients.SourceIPProfiles {
		assigned[strings.TrimSpace(assignment.Profile)] = struct{}{}
	}
	return assigned
}
