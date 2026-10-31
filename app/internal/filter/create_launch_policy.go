package filter

import (
	"encoding/json"
	"strings"
)

type createLaunchPolicy struct {
	commands    execPolicy
	entrypoints execPolicy
}

func newCreateLaunchPolicy(commands, entrypoints [][]string, allowed, denied, values []string) createLaunchPolicy {
	return createLaunchPolicy{
		commands:    newExecPolicy(ExecOptions{AllowedCommands: commands, AllowedEnvVars: allowed, DeniedEnvVars: denied, AllowedEnvValues: values}),
		entrypoints: newExecPolicy(ExecOptions{AllowedCommands: entrypoints}),
	}
}

func (p createLaunchPolicy) denyReason(command, entrypoint, env []string, subject string) string {
	for _, field := range []struct {
		name   string
		policy execPolicy
		argv   []string
	}{{"command", p.commands, command}, {"entrypoint", p.entrypoints, entrypoint}} {
		if len(field.policy.allowedCommands) == 0 {
			continue
		}
		matched := false
		for _, allowed := range field.policy.allowedCommands {
			if allowed.matches(field.argv) {
				matched = true
				break
			}
		}
		if !matched {
			return subject + " denied: " + field.name + " must be explicitly allowlisted"
		}
	}
	if reason := p.commands.envDenyReason(env); reason != "" {
		return strings.Replace(reason, "exec denied:", subject+" denied:", 1)
	}
	return ""
}

func (p createLaunchPolicy) envRestricted() bool {
	return len(p.commands.allowedEnvVars) > 0 || len(p.commands.deniedEnvVars) > 0 || len(p.commands.allowedEnvValues) > 0
}

func (p createLaunchPolicy) denyLibpodReason(req libpodContainerCreateRequest) string {
	var secrets map[string]string
	secretErr := error(nil)
	if p.envRestricted() && len(req.EnvSecrets) > 0 {
		secretErr = json.Unmarshal(req.EnvSecrets, &secrets)
	}
	if p.envRestricted() && (req.EnvHost || (req.HTTPProxy != nil && *req.HTTPProxy) || secretErr != nil || len(secrets) > 0 || len(req.EnvMerge) > 0) {
		return "libpod container create denied: environment policy forbids env_host, httpproxy, secret_env and envmerge"
	}
	env := make([]string, 0, len(req.Env))
	for name, value := range req.Env {
		env = append(env, name+"="+value)
	}
	return p.denyReason(req.Command, req.Entrypoint, env, "libpod container create")
}
