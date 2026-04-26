package config

import "github.com/codeswhat/sockguard/internal/filter"

// ToFilterOptions converts request-body config into filter middleware policy
// options. Runtime-only fields, such as exec-start upstream inspection, are
// intentionally left for the caller to attach.
func (c RequestBodyConfig) ToFilterOptions() filter.PolicyConfig {
	return filter.PolicyConfig{
		ContainerCreate: c.ContainerCreate.ToFilterOptions(),
		Exec:            c.Exec.ToFilterOptions(),
		ImagePull:       c.ImagePull.ToFilterOptions(),
		Build:           c.Build.ToFilterOptions(),
		Volume:          c.Volume.ToFilterOptions(),
		Secret:          c.Secret.ToFilterOptions(),
		Config:          c.Config.ToFilterOptions(),
		Service:         c.Service.ToFilterOptions(),
		Swarm:           c.Swarm.ToFilterOptions(),
		Plugin:          c.Plugin.ToFilterOptions(),
	}
}

// ToFilterOptions converts container-create request-body config into filter
// options.
func (c ContainerCreateRequestBodyConfig) ToFilterOptions() filter.ContainerCreateOptions {
	return filter.ContainerCreateOptions{
		AllowPrivileged:   c.AllowPrivileged,
		AllowHostNetwork:  c.AllowHostNetwork,
		AllowedBindMounts: c.AllowedBindMounts,
	}
}

// ToFilterOptions converts exec request-body config into filter options.
func (c ExecRequestBodyConfig) ToFilterOptions() filter.ExecOptions {
	return filter.ExecOptions{
		AllowPrivileged: c.AllowPrivileged,
		AllowRootUser:   c.AllowRootUser,
		AllowedCommands: c.AllowedCommands,
	}
}

// ToFilterOptions converts image-pull request config into filter options.
func (c ImagePullRequestBodyConfig) ToFilterOptions() filter.ImagePullOptions {
	return filter.ImagePullOptions{
		AllowImports:       c.AllowImports,
		AllowAllRegistries: c.AllowAllRegistries,
		AllowOfficial:      c.AllowOfficial,
		AllowedRegistries:  c.AllowedRegistries,
	}
}

// ToFilterOptions converts build request-body config into filter options.
func (c BuildRequestBodyConfig) ToFilterOptions() filter.BuildOptions {
	return filter.BuildOptions{
		AllowRemoteContext:   c.AllowRemoteContext,
		AllowHostNetwork:     c.AllowHostNetwork,
		AllowRunInstructions: c.AllowRunInstructions,
	}
}

// ToFilterOptions converts volume request-body config into filter options.
func (c VolumeRequestBodyConfig) ToFilterOptions() filter.VolumeOptions {
	return filter.VolumeOptions{
		AllowCustomDrivers: c.AllowCustomDrivers,
		AllowDriverOpts:    c.AllowDriverOpts,
	}
}

// ToFilterOptions converts secret request-body config into filter options.
func (c SecretRequestBodyConfig) ToFilterOptions() filter.SecretOptions {
	return filter.SecretOptions{
		AllowCustomDrivers:   c.AllowCustomDrivers,
		AllowTemplateDrivers: c.AllowTemplateDrivers,
	}
}

// ToFilterOptions converts config-write request-body config into filter
// options.
func (c ConfigRequestBodyConfig) ToFilterOptions() filter.ConfigOptions {
	return filter.ConfigOptions{
		AllowCustomDrivers:   c.AllowCustomDrivers,
		AllowTemplateDrivers: c.AllowTemplateDrivers,
	}
}

// ToFilterOptions converts service request-body config into filter options.
func (c ServiceRequestBodyConfig) ToFilterOptions() filter.ServiceOptions {
	return filter.ServiceOptions{
		AllowHostNetwork:   c.AllowHostNetwork,
		AllowedBindMounts:  c.AllowedBindMounts,
		AllowAllRegistries: c.AllowAllRegistries,
		AllowOfficial:      c.AllowOfficial,
		AllowedRegistries:  c.AllowedRegistries,
	}
}

// ToFilterOptions converts swarm request-body config into filter options.
func (c SwarmRequestBodyConfig) ToFilterOptions() filter.SwarmOptions {
	return filter.SwarmOptions{
		AllowForceNewCluster:          c.AllowForceNewCluster,
		AllowExternalCA:               c.AllowExternalCA,
		AllowedJoinRemoteAddrs:        c.AllowedJoinRemoteAddrs,
		AllowTokenRotation:            c.AllowTokenRotation,
		AllowManagerUnlockKeyRotation: c.AllowManagerUnlockKeyRotation,
		AllowAutoLockManagers:         c.AllowAutoLockManagers,
		AllowSigningCAUpdate:          c.AllowSigningCAUpdate,
	}
}

// ToFilterOptions converts plugin request-body config into filter options.
func (c PluginRequestBodyConfig) ToFilterOptions() filter.PluginOptions {
	return filter.PluginOptions{
		AllowHostNetwork:      c.AllowHostNetwork,
		AllowIPCHost:          c.AllowIPCHost,
		AllowPIDHost:          c.AllowPIDHost,
		AllowAllDevices:       c.AllowAllDevices,
		AllowedBindMounts:     c.AllowedBindMounts,
		AllowedDevices:        c.AllowedDevices,
		AllowAllCapabilities:  c.AllowAllCapabilities,
		AllowedCapabilities:   c.AllowedCapabilities,
		AllowAllRegistries:    c.AllowAllRegistries,
		AllowOfficial:         c.AllowOfficial,
		AllowedRegistries:     c.AllowedRegistries,
		AllowedSetEnvPrefixes: c.AllowedSetEnvPrefixes,
	}
}
