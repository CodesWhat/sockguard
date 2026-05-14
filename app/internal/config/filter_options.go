package config

import "github.com/codeswhat/sockguard/internal/filter"

// ToFilterOptions converts request-body config into filter middleware policy
// options. Runtime-only fields, such as exec-start upstream inspection, are
// intentionally left for the caller to attach.
func (c RequestBodyConfig) ToFilterOptions() filter.PolicyConfig {
	return filter.PolicyConfig{
		ContainerCreate:  c.ContainerCreate.ToFilterOptions(),
		Exec:             c.Exec.ToFilterOptions(),
		ImagePull:        c.ImagePull.ToFilterOptions(),
		Build:            c.Build.ToFilterOptions(),
		ContainerUpdate:  c.ContainerUpdate.ToFilterOptions(),
		ContainerArchive: c.ContainerArchive.ToFilterOptions(),
		ImageLoad:        c.ImageLoad.ToFilterOptions(),
		Volume:           c.Volume.ToFilterOptions(),
		Network:          c.Network.ToFilterOptions(),
		Secret:           c.Secret.ToFilterOptions(),
		Config:           c.Config.ToFilterOptions(),
		Service:          c.Service.ToFilterOptions(),
		Swarm:            c.Swarm.ToFilterOptions(),
		Node:             c.Node.ToFilterOptions(),
		Plugin:           c.Plugin.ToFilterOptions(),
	}
}

func (c ContainerCreateRequestBodyConfig) ToFilterOptions() filter.ContainerCreateOptions {
	return filter.ContainerCreateOptions{
		AllowPrivileged:            c.AllowPrivileged,
		AllowHostNetwork:           c.AllowHostNetwork,
		AllowHostPID:               c.AllowHostPID,
		AllowHostIPC:               c.AllowHostIPC,
		AllowedBindMounts:          c.AllowedBindMounts,
		AllowAllDevices:            c.AllowAllDevices,
		AllowedDevices:             c.AllowedDevices,
		AllowDeviceRequests:         c.AllowDeviceRequests,
		AllowedDeviceRequests:       toFilterAllowedDeviceRequests(c.AllowedDeviceRequests),
		AllowDeviceCgroupRules:      c.AllowDeviceCgroupRules,
		AllowedDeviceCgroupRules:    c.AllowedDeviceCgroupRules,
		RequireNoNewPrivileges:     c.RequireNoNewPrivileges,
		RequireNonRootUser:         c.RequireNonRootUser,
		RequireReadonlyRootfs:      c.RequireReadonlyRootfs,
		RequireDropAllCapabilities: c.RequireDropAllCapabilities,
		AllowAllCapabilities:       c.AllowAllCapabilities,
		AllowedCapabilities:        c.AllowedCapabilities,
		RequireMemoryLimit:         c.RequireMemoryLimit,
		RequireCPULimit:            c.RequireCPULimit,
		RequirePidsLimit:           c.RequirePidsLimit,
		AllowedSeccompProfiles:     c.AllowedSeccompProfiles,
		DenyUnconfinedSeccomp:      c.DenyUnconfinedSeccomp,
		AllowedAppArmorProfiles:    c.AllowedAppArmorProfiles,
		DenyUnconfinedAppArmor:     c.DenyUnconfinedAppArmor,
		AllowHostUserNS:            c.AllowHostUserNS,
		AllowSysctls:               c.AllowSysctls,
		RequiredLabels:             c.RequiredLabels,
		ImageTrust:                 c.ImageTrust.toFilterOptions(),
	}
}

func (c ImageTrustConfig) toFilterOptions() filter.ImageTrustOptions {
	var keys []filter.SigningKeyOptions
	if len(c.AllowedSigningKeys) > 0 {
		keys = make([]filter.SigningKeyOptions, 0, len(c.AllowedSigningKeys))
		for _, k := range c.AllowedSigningKeys {
			keys = append(keys, filter.SigningKeyOptions{PEM: k.PEM})
		}
	}
	var kl []filter.KeylessOptions
	if len(c.AllowedKeyless) > 0 {
		kl = make([]filter.KeylessOptions, 0, len(c.AllowedKeyless))
		for _, k := range c.AllowedKeyless {
			kl = append(kl, filter.KeylessOptions{
				Issuer:         k.Issuer,
				SubjectPattern: k.SubjectPattern,
			})
		}
	}
	return filter.ImageTrustOptions{
		Mode:                  c.Mode,
		AllowedSigningKeys:    keys,
		AllowedKeyless:        kl,
		RequireRekorInclusion: c.RequireRekorInclusion,
		VerifyTimeout:         c.VerifyTimeout,
	}
}

func (c ExecRequestBodyConfig) ToFilterOptions() filter.ExecOptions {
	return filter.ExecOptions{
		AllowPrivileged: c.AllowPrivileged,
		AllowRootUser:   c.AllowRootUser,
		AllowedCommands: c.AllowedCommands,
	}
}

func (c ImagePullRequestBodyConfig) ToFilterOptions() filter.ImagePullOptions {
	return filter.ImagePullOptions{
		AllowImports:       c.AllowImports,
		AllowAllRegistries: c.AllowAllRegistries,
		AllowOfficial:      c.AllowOfficial,
		AllowedRegistries:  c.AllowedRegistries,
	}
}

func (c BuildRequestBodyConfig) ToFilterOptions() filter.BuildOptions {
	return filter.BuildOptions{
		AllowRemoteContext:   c.AllowRemoteContext,
		AllowHostNetwork:     c.AllowHostNetwork,
		AllowRunInstructions: c.AllowRunInstructions,
	}
}

func (c ContainerUpdateRequestBodyConfig) ToFilterOptions() filter.ContainerUpdateOptions {
	return filter.ContainerUpdateOptions{
		AllowPrivileged:      c.AllowPrivileged,
		AllowAllDevices:      c.AllowAllDevices,
		AllowCapabilities:    c.AllowCapabilities,
		AllowResourceUpdates: c.AllowResourceUpdates,
		AllowRestartPolicy:   c.AllowRestartPolicy,
	}
}

func (c ContainerArchiveRequestBodyConfig) ToFilterOptions() filter.ContainerArchiveOptions {
	return filter.ContainerArchiveOptions{
		AllowedPaths:       c.AllowedPaths,
		AllowSetID:         c.AllowSetID,
		AllowDeviceNodes:   c.AllowDeviceNodes,
		AllowEscapingLinks: c.AllowEscapingLinks,
	}
}

func (c ImageLoadRequestBodyConfig) ToFilterOptions() filter.ImageLoadOptions {
	return filter.ImageLoadOptions{
		AllowAllRegistries: c.AllowAllRegistries,
		AllowOfficial:      c.AllowOfficial,
		AllowedRegistries:  c.AllowedRegistries,
		AllowUntagged:      c.AllowUntagged,
	}
}

func (c VolumeRequestBodyConfig) ToFilterOptions() filter.VolumeOptions {
	return filter.VolumeOptions{
		AllowCustomDrivers: c.AllowCustomDrivers,
		AllowDriverOpts:    c.AllowDriverOpts,
	}
}

func (c NetworkRequestBodyConfig) ToFilterOptions() filter.NetworkOptions {
	return filter.NetworkOptions{
		AllowCustomDrivers:     c.AllowCustomDrivers,
		AllowSwarmScope:        c.AllowSwarmScope,
		AllowIngress:           c.AllowIngress,
		AllowAttachable:        c.AllowAttachable,
		AllowConfigOnly:        c.AllowConfigOnly,
		AllowConfigFrom:        c.AllowConfigFrom,
		AllowCustomIPAMDrivers: c.AllowCustomIPAMDrivers,
		AllowCustomIPAMConfig:  c.AllowCustomIPAMConfig,
		AllowIPAMOptions:       c.AllowIPAMOptions,
		AllowDriverOptions:     c.AllowDriverOptions,
		AllowEndpointConfig:    c.AllowEndpointConfig,
		AllowDisconnectForce:   c.AllowDisconnectForce,
	}
}

func (c SecretRequestBodyConfig) ToFilterOptions() filter.SecretOptions {
	return filter.SecretOptions{
		AllowCustomDrivers:   c.AllowCustomDrivers,
		AllowTemplateDrivers: c.AllowTemplateDrivers,
	}
}

func (c ConfigRequestBodyConfig) ToFilterOptions() filter.ConfigOptions {
	return filter.ConfigOptions{
		AllowCustomDrivers:   c.AllowCustomDrivers,
		AllowTemplateDrivers: c.AllowTemplateDrivers,
	}
}

func (c ServiceRequestBodyConfig) ToFilterOptions() filter.ServiceOptions {
	return filter.ServiceOptions{
		AllowHostNetwork:   c.AllowHostNetwork,
		AllowedBindMounts:  c.AllowedBindMounts,
		AllowAllRegistries: c.AllowAllRegistries,
		AllowOfficial:      c.AllowOfficial,
		AllowedRegistries:  c.AllowedRegistries,
	}
}

func (c SwarmRequestBodyConfig) ToFilterOptions() filter.SwarmOptions {
	return filter.SwarmOptions{
		AllowForceNewCluster:          c.AllowForceNewCluster,
		AllowExternalCA:               c.AllowExternalCA,
		AllowedJoinRemoteAddrs:        c.AllowedJoinRemoteAddrs,
		AllowTokenRotation:            c.AllowTokenRotation,
		AllowManagerUnlockKeyRotation: c.AllowManagerUnlockKeyRotation,
		AllowAutoLockManagers:         c.AllowAutoLockManagers,
		AllowSigningCAUpdate:          c.AllowSigningCAUpdate,
		AllowUnlock:                   c.AllowUnlock,
	}
}

func (c NodeRequestBodyConfig) ToFilterOptions() filter.NodeOptions {
	return filter.NodeOptions{
		AllowNameChange:         c.AllowNameChange,
		AllowRoleChange:         c.AllowRoleChange,
		AllowAvailabilityChange: c.AllowAvailabilityChange,
		AllowLabelMutation:      c.AllowLabelMutation,
		AllowedLabelKeys:        c.AllowedLabelKeys,
	}
}

func (c PluginRequestBodyConfig) ToFilterOptions() filter.PluginOptions {
	return filter.PluginOptions{
		AllowHostNetwork:      c.AllowHostNetwork,
		AllowHostIPC:          c.AllowHostIPC,
		AllowHostPID:          c.AllowHostPID,
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

// toFilterAllowedDeviceRequests converts config AllowedDeviceRequest slices to
// the filter package's AllowedDeviceRequestEntry type. Returns nil when the
// input is empty so reflect.DeepEqual comparisons against zero-value structs
// remain correct.
func toFilterAllowedDeviceRequests(entries []AllowedDeviceRequest) []filter.AllowedDeviceRequestEntry {
	if len(entries) == 0 {
		return nil
	}
	out := make([]filter.AllowedDeviceRequestEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, filter.AllowedDeviceRequestEntry{
			Driver:              e.Driver,
			AllowedCapabilities: e.AllowedCapabilities,
			MaxCount:            e.MaxCount,
		})
	}
	return out
}
