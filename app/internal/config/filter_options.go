package config

import (
	"strings"

	"github.com/codeswhat/sockguard/internal/filter"
)

// ToFilterOptions converts request-body config into filter middleware policy
// options. Runtime-only fields, such as exec-start upstream inspection, are
// intentionally left for the caller to attach.
func (c RequestBodyConfig) ToFilterOptions() filter.PolicyConfig {
	// container_create.allow_endpoint_config is deliberately NOT its own YAML
	// key: POST /containers/create's NetworkingConfig.EndpointsConfig carries
	// the identical static-IP/MAC/Links/DriverOpts attack surface Docker's
	// POST /networks/*/connect already gates via network.allow_endpoint_config,
	// so a second knob would let an operator widen one endpoint and forget the
	// other. One flag governs both — see filter.ContainerCreateOptions.AllowEndpointConfig.
	containerCreate := c.ContainerCreate.ToFilterOptions()
	containerCreate.AllowEndpointConfig = c.Network.AllowEndpointConfig

	return filter.PolicyConfig{
		ContainerCreate:  containerCreate,
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
		AllowPrivileged:                   c.AllowPrivileged,
		AllowHostNetwork:                  c.AllowHostNetwork,
		AllowHostPID:                      c.AllowHostPID,
		AllowHostIPC:                      c.AllowHostIPC,
		AllowedBindMounts:                 c.AllowedBindMounts,
		AllowAllDevices:                   c.AllowAllDevices,
		AllowedDevices:                    c.AllowedDevices,
		AllowDeviceRequests:               c.AllowDeviceRequests,
		AllowedDeviceRequests:             toFilterAllowedDeviceRequests(c.AllowedDeviceRequests),
		AllowDeviceCgroupRules:            c.AllowDeviceCgroupRules,
		AllowedDeviceCgroupRules:          c.AllowedDeviceCgroupRules,
		RequireNoNewPrivileges:            c.RequireNoNewPrivileges,
		RequireNonRootUser:                c.RequireNonRootUser,
		RequireReadonlyRootfs:             c.RequireReadonlyRootfs,
		RequireDropAllCapabilities:        c.RequireDropAllCapabilities,
		AllowAllCapabilities:              c.AllowAllCapabilities,
		AllowedCapabilities:               c.AllowedCapabilities,
		RequireMemoryLimit:                c.RequireMemoryLimit,
		RequireCPULimit:                   c.RequireCPULimit,
		RequireCPULimitHard:               c.RequireCPULimitHard,
		RequirePidsLimit:                  c.RequirePidsLimit,
		AllowedSeccompProfiles:            c.AllowedSeccompProfiles,
		DenyUnconfinedSeccomp:             c.DenyUnconfinedSeccomp,
		AllowedAppArmorProfiles:           c.AllowedAppArmorProfiles,
		DenyUnconfinedAppArmor:            c.DenyUnconfinedAppArmor,
		AllowHostUserNS:                   c.AllowHostUserNS,
		AllowHostCgroupNS:                 c.AllowHostCgroupNS,
		RestrictNamespaceSharing:          c.RestrictNamespaceSharing,
		AllowedNamespaceSharingContainers: c.AllowedNamespaceSharingContainers,
		DenyNamespacePathMode:             c.DenyNamespacePathMode,
		AllowSysctls:                      c.AllowSysctls,
		RequiredLabels:                    c.RequiredLabels,
		AllowedRuntimes:                   c.AllowedRuntimes,
		ImageTrust:                        c.ImageTrust.toFilterOptions(),
		DenySelinuxDisable:                c.DenySelinuxDisable,
		DenySelinuxLabelOverride:          c.DenySelinuxLabelOverride,
		DenyUnconfinedSystemPaths:         c.DenyUnconfinedSystemPaths,
		AllowTmpfsPrivilegedOptions:       c.AllowTmpfsPrivilegedOptions,
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
		AllowPrivileged:  c.AllowPrivileged,
		AllowRootUser:    c.AllowRootUser,
		AllowedCommands:  c.AllowedCommands,
		AllowedEnvVars:   c.AllowedEnvVars,
		DeniedEnvVars:    c.DeniedEnvVars,
		AllowedEnvValues: c.AllowedEnvValues,
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
		RequireMemoryLimit:   c.RequireMemoryLimit,
		RequireCPULimit:      c.RequireCPULimit,
		RequireCPULimitHard:  c.RequireCPULimitHard,
		RequirePidsLimit:     c.RequirePidsLimit,
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
		AllowDisableIPv4:       c.AllowDisableIPv4,
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
		AllowHostNetwork:           c.AllowHostNetwork,
		AllowedBindMounts:          c.AllowedBindMounts,
		AllowAllRegistries:         c.AllowAllRegistries,
		AllowOfficial:              c.AllowOfficial,
		AllowedRegistries:          c.AllowedRegistries,
		AllowAllCapabilities:       c.AllowAllCapabilities,
		AllowedCapabilities:        c.AllowedCapabilities,
		AllowSysctls:               c.AllowSysctls,
		RequireNonRootUser:         c.RequireNonRootUser,
		RequireNoNewPrivileges:     c.RequireNoNewPrivileges,
		RequireReadonlyRootfs:      c.RequireReadonlyRootfs,
		RequireDropAllCapabilities: c.RequireDropAllCapabilities,
		DenyUnconfinedSeccomp:      c.DenyUnconfinedSeccomp,
		DenyCustomSeccompProfiles:  c.DenyCustomSeccompProfiles,
		DenyUnconfinedAppArmor:     c.DenyUnconfinedAppArmor,
		DenySelinuxDisable:         c.DenySelinuxDisable,
		DenySelinuxLabelOverride:   c.DenySelinuxLabelOverride,
		ImageTrust:                 c.ImageTrust.toFilterOptions(),
		RequireCPULimit:            c.RequireCPULimit,
		RequireCPULimitHard:        c.RequireCPULimitHard,
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

// ToFilterOptions converts the mutations config block into filter.MutationOptions.
// Unlike RequestBodyConfig.ToFilterOptions, this carries global state (see
// MutationsConfig's doc comment: mutations are not part of clients.profiles),
// so cmd/serve.go attaches the result to filter.Options.Mutation directly
// rather than through PolicyConfig.
func (c MutationsConfig) ToFilterOptions() filter.MutationOptions {
	if len(c.Rules) == 0 {
		return filter.MutationOptions{}
	}
	rules := make([]filter.MutationRuleOptions, 0, len(c.Rules))
	for _, r := range c.Rules {
		opt := filter.MutationRuleOptions{
			ID:       r.ID,
			Mode:     r.Mode,
			Surfaces: r.Surfaces,
		}
		if r.InjectLabels != nil {
			opt.InjectLabels = &filter.InjectLabelsMutationOptions{Labels: r.InjectLabels.Labels}
		}
		if r.RemapImage != nil {
			// Validation (validateMutationRemapImage) accepts match case-
			// insensitively (lowercasing before comparing against
			// "exact"/"prefix"), but does not write the canonical form back
			// onto rule.RemapImage.Match. Normalize here too, rather than
			// relying solely on filter.newMutationEngine's own
			// ToLower(TrimSpace(...)) of this same field, so this package's
			// output is already canonical independent of that internal
			// detail of a different package.
			opt.RemapImage = &filter.ImageRemapMutationOptions{
				Match: strings.ToLower(strings.TrimSpace(r.RemapImage.Match)),
				From:  r.RemapImage.From,
				To:    r.RemapImage.To,
			}
		}
		rules = append(rules, opt)
	}
	return filter.MutationOptions{Rules: rules}
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
