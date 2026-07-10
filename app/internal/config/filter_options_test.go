package config

import (
	"reflect"
	"testing"

	"github.com/codeswhat/sockguard/internal/filter"
)

func TestRequestBodyConfigToFilterOptionsMapsEveryPolicy(t *testing.T) {
	cfg := RequestBodyConfig{
		ContainerCreate: ContainerCreateRequestBodyConfig{
			AllowPrivileged:                   true,
			AllowHostNetwork:                  true,
			AllowHostPID:                      true,
			AllowHostIPC:                      true,
			AllowedBindMounts:                 []string{"/srv/data", "/var/lib/sockguard"},
			AllowAllDevices:                   true,
			AllowedDevices:                    []string{"/dev/kvm", "/dev/dri"},
			AllowDeviceRequests:               true,
			AllowDeviceCgroupRules:            true,
			RestrictNamespaceSharing:          true,
			AllowedNamespaceSharingContainers: []string{"sidecar", "abc123"},
			DenyNamespacePathMode:             true,
		},
		Exec: ExecRequestBodyConfig{
			AllowPrivileged: true,
			AllowRootUser:   true,
			AllowedCommands: [][]string{{"/usr/local/bin/deploy", "--check"}},
			AllowedEnvVars:  []string{"PATH", "HOME"},
			DeniedEnvVars:   []string{"LD_PRELOAD", "LD_LIBRARY_PATH"},
		},
		ImagePull: ImagePullRequestBodyConfig{
			AllowImports:       true,
			AllowAllRegistries: true,
			AllowOfficial:      false,
			AllowedRegistries:  []string{"ghcr.io", "registry.example.com:5000"},
		},
		Build: BuildRequestBodyConfig{
			AllowRemoteContext:   true,
			AllowHostNetwork:     true,
			AllowRunInstructions: true,
		},
		ContainerUpdate: ContainerUpdateRequestBodyConfig{
			AllowPrivileged:      true,
			AllowAllDevices:      true,
			AllowCapabilities:    true,
			AllowResourceUpdates: true,
			AllowRestartPolicy:   true,
		},
		ContainerArchive: ContainerArchiveRequestBodyConfig{
			AllowedPaths:       []string{"/tmp/uploads", "/var/lib/app"},
			AllowSetID:         true,
			AllowDeviceNodes:   true,
			AllowEscapingLinks: true,
		},
		ImageLoad: ImageLoadRequestBodyConfig{
			AllowAllRegistries: true,
			AllowOfficial:      false,
			AllowedRegistries:  []string{"registry.example.com"},
			AllowUntagged:      true,
		},
		Volume: VolumeRequestBodyConfig{
			AllowCustomDrivers: true,
			AllowDriverOpts:    true,
		},
		Network: NetworkRequestBodyConfig{
			AllowCustomDrivers:     true,
			AllowSwarmScope:        true,
			AllowIngress:           true,
			AllowAttachable:        true,
			AllowConfigOnly:        true,
			AllowConfigFrom:        true,
			AllowCustomIPAMDrivers: true,
			AllowCustomIPAMConfig:  true,
			AllowIPAMOptions:       true,
			AllowDriverOptions:     true,
			AllowEndpointConfig:    true,
			AllowDisconnectForce:   true,
		},
		Secret: SecretRequestBodyConfig{
			AllowCustomDrivers:   true,
			AllowTemplateDrivers: true,
		},
		Config: ConfigRequestBodyConfig{
			AllowCustomDrivers:   true,
			AllowTemplateDrivers: true,
		},
		Service: ServiceRequestBodyConfig{
			AllowHostNetwork:           true,
			AllowedBindMounts:          []string{"/srv/services"},
			AllowAllRegistries:         true,
			AllowOfficial:              false,
			AllowedRegistries:          []string{"registry.example.com"},
			RequireNonRootUser:         true,
			RequireNoNewPrivileges:     true,
			RequireReadonlyRootfs:      true,
			RequireDropAllCapabilities: true,
			DenyUnconfinedSeccomp:      true,
			DenyCustomSeccompProfiles:  true,
			DenyUnconfinedAppArmor:     true,
		},
		Swarm: SwarmRequestBodyConfig{
			AllowForceNewCluster:          true,
			AllowExternalCA:               true,
			AllowedJoinRemoteAddrs:        []string{"manager.internal:2377"},
			AllowTokenRotation:            true,
			AllowManagerUnlockKeyRotation: true,
			AllowAutoLockManagers:         true,
			AllowSigningCAUpdate:          true,
			AllowUnlock:                   true,
		},
		Node: NodeRequestBodyConfig{
			AllowNameChange:         true,
			AllowRoleChange:         true,
			AllowAvailabilityChange: true,
			AllowLabelMutation:      true,
			AllowedLabelKeys:        []string{"com.example.safe"},
		},
		Plugin: PluginRequestBodyConfig{
			AllowHostNetwork:      true,
			AllowHostIPC:          true,
			AllowHostPID:          true,
			AllowAllDevices:       true,
			AllowedBindMounts:     []string{"/var/lib/plugins"},
			AllowedDevices:        []string{"/dev/fuse"},
			AllowAllCapabilities:  true,
			AllowedCapabilities:   []string{"CAP_SYS_ADMIN"},
			AllowAllRegistries:    true,
			AllowOfficial:         false,
			AllowedRegistries:     []string{"plugins.example.com"},
			AllowedSetEnvPrefixes: []string{"DEBUG=", "LOG_LEVEL="},
		},
	}

	got := cfg.ToFilterOptions()
	want := filter.PolicyConfig{
		ContainerCreate: filter.ContainerCreateOptions{
			AllowPrivileged:                   true,
			AllowHostNetwork:                  true,
			AllowHostPID:                      true,
			AllowHostIPC:                      true,
			AllowedBindMounts:                 []string{"/srv/data", "/var/lib/sockguard"},
			AllowAllDevices:                   true,
			AllowedDevices:                    []string{"/dev/kvm", "/dev/dri"},
			AllowDeviceRequests:               true,
			AllowDeviceCgroupRules:            true,
			RestrictNamespaceSharing:          true,
			AllowedNamespaceSharingContainers: []string{"sidecar", "abc123"},
			DenyNamespacePathMode:             true,
		},
		Exec: filter.ExecOptions{
			AllowPrivileged: true,
			AllowRootUser:   true,
			AllowedCommands: [][]string{{"/usr/local/bin/deploy", "--check"}},
			AllowedEnvVars:  []string{"PATH", "HOME"},
			DeniedEnvVars:   []string{"LD_PRELOAD", "LD_LIBRARY_PATH"},
		},
		ImagePull: filter.ImagePullOptions{
			AllowImports:       true,
			AllowAllRegistries: true,
			AllowOfficial:      false,
			AllowedRegistries:  []string{"ghcr.io", "registry.example.com:5000"},
		},
		Build: filter.BuildOptions{
			AllowRemoteContext:   true,
			AllowHostNetwork:     true,
			AllowRunInstructions: true,
		},
		ContainerUpdate: filter.ContainerUpdateOptions{
			AllowPrivileged:      true,
			AllowAllDevices:      true,
			AllowCapabilities:    true,
			AllowResourceUpdates: true,
			AllowRestartPolicy:   true,
		},
		ContainerArchive: filter.ContainerArchiveOptions{
			AllowedPaths:       []string{"/tmp/uploads", "/var/lib/app"},
			AllowSetID:         true,
			AllowDeviceNodes:   true,
			AllowEscapingLinks: true,
		},
		ImageLoad: filter.ImageLoadOptions{
			AllowAllRegistries: true,
			AllowOfficial:      false,
			AllowedRegistries:  []string{"registry.example.com"},
			AllowUntagged:      true,
		},
		Volume: filter.VolumeOptions{
			AllowCustomDrivers: true,
			AllowDriverOpts:    true,
		},
		Network: filter.NetworkOptions{
			AllowCustomDrivers:     true,
			AllowSwarmScope:        true,
			AllowIngress:           true,
			AllowAttachable:        true,
			AllowConfigOnly:        true,
			AllowConfigFrom:        true,
			AllowCustomIPAMDrivers: true,
			AllowCustomIPAMConfig:  true,
			AllowIPAMOptions:       true,
			AllowDriverOptions:     true,
			AllowEndpointConfig:    true,
			AllowDisconnectForce:   true,
		},
		Secret: filter.SecretOptions{
			AllowCustomDrivers:   true,
			AllowTemplateDrivers: true,
		},
		Config: filter.ConfigOptions{
			AllowCustomDrivers:   true,
			AllowTemplateDrivers: true,
		},
		Service: filter.ServiceOptions{
			AllowHostNetwork:           true,
			AllowedBindMounts:          []string{"/srv/services"},
			AllowAllRegistries:         true,
			AllowOfficial:              false,
			AllowedRegistries:          []string{"registry.example.com"},
			RequireNonRootUser:         true,
			RequireNoNewPrivileges:     true,
			RequireReadonlyRootfs:      true,
			RequireDropAllCapabilities: true,
			DenyUnconfinedSeccomp:      true,
			DenyCustomSeccompProfiles:  true,
			DenyUnconfinedAppArmor:     true,
		},
		Swarm: filter.SwarmOptions{
			AllowForceNewCluster:          true,
			AllowExternalCA:               true,
			AllowedJoinRemoteAddrs:        []string{"manager.internal:2377"},
			AllowTokenRotation:            true,
			AllowManagerUnlockKeyRotation: true,
			AllowAutoLockManagers:         true,
			AllowSigningCAUpdate:          true,
			AllowUnlock:                   true,
		},
		Node: filter.NodeOptions{
			AllowNameChange:         true,
			AllowRoleChange:         true,
			AllowAvailabilityChange: true,
			AllowLabelMutation:      true,
			AllowedLabelKeys:        []string{"com.example.safe"},
		},
		Plugin: filter.PluginOptions{
			AllowHostNetwork:      true,
			AllowHostIPC:          true,
			AllowHostPID:          true,
			AllowAllDevices:       true,
			AllowedBindMounts:     []string{"/var/lib/plugins"},
			AllowedDevices:        []string{"/dev/fuse"},
			AllowAllCapabilities:  true,
			AllowedCapabilities:   []string{"CAP_SYS_ADMIN"},
			AllowAllRegistries:    true,
			AllowOfficial:         false,
			AllowedRegistries:     []string{"plugins.example.com"},
			AllowedSetEnvPrefixes: []string{"DEBUG=", "LOG_LEVEL="},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RequestBodyConfig.ToFilterOptions() = %#v, want %#v", got, want)
	}
}

func TestContainerCreateRequestBodyConfigToFilterOptionsMapsSelinuxAndSystemPaths(t *testing.T) {
	cfg := ContainerCreateRequestBodyConfig{
		DenySelinuxDisable:        true,
		DenySelinuxLabelOverride:  true,
		DenyUnconfinedSystemPaths: true,
	}
	got := cfg.ToFilterOptions()
	if !got.DenySelinuxDisable {
		t.Error("DenySelinuxDisable not propagated")
	}
	if !got.DenySelinuxLabelOverride {
		t.Error("DenySelinuxLabelOverride not propagated")
	}
	if !got.DenyUnconfinedSystemPaths {
		t.Error("DenyUnconfinedSystemPaths not propagated")
	}
}

func TestContainerCreateRequestBodyConfigToFilterOptionsMapsRequireCPULimitHard(t *testing.T) {
	got := (ContainerCreateRequestBodyConfig{
		RequireCPULimitHard: true,
	}).ToFilterOptions()
	if !got.RequireCPULimitHard {
		t.Error("RequireCPULimitHard not propagated")
	}
}

func TestExecRequestBodyConfigToFilterOptionsLeavesRuntimeInspectorUnset(t *testing.T) {
	got := (ExecRequestBodyConfig{
		AllowPrivileged: true,
		AllowRootUser:   true,
		AllowedCommands: [][]string{{"/bin/sh", "-c", "id"}},
	}).ToFilterOptions()

	if got.InspectStart != nil {
		t.Fatal("ExecRequestBodyConfig.ToFilterOptions().InspectStart is set, want nil")
	}
}

func TestExecRequestBodyConfigToFilterOptionsMapsEnvAllowlists(t *testing.T) {
	got := (ExecRequestBodyConfig{
		AllowedEnvVars: []string{"PATH", "HOME"},
		DeniedEnvVars:  []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PATH", "PYTHONPATH"},
	}).ToFilterOptions()

	if want := []string{"PATH", "HOME"}; !reflect.DeepEqual(got.AllowedEnvVars, want) {
		t.Fatalf("AllowedEnvVars = %#v, want %#v", got.AllowedEnvVars, want)
	}
	if want := []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PATH", "PYTHONPATH"}; !reflect.DeepEqual(got.DeniedEnvVars, want) {
		t.Fatalf("DeniedEnvVars = %#v, want %#v", got.DeniedEnvVars, want)
	}
}
