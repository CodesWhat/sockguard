package config

import (
	"reflect"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/filter"
)

func TestRequestBodyConfigToFilterOptionsMapsEveryPolicy(t *testing.T) {
	cfg := RequestBodyConfig{
		ContainerCreate: ContainerCreateRequestBodyConfig{
			AllowPrivileged:                   true,
			AllowHostNetwork:                  true,
			AllowHostPID:                      true,
			AllowHostIPC:                      true,
			AllowHostUserNS:                   true,
			AllowHostCgroupNS:                 true,
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
			AllowPrivileged:  true,
			AllowRootUser:    true,
			AllowedCommands:  [][]string{{"/usr/local/bin/deploy", "--check"}},
			AllowedEnvVars:   []string{"PATH", "HOME"},
			DeniedEnvVars:    []string{"LD_PRELOAD", "LD_LIBRARY_PATH"},
			AllowedEnvValues: []string{"CALLBACK_URL=http://127.0.0.1:3000/callback"},
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
		ContainerRemove: ContainerRemoveRequestBodyConfig{
			AllowForce:         true,
			AllowRemoveVolumes: true,
			AllowRemoveLinks:   true,
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
			EndpointConfig: EndpointConfigRequestBodyConfig{
				AllowStaticAddressing: true,
				AllowLinkLocalIPs:     true,
				AllowMACPinning:       true,
				AllowGwPriority:       true,
				AllowAliases:          true,
			},
			AllowDisconnectForce: true,
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
		// LibpodNetwork.EndpointConfig.AllowAliases is set here purely so its
		// ToFilterOptions() inversion (DenyAliases) matches the implicit
		// filter.NetworkOptions{} zero value in want below — LibpodNetwork is
		// otherwise untested here since libpod_network.go never consults
		// EndpointConfig (no libpod-native network-connect endpoint exists).
		LibpodNetwork: NetworkRequestBodyConfig{
			EndpointConfig: EndpointConfigRequestBodyConfig{AllowAliases: true},
		},
	}

	got := cfg.ToFilterOptions()
	want := filter.PolicyConfig{
		ContainerCreate: filter.ContainerCreateOptions{
			AllowPrivileged:                   true,
			AllowHostNetwork:                  true,
			AllowHostPID:                      true,
			AllowHostIPC:                      true,
			AllowHostUserNS:                   true,
			AllowHostCgroupNS:                 true,
			AllowedBindMounts:                 []string{"/srv/data", "/var/lib/sockguard"},
			AllowAllDevices:                   true,
			AllowedDevices:                    []string{"/dev/kvm", "/dev/dri"},
			AllowDeviceRequests:               true,
			AllowDeviceCgroupRules:            true,
			RestrictNamespaceSharing:          true,
			AllowedNamespaceSharingContainers: []string{"sidecar", "abc123"},
			DenyNamespacePathMode:             true,
			// AllowEndpointConfig and EndpointConfig have no
			// ContainerCreateRequestBodyConfig field of their own — both are
			// cross-wired from cfg.Network.AllowEndpointConfig/EndpointConfig
			// (set above) by RequestBodyConfig.ToFilterOptions. See
			// TestRequestBodyConfigToFilterOptionsWiresNetworkAllowEndpointConfigIntoContainerCreate
			// for a focused regression on that cross-wire alone.
			AllowEndpointConfig: true,
			EndpointConfig: filter.EndpointConfigOptions{
				AllowStaticAddressing: true,
				AllowLinkLocalIPs:     true,
				AllowMACPinning:       true,
				AllowGwPriority:       true,
				DenyAliases:           false,
			},
		},
		Exec: filter.ExecOptions{
			AllowPrivileged:  true,
			AllowRootUser:    true,
			AllowedCommands:  [][]string{{"/usr/local/bin/deploy", "--check"}},
			AllowedEnvVars:   []string{"PATH", "HOME"},
			DeniedEnvVars:    []string{"LD_PRELOAD", "LD_LIBRARY_PATH"},
			AllowedEnvValues: []string{"CALLBACK_URL=http://127.0.0.1:3000/callback"},
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
		ContainerRemove: filter.ContainerRemoveOptions{
			AllowForce:         true,
			AllowRemoveVolumes: true,
			AllowRemoveLinks:   true,
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
			// AllowedBindMounts has no VolumeRequestBodyConfig field of its
			// own — it is cross-wired from cfg.ContainerCreate.AllowedBindMounts
			// (set above) by RequestBodyConfig.ToFilterOptions. See
			// TestRequestBodyConfigToFilterOptionsWiresAllowedBindMountsIntoVolume
			// for a focused regression on that cross-wire alone.
			AllowedBindMounts: []string{"/srv/data", "/var/lib/sockguard"},
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
			EndpointConfig: filter.EndpointConfigOptions{
				AllowStaticAddressing: true,
				AllowLinkLocalIPs:     true,
				AllowMACPinning:       true,
				AllowGwPriority:       true,
				DenyAliases:           false,
			},
			AllowDisconnectForce: true,
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

// TestRequestBodyConfigToFilterOptionsWiresNetworkAllowEndpointConfigIntoContainerCreate
// proves request_body.network.allow_endpoint_config is the single flag
// governing both endpoint-config inspectors: RequestBodyConfig.ToFilterOptions
// must copy it into both filter.NetworkOptions.AllowEndpointConfig (the
// existing /networks/*/connect gate) and filter.ContainerCreateOptions.AllowEndpointConfig
// (the new /containers/create NetworkingConfig gate), with no separate
// container_create YAML key of its own.
func TestRequestBodyConfigToFilterOptionsWiresNetworkAllowEndpointConfigIntoContainerCreate(t *testing.T) {
	t.Run("true flows into both policies", func(t *testing.T) {
		got := (RequestBodyConfig{
			Network: NetworkRequestBodyConfig{AllowEndpointConfig: true},
		}).ToFilterOptions()

		if !got.Network.AllowEndpointConfig {
			t.Error("Network.AllowEndpointConfig = false, want true")
		}
		if !got.ContainerCreate.AllowEndpointConfig {
			t.Error("ContainerCreate.AllowEndpointConfig = false, want true (cross-wired from Network)")
		}
	})

	t.Run("false (default) leaves both policies denying", func(t *testing.T) {
		got := (RequestBodyConfig{}).ToFilterOptions()

		if got.Network.AllowEndpointConfig {
			t.Error("Network.AllowEndpointConfig = true, want false")
		}
		if got.ContainerCreate.AllowEndpointConfig {
			t.Error("ContainerCreate.AllowEndpointConfig = true, want false")
		}
	})
}

// TestRequestBodyConfigToFilterOptionsWiresAllowedBindMountsIntoVolume proves
// the bind-mount allowlist is one list, not two: a local-driver volume whose
// options ask for a bind reaches the same host path a HostConfig.Binds entry
// reaches, so RequestBodyConfig.ToFilterOptions must copy
// container_create.allowed_bind_mounts into filter.VolumeOptions and
// libpod_container_create.allowed_bind_mounts into the libpod volume policy,
// with no allowed_bind_mounts key of their own and no leakage across the two
// API families.
func TestRequestBodyConfigToFilterOptionsWiresAllowedBindMountsIntoVolume(t *testing.T) {
	got := (RequestBodyConfig{
		ContainerCreate: ContainerCreateRequestBodyConfig{
			AllowedBindMounts: []string{"/srv/data"},
		},
		LibpodContainerCreate: LibpodContainerCreateRequestBodyConfig{
			AllowedBindMounts: []string{"/srv/podman"},
		},
	}).ToFilterOptions()

	if want := []string{"/srv/data"}; !reflect.DeepEqual(got.Volume.AllowedBindMounts, want) {
		t.Errorf("Volume.AllowedBindMounts = %#v, want %#v (cross-wired from ContainerCreate)", got.Volume.AllowedBindMounts, want)
	}
	if want := []string{"/srv/podman"}; !reflect.DeepEqual(got.LibpodVolume.AllowedBindMounts, want) {
		t.Errorf("LibpodVolume.AllowedBindMounts = %#v, want %#v (cross-wired from LibpodContainerCreate)", got.LibpodVolume.AllowedBindMounts, want)
	}
}

// TestRequestBodyConfigToFilterOptionsWiresNetworkEndpointConfigIntoContainerCreate
// is TestRequestBodyConfigToFilterOptionsWiresNetworkAllowEndpointConfigIntoContainerCreate's
// #186 counterpart: proves the granular endpoint_config block cross-wires
// into both filter.NetworkOptions.EndpointConfig and
// filter.ContainerCreateOptions.EndpointConfig from the single
// request_body.network.endpoint_config block, with AllowAliases inverted to
// DenyAliases on the way out.
func TestRequestBodyConfigToFilterOptionsWiresNetworkEndpointConfigIntoContainerCreate(t *testing.T) {
	got := (RequestBodyConfig{
		Network: NetworkRequestBodyConfig{
			EndpointConfig: EndpointConfigRequestBodyConfig{
				AllowStaticAddressing: true,
				AllowLinkLocalIPs:     true,
				AllowMACPinning:       true,
				AllowGwPriority:       true,
				AllowAliases:          false,
			},
		},
	}).ToFilterOptions()

	want := filter.EndpointConfigOptions{
		AllowStaticAddressing: true,
		AllowLinkLocalIPs:     true,
		AllowMACPinning:       true,
		AllowGwPriority:       true,
		DenyAliases:           true,
	}
	if !reflect.DeepEqual(got.Network.EndpointConfig, want) {
		t.Errorf("Network.EndpointConfig = %#v, want %#v", got.Network.EndpointConfig, want)
	}
	if !reflect.DeepEqual(got.ContainerCreate.EndpointConfig, want) {
		t.Errorf("ContainerCreate.EndpointConfig = %#v, want %#v (cross-wired from Network)", got.ContainerCreate.EndpointConfig, want)
	}
}

func TestRequestBodyConfigToFilterOptionsMapsLibpodNetworkPolicy(t *testing.T) {
	t.Run("maps every native field independently from Docker policy", func(t *testing.T) {
		got := (RequestBodyConfig{
			Network: NetworkRequestBodyConfig{
				AllowSwarmScope: true,
			},
			LibpodNetwork: NetworkRequestBodyConfig{
				AllowCustomDrivers:    true,
				AllowAttachable:       true,
				AllowCustomIPAMConfig: true,
				AllowIPAMOptions:      true,
				AllowDriverOptions:    true,
				AllowEndpointConfig:   true,
				AllowDisconnectForce:  true,
				AllowDisableIPv4:      true,
				AllowDNSServers:       true,
			},
		}).ToFilterOptions()

		want := filter.NetworkOptions{
			AllowCustomDrivers:    true,
			AllowAttachable:       true,
			AllowCustomIPAMConfig: true,
			AllowIPAMOptions:      true,
			AllowDriverOptions:    true,
			AllowEndpointConfig:   true,
			EndpointConfig: filter.EndpointConfigOptions{
				DenyAliases: true,
			},
			AllowDisconnectForce: true,
			AllowDisableIPv4:     true,
			AllowDNSServers:      true,
		}
		if !reflect.DeepEqual(got.LibpodNetwork, want) {
			t.Fatalf("LibpodNetwork = %#v, want %#v", got.LibpodNetwork, want)
		}
		if !got.Network.AllowSwarmScope {
			t.Fatal("Network.AllowSwarmScope = false, want Docker policy preserved independently")
		}
		if got.LibpodNetwork.AllowSwarmScope {
			t.Fatal("LibpodNetwork.AllowSwarmScope = true, want no cross-wire from Docker policy")
		}
	})

	t.Run("maps granular endpoint config and inverts aliases", func(t *testing.T) {
		got := (RequestBodyConfig{
			LibpodNetwork: NetworkRequestBodyConfig{
				EndpointConfig: EndpointConfigRequestBodyConfig{
					AllowStaticAddressing: true,
					AllowLinkLocalIPs:     true,
					AllowMACPinning:       true,
					AllowGwPriority:       true,
					AllowAliases:          false,
				},
			},
		}).ToFilterOptions()

		want := filter.EndpointConfigOptions{
			AllowStaticAddressing: true,
			AllowLinkLocalIPs:     true,
			AllowMACPinning:       true,
			AllowGwPriority:       true,
			DenyAliases:           true,
		}
		if !reflect.DeepEqual(got.LibpodNetwork.EndpointConfig, want) {
			t.Fatalf("LibpodNetwork.EndpointConfig = %#v, want %#v", got.LibpodNetwork.EndpointConfig, want)
		}
		if reflect.DeepEqual(got.Network.EndpointConfig, want) {
			t.Fatal("Network.EndpointConfig inherited the libpod-native policy")
		}
	})
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
		AllowedEnvVars:   []string{"PATH", "HOME"},
		DeniedEnvVars:    []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PATH", "PYTHONPATH"},
		AllowedEnvValues: []string{"CALLBACK_URL=http://127.0.0.1:3000/callback"},
	}).ToFilterOptions()

	if want := []string{"PATH", "HOME"}; !reflect.DeepEqual(got.AllowedEnvVars, want) {
		t.Fatalf("AllowedEnvVars = %#v, want %#v", got.AllowedEnvVars, want)
	}
	if want := []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PATH", "PYTHONPATH"}; !reflect.DeepEqual(got.DeniedEnvVars, want) {
		t.Fatalf("DeniedEnvVars = %#v, want %#v", got.DeniedEnvVars, want)
	}
	if want := []string{"CALLBACK_URL=http://127.0.0.1:3000/callback"}; !reflect.DeepEqual(got.AllowedEnvValues, want) {
		t.Fatalf("AllowedEnvValues = %#v, want %#v", got.AllowedEnvValues, want)
	}
}
