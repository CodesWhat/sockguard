package filter

import (
	"encoding/json"
	"slices"
)

// legacyRootHostConfigKeys is every field name of moby 26.1.5's HostConfig and
// its embedded Resources, plus the legacy Cpuset, spelled as the engine
// decodes it from JSON (api/types/container/hostconfig.go,
// api/types/container/config.go, runconfig/config_unix.go).
//
// Docker 24.x through 26.x decode POST /containers/create into
// ContainerConfigWrapper, which embeds *HostConfig next to the nested
// "HostConfig" object. A body with no nested HostConfig, or a null one, has the
// engine read these fields from the top level of the body instead, and
// sockguard only ever inspects the nested object. The embedding was removed in
// Docker 27.0.1, and Podman never read it. None of these names is a field of
// container.Config, so no legitimate create body carries one at the top level.
var legacyRootHostConfigKeys = []string{
	// HostConfig
	"Binds", "ContainerIDFile", "LogConfig", "NetworkMode", "PortBindings",
	"RestartPolicy", "AutoRemove", "VolumeDriver", "VolumesFrom", "ConsoleSize",
	"Annotations", "CapAdd", "CapDrop", "CgroupnsMode", "Dns", "DnsOptions",
	"DnsSearch", "ExtraHosts", "GroupAdd", "IpcMode", "Cgroup", "Links",
	"OomScoreAdj", "PidMode", "Privileged", "PublishAllPorts", "ReadonlyRootfs",
	"SecurityOpt", "StorageOpt", "Tmpfs", "UTSMode", "UsernsMode", "ShmSize",
	"Sysctls", "Runtime", "Isolation", "Mounts", "MaskedPaths", "ReadonlyPaths",
	"Init", "Capabilities",
	// Resources, embedded in HostConfig
	"CpuShares", "Memory", "NanoCpus", "CgroupParent", "BlkioWeight",
	"BlkioWeightDevice", "BlkioDeviceReadBps", "BlkioDeviceWriteBps",
	"BlkioDeviceReadIOps", "BlkioDeviceWriteIOps", "CpuPeriod", "CpuQuota",
	"CpuRealtimePeriod", "CpuRealtimeRuntime", "CpusetCpus", "CpusetMems",
	"Devices", "DeviceCgroupRules", "DeviceRequests", "KernelMemory",
	"KernelMemoryTCP", "MemoryReservation", "MemorySwap", "MemorySwappiness",
	"OomKillDisable", "PidsLimit", "Ulimits", "CpuCount", "CpuPercent",
	"IOMaximumIOps", "IOMaximumBandwidth",
	// ContainerConfigWrapper
	"Cpuset",
}

// legacyRootHostConfigKeySet is legacyRootHostConfigKeys under the fold
// both daemons' JSON decoders apply to object keys.
var legacyRootHostConfigKeySet = func() map[string]string {
	set := make(map[string]string, len(legacyRootHostConfigKeys))
	for _, key := range legacyRootHostConfigKeys {
		set[canonicalFoldKey(key)] = key
	}
	return set
}()

// denyLegacyRootHostConfigReason refuses a create body that carries a
// HostConfig or Resources field at its top level. The check reads the decoded
// keys of the body's root object, so an escaped spelling ("Privileged")
// and any letter case are caught the way the engine's own decoder would match
// them. A body that is not a JSON object is left for the struct decode to
// reject as malformed. Keys are visited in sorted order so the reason is
// stable.
func denyLegacyRootHostConfigReason(body []byte) string {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return ""
	}
	keys := make([]string, 0, len(root))
	for key := range root {
		if _, legacy := legacyRootHostConfigKeySet[canonicalFoldKey(key)]; legacy {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	slices.Sort(keys)
	return "container create denied: HostConfig field " + quoteJSONKey(keys[0]) + " at the top level of the body is not allowed (nest it under HostConfig)"
}

func quoteJSONKey(key string) string {
	quoted, err := json.Marshal(key)
	if err != nil {
		return `"?"`
	}
	return string(quoted)
}
