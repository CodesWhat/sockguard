package filter_test

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

// watchtowerContainerCreateBody is the representative JSON emitted by Moby
// client v0.5.1 for a recreated container whose modern-API endpoint was copied
// by Watchtower v1.21.2's processEndpoint. The copied operational IPAddress is
// always present; a user-configured MacAddress survives when it is not the
// engine-generated address derived from that IP.
const watchtowerContainerCreateBody = `{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":null,"Cmd":null,"Image":"nginx","Volumes":null,"WorkingDir":"","Entrypoint":null,"Labels":null,"HostConfig":{"Binds":null,"ContainerIDFile":"","LogConfig":{"Type":"","Config":null},"NetworkMode":"","PortBindings":null,"RestartPolicy":{"Name":"","MaximumRetryCount":0},"AutoRemove":false,"VolumeDriver":"","VolumesFrom":null,"ConsoleSize":[0,0],"CapAdd":null,"CapDrop":null,"CgroupnsMode":"","Dns":null,"DnsOptions":null,"DnsSearch":null,"ExtraHosts":null,"GroupAdd":null,"IpcMode":"","Cgroup":"","Links":null,"OomScoreAdj":0,"PidMode":"","Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":false,"SecurityOpt":null,"UTSMode":"","UsernsMode":"","ShmSize":0,"Runtime":"runc","Isolation":"","CpuShares":0,"Memory":0,"NanoCpus":0,"CgroupParent":"","BlkioWeight":0,"BlkioWeightDevice":null,"BlkioDeviceReadBps":null,"BlkioDeviceWriteBps":null,"BlkioDeviceReadIOps":null,"BlkioDeviceWriteIOps":null,"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpusetCpus":"","CpusetMems":"","Devices":null,"DeviceCgroupRules":null,"DeviceRequests":null,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":null,"OomKillDisable":null,"PidsLimit":null,"Ulimits":null,"CpuCount":0,"CpuPercent":0,"IOMaximumIOps":0,"IOMaximumBandwidth":0,"MaskedPaths":null,"ReadonlyPaths":null},"NetworkingConfig":{"EndpointsConfig":{"app-net":{"IPAMConfig":null,"Links":null,"Aliases":["watchtower-app"],"DriverOpts":null,"GwPriority":0,"NetworkID":"0123456789abcdef","EndpointID":"abcdef0123456789","Gateway":"172.20.0.1","IPAddress":"172.20.0.10","MacAddress":"02:42:de:ad:be:ef","IPPrefixLen":16,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"DNSNames":["watchtower-app","app"]}}}}`

// watchtowerNoRestartUpdateBody is the exact Moby client v0.5.1 JSON for
// ContainerUpdateOptions{RestartPolicy: &RestartPolicy{Name: "no"}}. Its
// embedded Resources fields are serialized even though Watchtower did not
// request a resource update.
const watchtowerNoRestartUpdateBody = `{"CpuShares":0,"Memory":0,"NanoCpus":0,"CgroupParent":"","BlkioWeight":0,"BlkioWeightDevice":null,"BlkioDeviceReadBps":null,"BlkioDeviceWriteBps":null,"BlkioDeviceReadIOps":null,"BlkioDeviceWriteIOps":null,"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpusetCpus":"","CpusetMems":"","Devices":null,"DeviceCgroupRules":null,"DeviceRequests":null,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":null,"OomKillDisable":null,"PidsLimit":null,"Ulimits":null,"CpuCount":0,"CpuPercent":0,"IOMaximumIOps":0,"IOMaximumBandwidth":0,"RestartPolicy":{"Name":"no","MaximumRetryCount":0}}`

// TestWatchtowerPresetConformance pins the Docker Engine API surface used by
// nicholas-fedor/watchtower v1.21.2. Watchtower's pkg/container package calls
// the Moby client for ping, info, container list/inspect/lifecycle/create,
// lifecycle-hook exec, image inspect/pull/remove and network connect. It does
// not list images or read the broad container, network, volume or distribution
// families the old preset globs admitted.
//
// The handler reuses the #379 preset helpers. Exec start is the one route whose
// production inspector needs a daemon lookup, so the shared policy hook supplies
// the immutable command metadata that Watchtower's preceding ExecCreate stored.
func TestWatchtowerPresetConformance(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "watchtower.yaml"))
	if err != nil {
		t.Fatalf("load preset watchtower.yaml: %v", err)
	}
	if !cfg.InsecureAllowBodyBlindWrites {
		t.Error("watchtower.yaml must acknowledge arbitrary lifecycle-hook exec commands")
	}
	if cfg.InsecureAllowReadExfiltration {
		t.Error("watchtower.yaml must not acknowledge read exfiltration; Watchtower uses no exfiltration route")
	}
	if cfg.RequestBody.Network.AllowEndpointConfig {
		t.Error("watchtower.yaml must not allow the whole endpoint config")
	}
	endpointConfig := cfg.RequestBody.Network.EndpointConfig
	if !endpointConfig.AllowStaticAddressing || !endpointConfig.AllowMACPinning {
		t.Errorf("watchtower endpoint config = %#v, want only copied static addressing and MAC pinning allowed", endpointConfig)
	}
	if endpointConfig.AllowLinkLocalIPs || endpointConfig.AllowGwPriority || !endpointConfig.AllowAliases {
		t.Errorf("watchtower endpoint config = %#v, want unrelated endpoint controls unchanged", endpointConfig)
	}
	if cfg.RequestBody.ContainerUpdate.AllowResourceUpdates {
		t.Error("watchtower.yaml must not allow resource updates")
	}

	handler := drydockPresetHandlerFromConfig(t, cfg, func(policy *filter.PolicyConfig) {
		policy.Exec.InspectStart = func(context.Context, string) (filter.ExecInspectResult, bool, error) {
			return filter.ExecInspectResult{
				Command: []string{"sh", "-c", "lifecycle hook"},
				User:    "",
			}, true, nil
		}
	})

	cases := []presetCase{
		// Moby client connection setup and mirror discovery.
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"ping-get-fallback", http.MethodGet, "/_ping", "", true},
		{"info", http.MethodGet, "/info", "", true},

		// Container discovery and lifecycle.
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-start", http.MethodPost, "/containers/abc/start", "", true},
		{"container-stop", http.MethodPost, "/containers/abc/stop", "", true},
		{"container-rename", http.MethodPost, "/containers/abc/rename", "", true},
		{"container-remove", http.MethodDelete, "/containers/abc", "", true},

		// Watchtower recreates inspected containers with the stock runtime. A
		// different explicit runtime must not pass the same create rule.
		{"container-create-copied-endpoint", http.MethodPost, "/containers/create", watchtowerContainerCreateBody, true},
		{"container-create-other-runtime-denied", http.MethodPost, "/containers/create", `{"Image":"nginx","HostConfig":{"Runtime":"kata"}}`, false},
		{"container-create-endpoint-links-denied", http.MethodPost, "/containers/create", strings.Replace(watchtowerContainerCreateBody, `"IPAMConfig":null,"Links":null`, `"IPAMConfig":null,"Links":["db:database"]`, 1), false},
		{"container-create-endpoint-driver-options-denied", http.MethodPost, "/containers/create", strings.Replace(watchtowerContainerCreateBody, `"DriverOpts":null`, `"DriverOpts":{"com.example":"value"}`, 1), false},

		// Moby embeds a zero-valued Resources in Watchtower's restart-only
		// update. Those daemon no-ops pass, while a one-field mutation remains
		// denied without allow_resource_updates.
		{"container-update-no-restart", http.MethodPost, "/containers/abc/update", watchtowerNoRestartUpdateBody, true},
		{"container-update-memory-denied", http.MethodPost, "/containers/abc/update", strings.Replace(watchtowerNoRestartUpdateBody, `"Memory":0`, `"Memory":1`, 1), false},
		{"container-update-cpu-denied", http.MethodPost, "/containers/abc/update", strings.Replace(watchtowerNoRestartUpdateBody, `"NanoCpus":0`, `"NanoCpus":2000000000`, 1), false},
		{"container-update-pids-clear-denied", http.MethodPost, "/containers/abc/update", strings.Replace(watchtowerNoRestartUpdateBody, `"PidsLimit":null`, `"PidsLimit":0`, 1), false},

		// Lifecycle-hook exec. Watchtower leaves User empty to use the
		// container's configured user, which Sockguard conservatively treats as
		// root, and sends arbitrary sh -c commands plus WT_CONTAINER metadata.
		{"exec-create", http.MethodPost, "/containers/abc/exec", `{"Tty":true,"Cmd":["sh","-c","lifecycle hook"],"Env":["WT_CONTAINER={}"]}`, true},
		{"exec-start", http.MethodPost, "/exec/def/start", `{"Detach":true,"Tty":true}`, true},
		{"exec-inspect", http.MethodGet, "/exec/def/json", "", true},

		// Image inspect accepts registry-qualified names, but image list must be
		// denied explicitly because Watchtower never calls ImageList.
		{"image-inspect-id", http.MethodGet, "/images/sha256:abc/json", "", true},
		{"image-inspect-qualified", http.MethodGet, "/images/ghcr.io/example/app:latest/json", "", true},
		{"image-pull", http.MethodPost, "/images/create?fromImage=ghcr.io/example/app&tag=latest", "", true},
		{"image-remove", http.MethodDelete, "/images/sha256:abc", "", true},
		{"images-list-explicitly-denied", http.MethodGet, "/images/json", "", false},

		// Recreate attaches secondary networks but does not read or mutate the
		// network collection otherwise.
		{"network-connect", http.MethodPost, "/networks/net1/connect", `{"Container":"abc"}`, true},

		// Version prefixes normalize before matching.
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json", "", true},
		{"v-prefixed-container-update", http.MethodPost, "/v1.45/containers/abc/update", watchtowerNoRestartUpdateBody, true},
		{"v-prefixed-image-inspect", http.MethodGet, "/v1.45/images/ghcr.io/example/app:latest/json", "", true},
		{"v-prefixed-network-connect", http.MethodPost, "/v1.45/networks/net1/connect", `{"Container":"abc"}`, true},

		// Metadata Watchtower does not call.
		{"version-denied", http.MethodGet, "/version", "", false},
		{"events-denied", http.MethodGet, "/events", "", false},
		{"system-df-denied", http.MethodGet, "/system/df", "", false},

		// Unused container reads and lifecycle operations.
		{"container-stats-denied", http.MethodGet, "/containers/abc/stats", "", false},
		{"container-top-denied", http.MethodGet, "/containers/abc/top", "", false},
		{"container-changes-denied", http.MethodGet, "/containers/abc/changes", "", false},
		{"container-restart-denied", http.MethodPost, "/containers/abc/restart", "", false},
		{"container-kill-denied", http.MethodPost, "/containers/abc/kill", "", false},
		{"container-wait-denied", http.MethodPost, "/containers/abc/wait", "", false},
		{"container-pause-denied", http.MethodPost, "/containers/abc/pause", "", false},
		{"container-unpause-denied", http.MethodPost, "/containers/abc/unpause", "", false},
		{"containers-prune-denied", http.MethodPost, "/containers/prune", "", false},

		// Unused image operations.
		{"image-history-denied", http.MethodGet, "/images/nginx/history", "", false},
		{"image-attestations-denied", http.MethodGet, "/images/nginx/attestations", "", false},
		{"image-tag-denied", http.MethodPost, "/images/nginx/tag", "", false},
		{"image-load-denied", http.MethodPost, "/images/load", "", false},
		{"images-prune-denied", http.MethodPost, "/images/prune", "", false},

		// Unused network, volume and distribution operations.
		{"networks-list-denied", http.MethodGet, "/networks", "", false},
		{"network-inspect-denied", http.MethodGet, "/networks/net1", "", false},
		{"network-create-denied", http.MethodPost, "/networks/create", "", false},
		{"network-disconnect-denied", http.MethodPost, "/networks/net1/disconnect", `{"Container":"abc"}`, false},
		{"network-remove-denied", http.MethodDelete, "/networks/net1", "", false},
		{"networks-prune-denied", http.MethodPost, "/networks/prune", "", false},
		{"volumes-list-denied", http.MethodGet, "/volumes", "", false},
		{"volume-inspect-denied", http.MethodGet, "/volumes/data", "", false},
		{"volume-create-denied", http.MethodPost, "/volumes/create", `{"Name":"data"}`, false},
		{"volume-remove-denied", http.MethodDelete, "/volumes/data", "", false},
		{"volumes-prune-denied", http.MethodPost, "/volumes/prune", "", false},
		{"distribution-denied", http.MethodGet, "/distribution/nginx/json", "", false},

		// Other Docker resource families remain default-deny.
		{"build-denied", http.MethodPost, "/build", "", false},
		{"services-list-denied", http.MethodGet, "/services", "", false},
		{"tasks-list-denied", http.MethodGet, "/tasks", "", false},
		{"secrets-list-denied", http.MethodGet, "/secrets", "", false},
		{"configs-list-denied", http.MethodGet, "/configs", "", false},
		{"plugins-list-denied", http.MethodGet, "/plugins", "", false},
	}
	cases = append(cases, exfilDenialCases...)

	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}
