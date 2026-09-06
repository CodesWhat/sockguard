package differential

import (
	"encoding/json"
	"net/http"
	"path"
	"strings"
	"testing"
)

// The JSON-decoder axis of the differential. sockguard inspects a
// /containers/create body by decoding it into a Go struct that names the
// HostConfig fields its policy enforces; the daemon decodes the same bytes
// into its own full struct. Both sides run encoding/json — so duplicate keys
// (last wins), case-insensitive field matching, and \uXXXX-escaped keys
// resolve identically. This suite pins that agreement: it proves no JSON
// encoding trick makes sockguard read a body as benign while the daemon would
// build a privileged container from it.

// daemonHostConfig models the security-relevant slice of Docker's
// HostConfig as the daemon's encoding/json decode sees it. The json tags
// mirror Docker's wire schema exactly.
type daemonHostConfig struct {
	Privileged        bool              `json:"Privileged"`
	NetworkMode       string            `json:"NetworkMode"`
	PidMode           string            `json:"PidMode"`
	IpcMode           string            `json:"IpcMode"`
	UTSMode           string            `json:"UTSMode"`
	UsernsMode        string            `json:"UsernsMode"`
	Binds             []string          `json:"Binds"`
	Mounts            []daemonMount     `json:"Mounts"`
	VolumesFrom       []string          `json:"VolumesFrom"`
	CapAdd            []string          `json:"CapAdd"`
	Devices           []json.RawMessage `json:"Devices"`
	DeviceRequests    []json.RawMessage `json:"DeviceRequests"`
	DeviceCgroupRules []string          `json:"DeviceCgroupRules"`
	Sysctls           map[string]string `json:"Sysctls"`
	CgroupParent      string            `json:"CgroupParent"`
	GroupAdd          []string          `json:"GroupAdd"`
	ExtraHosts        []string          `json:"ExtraHosts"`
}

type daemonMount struct {
	Type          string               `json:"Type"`
	Source        string               `json:"Source"`
	VolumeOptions *daemonVolumeOptions `json:"VolumeOptions"`
}

// daemonVolumeOptions and daemonVolumeDriverConfig model the slice of
// Mount.VolumeOptions the local volume driver reads. A Type "volume" mount is
// a named volume by default, but the driver config lets the same entry hand
// mount(2) a filesystem type and a device, which is how a volume reaches host
// storage without ever being a bind.
type daemonVolumeOptions struct {
	DriverConfig *daemonVolumeDriverConfig `json:"DriverConfig"`
}

type daemonVolumeDriverConfig struct {
	Name    string            `json:"Name"`
	Options map[string]string `json:"Options"`
}

type daemonContainerView struct {
	HostConfig daemonHostConfig `json:"HostConfig"`
}

// containerCreateDaemonDanger is the test oracle: it decodes a create body
// exactly as the daemon would — encoding/json into the full HostConfig — and
// reports whether the resulting container would hold elevated privilege. A
// decode error means the daemon's own decode fails too: it answers the create
// with 400 and runs nothing, so that is not a dangerous outcome.
//
// "Dangerous" is the union of the conditions sockguard's /containers/create
// inspector denies under default (zero-value) options. The invariant the
// suite enforces is one-directional: whenever sockguard allows a body, this
// oracle must report it benign.
func containerCreateDaemonDanger(body []byte) (bool, string) {
	var v daemonContainerView
	if err := json.Unmarshal(body, &v); err != nil {
		return false, ""
	}
	hc := v.HostConfig
	switch {
	case hc.Privileged:
		return true, "a privileged container"
	case isDaemonHostMode(hc.NetworkMode):
		return true, "a host-network container"
	case isDaemonHostMode(hc.PidMode):
		return true, "a host-PID container"
	case isDaemonHostMode(hc.IpcMode):
		return true, "a host-IPC container"
	case isDaemonHostMode(hc.UTSMode):
		return true, "a host-UTS container"
	case isDaemonHostMode(hc.UsernsMode):
		return true, "a host-userns container"
	case len(hc.Binds) > 0:
		return true, "a container with host bind mounts"
	case hasBindTypeMount(hc.Mounts):
		return true, "a container with bind-type mounts"
	case hasLocalDriverHostDeviceMount(hc.Mounts):
		return true, "a container mounting a host block device through the local volume driver"
	case len(hc.VolumesFrom) > 0:
		return true, "a container inheriting another container's volumes"
	case len(hc.CapAdd) > 0:
		return true, "a container with added Linux capabilities"
	case len(hc.Devices) > 0:
		return true, "a container with passed-through host devices"
	case len(hc.DeviceRequests) > 0:
		return true, "a container with device requests"
	case len(hc.DeviceCgroupRules) > 0:
		return true, "a container with device cgroup rules"
	case len(hc.Sysctls) > 0:
		return true, "a container setting kernel sysctls"
	case hc.CgroupParent != "":
		return true, "a container with a custom cgroup parent"
	case len(hc.GroupAdd) > 0:
		return true, "a container with extra supplemental groups"
	case len(hc.ExtraHosts) > 0:
		return true, "a container with injected /etc/hosts entries"
	default:
		return false, ""
	}
}

// isDaemonHostMode models Docker's namespace-mode check, which is an exact,
// case-sensitive match on "host" (container.NetworkMode.IsHost and friends).
// sockguard's own check is case-insensitive — broader, so strictly safer —
// but the oracle must mirror the daemon, not sockguard.
func isDaemonHostMode(mode string) bool {
	return mode == "host"
}

func hasBindTypeMount(mounts []daemonMount) bool {
	for _, m := range mounts {
		if m.Type == "bind" {
			return true
		}
	}
	return false
}

// hasLocalDriverHostDeviceMount models the local volume driver's own mount
// call: it passes "device" to mount(2) as the source and "type" as the
// filesystem, so a /dev node under any type other than a network filesystem
// or tmpfs mounts the host's own storage inside the container. Written from
// the daemon's behavior and deliberately independent of the filter package's
// helpers, which is the whole point of the differential — a device the daemon
// would mount but sockguard allowed is the bypass this catches.
func hasLocalDriverHostDeviceMount(mounts []daemonMount) bool {
	remoteTypes := map[string]bool{"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "tmpfs": true}

	for _, m := range mounts {
		if m.VolumeOptions == nil || m.VolumeOptions.DriverConfig == nil {
			continue
		}
		driver := m.VolumeOptions.DriverConfig
		if driver.Name != "" && !strings.EqualFold(driver.Name, "local") {
			continue
		}

		var fsType, device string
		for key, value := range driver.Options {
			switch strings.ToLower(key) {
			case "type":
				fsType = strings.ToLower(value)
			case "device":
				device = value
			}
		}
		if device == "" || remoteTypes[fsType] {
			continue
		}
		if !strings.HasPrefix(device, "/") {
			device = "/" + device
		}
		if cleaned := path.Clean(device); cleaned == "/dev" || strings.HasPrefix(cleaned, "/dev/") {
			return true
		}
	}
	return false
}

func TestJSONDifferentialContainerCreateNoDecoderBypass(t *testing.T) {
	t.Parallel()

	daemon := newRecordingDaemon(t)
	chain := buildChain(t, daemon.socketPath, allowRule(http.MethodPost, "/containers/create"))

	// JSON permits \uXXXX escapes inside object keys; P is 'P'. An
	// inspector that scanned raw body bytes for the literal key would miss
	// this. encoding/json decodes the key before matching struct fields, so
	// both sockguard and the daemon resolve it to HostConfig.Privileged. The
	// leading backslash is built from its byte value (0x5c) so this source
	// file carries no escape sequence of its own.
	unicodeEscapedPrivileged := `{"HostConfig":{"` + string([]byte{0x5c}) + `u0050rivileged":true}}`

	tests := []struct {
		name        string
		body        string
		wantAllowed bool
	}{
		// --- benign bodies: allowed, and the daemon agrees they are benign ---
		{"image-only body", `{"Image":"nginx:latest"}`, true},
		{"empty json object", `{}`, true},
		{"null host config", `{"HostConfig":null}`, true},
		{
			// A named volume is not a host path, and an nfs export is a
			// server path, so neither is the device check's business.
			"volume-type mount over an nfs export",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"nfs","o":"addr=1.2.3.4","device":":/exports/data"}}}}]}}`,
			true,
		},
		{
			"plain named volume mount",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"cache"}]}}`,
			true,
		},
		{
			// Duplicate keys resolve to the last value on both sides; here the
			// last value is false, so the container is not privileged.
			"duplicate privileged key resolves to false",
			`{"HostConfig":{"Privileged":true,"Privileged":false}}`,
			true,
		},
		{
			// Privileged lives under HostConfig. At the top level it is an
			// unknown field — ignored by sockguard and by the daemon alike.
			"privileged at the top level is not a host-config field",
			`{"Privileged":true}`,
			true,
		},

		// --- privileged, encoded every way encoding/json accepts ---
		{"privileged true", `{"HostConfig":{"Privileged":true}}`, false},
		{"privileged lowercase key", `{"HostConfig":{"privileged":true}}`, false},
		{"privileged uppercase key", `{"HostConfig":{"PRIVILEGED":true}}`, false},
		{"privileged unicode-escaped key", unicodeEscapedPrivileged, false},
		{"host-config lowercase key", `{"hostconfig":{"Privileged":true}}`, false},
		{
			"duplicate privileged key resolves to true",
			`{"HostConfig":{"Privileged":false,"Privileged":true}}`,
			false,
		},
		{
			"duplicate host-config object, last wins",
			`{"HostConfig":{"Privileged":false},"HostConfig":{"Privileged":true}}`,
			false,
		},
		{
			"whitespace-laden privileged body",
			"{\n\t\"HostConfig\" : {\r\n  \"Privileged\"\t:\ttrue\n}\n}",
			false,
		},

		// --- other elevated-privilege fields ---
		{"host network mode", `{"HostConfig":{"NetworkMode":"host"}}`, false},
		{"host bind mount", `{"HostConfig":{"Binds":["/:/host"]}}`, false},
		{
			"volume-type mount handing the local driver a block device",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"ext4","device":"/dev/sda1"}}}}]}}`,
			false,
		},
		{
			"volume-type mount naming a block device with no filesystem type",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"device":"/dev/sda1"}}}}]}}`,
			false,
		},
		{"volumes from another container", `{"HostConfig":{"VolumesFrom":["donor"]}}`, false},
		{"kernel sysctls", `{"HostConfig":{"Sysctls":{"net.ipv4.ip_forward":"1"}}}`, false},
		{"added capability", `{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`, false},

		// --- malformed bodies: sockguard fails closed (deny) ---
		{"privileged as a number", `{"HostConfig":{"Privileged":1}}`, false},
		{"privileged as a string", `{"HostConfig":{"Privileged":"true"}}`, false},
		{
			// json.Unmarshal rejects a second value after the first — sockguard
			// denies rather than inspecting only the leading object.
			"trailing data after the json value",
			`{"HostConfig":{}}{"HostConfig":{"Privileged":true}}`,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res, fwd := sendRequest(t, chain, daemon, http.MethodPost, "/containers/create", []byte(tt.body))

			if res.allowed != tt.wantAllowed {
				t.Fatalf("%s: allowed = %v, want %v (status %d, body %q)",
					tt.name, res.allowed, tt.wantAllowed, res.statusCode, res.body)
			}

			if !res.allowed {
				if res.statusCode != http.StatusForbidden {
					t.Fatalf("%s: denied with status %d, want %d",
						tt.name, res.statusCode, http.StatusForbidden)
				}
				return
			}

			// Allowed: decode the exact bytes the daemon received and confirm
			// they do not build an elevated-privilege container.
			if dangerous, why := containerCreateDaemonDanger(fwd.Body); dangerous {
				t.Fatalf("BYPASS: sockguard allowed container-create body %q, "+
					"but the daemon's JSON decode yields %s", tt.body, why)
			}
		})
	}
}
