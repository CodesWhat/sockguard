package responsefilter

import (
	"net/http"
	"testing"
)

// legacyRedactionSystemDFBody is the Engine API <= 1.51 GET /system/df shape: bare
// top-level arrays plus LayersSize, with no per-section usage objects.
const legacyRedactionSystemDFBody = `{
	"LayersSize": 1092588,
	"Images": [{"Id":"sha256:aaa","RepoTags":["app:1"],"Size":1092588}],
	"Containers": [
		{
			"Id":"c1",
			"Mounts":[{"Type":"bind","Source":"/srv/secrets","Destination":"/run/secrets"}],
			"NetworkSettings":{"Networks":{"bridge":{"NetworkID":"net-123","IPAddress":"172.18.0.5"}}}
		}
	],
	"Volumes": [{"Name":"cache","Mountpoint":"/var/lib/docker/volumes/cache/_data"}],
	"BuildCache": [{"ID":"bc1","Description":"RUN apt-get install -y curl"}]
}`

// TestSystemDataUsageRedactionCoversTheLegacyShape is the regression for a
// redaction that silently did nothing.
//
// redactSystemDataUsageContainers and redactSystemDataUsageVolumes read
// ContainerUsage.Items and VolumeUsage.Items, keys the Docker Engine API only
// introduced at 1.52. Every daemon below that returns bare Containers and
// Volumes arrays instead, so redact_mount_paths and redact_network_topology
// were documented to cover /system/df and did nothing there — against, in
// practice, almost every daemon in the field, plus Podman's compat API.
//
// The filter now reads both key sets, so the redaction applies whichever
// shape the upstream answers in.
func TestSystemDataUsageRedactionCoversTheLegacyShape(t *testing.T) {
	filter := New(Options{RedactMountPaths: true, RedactNetworkTopology: true})

	resp := newResponseForTest(t, http.MethodGet, "/v1.51/system/df", legacyRedactionSystemDFBody)
	if err := filter.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse(legacy system df) error = %v, want nil", err)
	}

	payload := decodeBodyForTest(t, resp)

	containers, _ := payload["Containers"].([]any)
	if len(containers) != 1 {
		t.Fatalf("Containers = %#v, want one item", payload["Containers"])
	}
	container, _ := containers[0].(map[string]any)

	mounts, _ := container["Mounts"].([]any)
	if len(mounts) != 1 {
		t.Fatalf("Containers[0].Mounts = %#v, want one item", container["Mounts"])
	}
	mount, _ := mounts[0].(map[string]any)
	if got, _ := mount["Source"].(string); got != "<redacted>" {
		t.Fatalf("Containers[0].Mounts[0].Source = %q, want %q", got, "<redacted>")
	}

	bridge := nestedMapForTest(t, container, "NetworkSettings", "Networks", "bridge")
	if got, _ := bridge["NetworkID"].(string); got != "<redacted>" {
		t.Fatalf("Containers[0].NetworkSettings.Networks.bridge.NetworkID = %q, want %q", got, "<redacted>")
	}

	volumes, _ := payload["Volumes"].([]any)
	if len(volumes) != 1 {
		t.Fatalf("Volumes = %#v, want one item", payload["Volumes"])
	}
	volume, _ := volumes[0].(map[string]any)
	if got, _ := volume["Mountpoint"].(string); got != "<redacted>" {
		t.Fatalf("Volumes[0].Mountpoint = %q, want %q", got, "<redacted>")
	}
}

// TestSystemDataUsageRedactionLeavesLegacyBodyOtherwiseIntact guards the
// blast radius: reading a second key set must not disturb anything else in a
// shape the filter previously ignored end to end.
func TestSystemDataUsageRedactionLeavesLegacyBodyOtherwiseIntact(t *testing.T) {
	filter := New(Options{RedactMountPaths: true, RedactNetworkTopology: true})

	resp := newResponseForTest(t, http.MethodGet, "/v1.51/system/df", legacyRedactionSystemDFBody)
	if err := filter.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse(legacy system df) error = %v, want nil", err)
	}
	payload := decodeBodyForTest(t, resp)

	if _, ok := payload["LayersSize"]; !ok {
		t.Fatal("LayersSize was dropped; the redaction filter must not reshape the response")
	}
	if images, _ := payload["Images"].([]any); len(images) != 1 {
		t.Fatalf("Images = %#v, want the one item to survive untouched", payload["Images"])
	}
	// The redaction filter is not the isolation filter: build cache is dropped
	// by ownership/visibility when those are configured, never here.
	if cache, _ := payload["BuildCache"].([]any); len(cache) != 1 {
		t.Fatalf("BuildCache = %#v, want the one item to survive; dropping it is the isolation filter's job", payload["BuildCache"])
	}
}

// TestSystemDataUsageRedactionRejectsMalformedLegacyArrays keeps the new key
// set fail-closed the same way the >= 1.52 one already is.
func TestSystemDataUsageRedactionRejectsMalformedLegacyArrays(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"containers not an array", `{"Containers":{"nope":true}}`},
		{"container entry not an object", `{"Containers":["nope"]}`},
		{"volumes not an array", `{"Volumes":42}`},
		{"volume entry not an object", `{"Volumes":[7]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filter := New(Options{RedactMountPaths: true, RedactNetworkTopology: true})
			resp := newResponseForTest(t, http.MethodGet, "/system/df", tc.body)
			if err := filter.ModifyResponse(resp); err == nil {
				t.Fatal("ModifyResponse() = nil, want an error for a malformed legacy array")
			}
		})
	}
}
