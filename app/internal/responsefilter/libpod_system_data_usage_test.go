package responsefilter

import (
	"encoding/json"
	"io"
	"slices"
	"sort"
	"strings"
	"testing"
)

// libpodSystemDFUpstream is a GET /libpod/system/df body in Podman's native
// report shape: entities.SystemDfReport as libpod.DiskUsage serializes it,
// holding one image, container and volume for each of two tenants.
//
// Every field name here is transcribed from Podman v5.8.1's
// pkg/domain/entities/types/system.go. None of the three item structs declares
// a json tag, so the Go field names are the wire names, and none of them
// declares Labels — which is the whole reason
// LibpodSystemDataUsageDenyReason exists. Nothing about the tenant split below
// is expressible to a filter: "team-a" and "team-b" appear only inside
// Repository, Image, Names and VolumeName strings, which are free text a
// caller chooses, not policy input.
const libpodSystemDFUpstream = `{
  "ImagesSize": 1092588,
  "Images": [
    {"Repository":"docker.io/team-a/app","Tag":"1","ImageID":"aaaa111122223333","Created":"2026-08-01T00:00:00Z","Size":5000,"SharedSize":1000,"UniqueSize":4000,"Containers":1},
    {"Repository":"docker.io/team-b/app","Tag":"1","ImageID":"bbbb444455556666","Created":"2026-08-02T00:00:00Z","Size":6000,"SharedSize":1000,"UniqueSize":5000,"Containers":1}
  ],
  "Containers": [
    {"ContainerID":"c-a","Image":"docker.io/team-a/app:1","Command":["sleep","infinity"],"LocalVolumes":1,"Size":100,"RWSize":50,"Created":"2026-08-03T00:00:00Z","Status":"running","Names":"team-a-web"},
    {"ContainerID":"c-b","Image":"docker.io/team-b/app:1","Command":["sleep","infinity"],"LocalVolumes":1,"Size":200,"RWSize":60,"Created":"2026-08-04T00:00:00Z","Status":"running","Names":"team-b-web"}
  ],
  "Volumes": [
    {"VolumeName":"vol-a","Links":1,"Size":300,"ReclaimableSize":300},
    {"VolumeName":"vol-b","Links":1,"Size":400,"ReclaimableSize":400}
  ]
}`

// TestLibpodSystemDataUsageReportCarriesNoLabels pins the fact the whole
// refusal rests on: no entry in Podman's native disk-usage report carries a
// label, so no keep predicate in this package can classify one as owned or
// visible.
//
// If this ever fails because Podman added Labels to one of the three report
// types, that is the signal to replace the refusal in the ownership and
// visibility middlewares with a FilterSystemDataUsage-style item filter, and
// this test is where the news arrives.
func TestLibpodSystemDataUsageReportCarriesNoLabels(t *testing.T) {
	t.Parallel()

	// Transcribed from Podman v5.8.1 pkg/domain/entities/types/system.go.
	wantFields := map[string][]string{
		"Images":     {"Containers", "Created", "ImageID", "Repository", "SharedSize", "Size", "Tag", "UniqueSize"},
		"Containers": {"Command", "ContainerID", "Created", "Image", "LocalVolumes", "Names", "RWSize", "Size", "Status"},
		"Volumes":    {"Links", "ReclaimableSize", "Size", "VolumeName"},
	}

	var report map[string]json.RawMessage
	if err := json.Unmarshal([]byte(libpodSystemDFUpstream), &report); err != nil {
		t.Fatalf("decode libpod report: %v", err)
	}

	for section, want := range wantFields {
		raw, ok := report[section]
		if !ok {
			t.Fatalf("libpod report has no %s section", section)
		}
		var items []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			t.Fatalf("decode %s items: %v", section, err)
		}
		if len(items) == 0 {
			t.Fatalf("%s section is empty, so it proves nothing", section)
		}
		for i, item := range items {
			if _, labeled := item["Labels"]; labeled {
				t.Errorf("%s[%d] carries Labels; the shape is classifiable and the refusal should become a filter", section, i)
			}
			got := make([]string, 0, len(item))
			for field := range item {
				got = append(got, field)
			}
			sort.Strings(got)
			if !slices.Equal(got, want) {
				t.Errorf("%s[%d] fields = %v, want %v (Podman v5.8.1 SystemDf*Report)", section, i, got, want)
			}
		}
	}
}

// TestLibpodSystemDataUsageIsNotTheCompatPath guards the constant against the
// one mistake that would silently reopen the gap: making /libpod/system/df
// compare equal to the compat path, so the middlewares' compat branch swallows
// it and runs a filter that drops every item without saying so.
func TestLibpodSystemDataUsageIsNotTheCompatPath(t *testing.T) {
	t.Parallel()
	if LibpodSystemDataUsagePath == SystemDataUsagePath {
		t.Fatal("LibpodSystemDataUsagePath equals SystemDataUsagePath; the two endpoints return different bodies")
	}
	if got, want := LibpodSystemDataUsagePath, "/libpod/system/df"; got != want {
		t.Fatalf("LibpodSystemDataUsagePath = %q, want %q", got, want)
	}
}

// TestLibpodSystemDataUsageHasNothingToRedact pins the reason ModifyResponse
// has no LibpodSystemDataUsagePath case: every field the /system/df redaction
// rewrites is absent from Podman's native report, so routing the native shape
// through it would decode a body and change nothing.
//
// The compat sub-test is not decoration. Without it the libpod assertion would
// keep passing if the redaction stopped working entirely.
func TestLibpodSystemDataUsageHasNothingToRedact(t *testing.T) {
	t.Parallel()

	// The compat body carries exactly the three fields the handler rewrites:
	// container Mounts, container network topology, and volume Mountpoint.
	const compatBody = `{"Containers":[{"Id":"c-a","Mounts":[{"Source":"/host/secret","Destination":"/data"}],` +
		`"NetworkSettings":{"Networks":{"bridge":{"NetworkID":"net-1","IPAddress":"172.17.0.2"}}}}],` +
		`"Volumes":[{"Name":"vol-a","Mountpoint":"/var/lib/docker/volumes/vol-a/_data"}]}`

	opts := Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
		RedactSensitiveData:   true,
		RedactHostTopology:    true,
	}

	t.Run("libpod report is returned byte for byte", func(t *testing.T) {
		t.Parallel()
		resp := newResponseForTest(t, "GET", "/v5.8.1"+LibpodSystemDataUsagePath, libpodSystemDFUpstream)
		if err := New(opts).ModifyResponse(resp); err != nil {
			t.Fatalf("ModifyResponse: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(body) != libpodSystemDFUpstream {
			t.Fatalf("native report was rewritten:\n got: %s\nwant: %s", body, libpodSystemDFUpstream)
		}
	})

	t.Run("compat report is still redacted", func(t *testing.T) {
		t.Parallel()
		resp := newResponseForTest(t, "GET", "/v1.53"+SystemDataUsagePath, compatBody)
		if err := New(opts).ModifyResponse(resp); err != nil {
			t.Fatalf("ModifyResponse: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		for _, secret := range []string{"/host/secret", "net-1", "172.17.0.2", "/var/lib/docker/volumes/vol-a/_data"} {
			if strings.Contains(string(body), secret) {
				t.Fatalf("compat redaction is not running, so the libpod sub-test proves nothing: %q survived in %s", secret, body)
			}
		}
	})
}
