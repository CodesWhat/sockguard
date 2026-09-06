package filter

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/imagetrust"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// ---------------------------------------------------------------------------
// Decode-target reuse
// ---------------------------------------------------------------------------

// fillContainerCreateRequestFields walks v and writes a non-zero value into
// every field it can reach, so resetForReuse can be checked against a target
// that is dirty everywhere rather than only in the places a hand-written
// fixture remembered to touch. New schema fields are covered automatically,
// which is the whole point: a field added to containerCreateRequest without a
// matching resetForReuse line fails the test below without anyone editing it.
func fillContainerCreateRequestFields(v reflect.Value) {
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.String:
		v.SetString("dirty")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(7)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(7)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fillContainerCreateRequestFields(v.Elem())
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 2, 2))
		for i := range v.Len() {
			fillContainerCreateRequestFields(v.Index(i))
		}
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		key := reflect.New(v.Type().Key()).Elem()
		fillContainerCreateRequestFields(key)
		elem := reflect.New(v.Type().Elem()).Elem()
		fillContainerCreateRequestFields(elem)
		v.SetMapIndex(key, elem)
	case reflect.Struct:
		for i := range v.NumField() {
			fillContainerCreateRequestFields(v.Field(i))
		}
	case reflect.Interface:
		v.Set(reflect.ValueOf("dirty"))
	default:
	}
}

// containerCreateResidue returns the paths of every field that still carries
// data a policy could read. A slice or map that kept its capacity but has no
// reachable elements is clean; anything else is residue from the previous
// request.
func containerCreateResidue(v reflect.Value, path string) []string {
	switch v.Kind() {
	case reflect.Bool:
		if v.Bool() {
			return []string{path}
		}
	case reflect.String:
		if v.String() != "" {
			return []string{path}
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.Int() != 0 {
			return []string{path}
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if v.Uint() != 0 {
			return []string{path}
		}
	case reflect.Float32, reflect.Float64:
		if v.Float() != 0 {
			return []string{path}
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			return []string{path}
		}
	case reflect.Slice, reflect.Map:
		if v.Len() != 0 {
			return []string{path}
		}
	case reflect.Struct:
		var out []string
		for i := range v.NumField() {
			out = append(out, containerCreateResidue(v.Field(i), path+"."+v.Type().Field(i).Name)...)
		}
		return out
	default:
	}
	return nil
}

func TestContainerCreateRequestResetForReuseClearsEveryField(t *testing.T) {
	var req containerCreateRequest
	fillContainerCreateRequestFields(reflect.ValueOf(&req).Elem())

	if residue := containerCreateResidue(reflect.ValueOf(&req).Elem(), "containerCreateRequest"); len(residue) == 0 {
		t.Fatal("fillContainerCreateRequestFields() left the request clean; the reset check would be vacuous")
	}

	req.resetForReuse()

	if residue := containerCreateResidue(reflect.ValueOf(&req).Elem(), "containerCreateRequest"); len(residue) > 0 {
		t.Fatalf("resetForReuse() left %d field(s) carrying data: %v", len(residue), residue)
	}
}

// containerCreateDecodeCorpus is the set of bodies the reuse-parity checks
// decode in every ordered pair. It deliberately mixes rich bodies with sparse
// ones: the hazard a recycled decode target introduces is a field the second
// body never mentions still reading back the first body's value.
var containerCreateDecodeCorpus = []string{
	`{}`,
	`{"Image":"alpine:3.19","User":"1000","Labels":{"team":"core"}}`,
	`{"MacAddress":"02:42:ac:11:00:02"}`,
	`{"NetworkingConfig":{"EndpointsConfig":{"frontend":{"IPAddress":"10.0.0.5","Links":["db"]}}}}`,
	`{"HostConfig":{"Privileged":true,"NetworkMode":"host","PidMode":"host","IpcMode":"host","UsernsMode":"host","CgroupnsMode":"host"}}`,
	`{"HostConfig":{"Binds":["/etc:/etc","/srv:/srv","/var:/var"],"VolumesFrom":["other"],"GroupAdd":["docker"],"ExtraHosts":["a:1.2.3.4"]}}`,
	`{"HostConfig":{"Binds":["/only"]}}`,
	`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"v","VolumeOptions":{"Subpath":"sub","DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/etc"}}}},{"Type":"tmpfs","TmpfsOptions":{"Options":[["exec"],["mode","1770"]]}}]}}`,
	`{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/srv/data"}]}}`,
	`{"HostConfig":{"Devices":[{"PathOnHost":"/dev/sda"},{"PathOnHost":"/dev/null"}],"DeviceCgroupRules":["c 10:200 rwm"]}}`,
	`{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":4,"DeviceIDs":["0"],"Capabilities":[["gpu","compute"]],"Options":{"a":"b"}}]}}`,
	`{"HostConfig":{"SecurityOpt":["seccomp=unconfined","apparmor=unconfined","label=disable","systempaths=unconfined"],"CapAdd":["SYS_ADMIN"],"CapDrop":["ALL"]}}`,
	`{"HostConfig":{"Memory":67108864,"MemoryReservation":1024,"NanoCpus":500000000,"CpuQuota":50000,"CpuPeriod":100000,"CpuShares":512,"PidsLimit":256}}`,
	`{"HostConfig":{"Sysctls":{"net.ipv4.ip_forward":"1"},"UTSMode":"host","CgroupParent":"/custom","Runtime":"kata","ReadonlyRootfs":true}}`,
	`{"HostConfig":{"MaskedPaths":[],"ReadonlyPaths":[]}}`,
	`{"HostConfig":{"MaskedPaths":["/proc/kcore"],"ReadonlyPaths":["/proc/sys"]}}`,
	`{"HostConfig":{"Binds":null,"Labels":null,"PidsLimit":null,"Sysctls":null}}`,
}

// normalizeContainerCreateForCompare rewrites zero-length slices and maps to
// nil so a recycled target that kept a truncated backing array compares equal
// to a freshly allocated one. Capacity is invisible to the policy; length is
// not.
func normalizeContainerCreateForCompare(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			normalizeContainerCreateForCompare(v.Elem())
		}
	case reflect.Slice:
		if v.Len() == 0 {
			v.Set(reflect.Zero(v.Type()))
			return
		}
		for i := range v.Len() {
			normalizeContainerCreateForCompare(v.Index(i))
		}
	case reflect.Map:
		if v.Len() == 0 {
			v.Set(reflect.Zero(v.Type()))
		}
	case reflect.Struct:
		for i := range v.NumField() {
			normalizeContainerCreateForCompare(v.Field(i))
		}
	default:
	}
}

func decodeContainerCreateBody(t *testing.T, target *containerCreateRequest, body string) error {
	t.Helper()
	return json.Unmarshal([]byte(body), target)
}

func TestContainerCreateDecodeIntoReusedTargetMatchesFreshTarget(t *testing.T) {
	for i, first := range containerCreateDecodeCorpus {
		for j, second := range containerCreateDecodeCorpus {
			t.Run(fmt.Sprintf("body%d_then_body%d", i, j), func(t *testing.T) {
				var fresh containerCreateRequest
				freshErr := decodeContainerCreateBody(t, &fresh, second)

				reused := new(containerCreateRequest)
				if err := decodeContainerCreateBody(t, reused, first); err != nil {
					t.Fatalf("decode of first body error = %v, want nil", err)
				}
				reused.resetForReuse()
				reusedErr := decodeContainerCreateBody(t, reused, second)

				if (freshErr == nil) != (reusedErr == nil) {
					t.Fatalf("decode error mismatch after %s: fresh(%s) = %v, reused = %v", first, second, freshErr, reusedErr)
				}

				normalizeContainerCreateForCompare(reflect.ValueOf(&fresh).Elem())
				normalizeContainerCreateForCompare(reflect.ValueOf(reused).Elem())
				if !reflect.DeepEqual(fresh, *reused) {
					t.Fatalf("decoding %s into a target that last held %s gave %+v, want %+v", second, first, *reused, fresh)
				}
			})
		}
	}
}

func TestContainerCreateInspectIsUnaffectedByAPreviousRequest(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowedBindMounts:          []string{"/srv"},
		AllowedDevices:             []string{"/dev/null"},
		AllowedCapabilities:        []string{"NET_BIND_SERVICE"},
		AllowedRuntimes:            []string{"runsc"},
		RequiredLabels:             []string{"team"},
		RequireNonRootUser:         true,
		RequireMemoryLimit:         true,
		RequirePidsLimit:           true,
		RequireReadonlyRootfs:      true,
		RequireDropAllCapabilities: true,
		DenyUnconfinedSeccomp:      true,
		DenyUnconfinedSystemPaths:  true,
	})

	for i, first := range containerCreateDecodeCorpus {
		for j, second := range containerCreateDecodeCorpus {
			t.Run(fmt.Sprintf("body%d_then_body%d", i, j), func(t *testing.T) {
				isolated, err := policy.inspect(nil, makeInspectRequest(t, second), "/containers/create")
				if err != nil {
					t.Fatalf("isolated inspect() error = %v", err)
				}

				if _, err := policy.inspect(nil, makeInspectRequest(t, first), "/containers/create"); err != nil {
					t.Fatalf("first inspect() error = %v", err)
				}
				sequential, err := policy.inspect(nil, makeInspectRequest(t, second), "/containers/create")
				if err != nil {
					t.Fatalf("sequential inspect() error = %v", err)
				}

				if sequential != isolated {
					t.Fatalf("inspect(%s) after inspecting %s = %q, want %q", second, first, sequential, isolated)
				}
			})
		}
	}
}

func TestContainerCreateInspectIsSafeUnderConcurrentRequests(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowedBindMounts:     []string{"/srv"},
		AllowedDevices:        []string{"/dev/null"},
		AllowedCapabilities:   []string{"NET_BIND_SERVICE"},
		AllowedRuntimes:       []string{"runsc"},
		RequiredLabels:        []string{"team"},
		RequireNonRootUser:    true,
		DenyUnconfinedSeccomp: true,
	})

	want := make([]string, len(containerCreateDecodeCorpus))
	for i, body := range containerCreateDecodeCorpus {
		reason, err := policy.inspect(nil, makeInspectRequest(t, body), "/containers/create")
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		want[i] = reason
	}

	const rounds = 40
	var wg sync.WaitGroup
	errs := make(chan string, len(containerCreateDecodeCorpus)*rounds)
	for i, body := range containerCreateDecodeCorpus {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range rounds {
				reason, err := policy.inspect(nil, makeInspectRequest(t, body), "/containers/create")
				if err != nil {
					errs <- fmt.Sprintf("inspect(%s) error = %v", body, err)
					return
				}
				if reason != want[i] {
					errs <- fmt.Sprintf("inspect(%s) = %q, want %q", body, reason, want[i])
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

func TestReleaseContainerCreateRequestDropsOversizedTargets(t *testing.T) {
	tests := []struct {
		name string
		req  *containerCreateRequest
		want bool
	}{
		{name: "nil", req: nil, want: false},
		{name: "empty", req: new(containerCreateRequest), want: false},
		{
			name: "binds within cap",
			req: &containerCreateRequest{HostConfig: containerCreateHostConfig{
				Binds: make([]string, 0, containerCreateReuseCap),
			}},
			want: false,
		},
		{
			name: "binds over cap",
			req: &containerCreateRequest{HostConfig: containerCreateHostConfig{
				Binds: make([]string, 0, containerCreateReuseCap+1),
			}},
			want: true,
		},
		{
			name: "labels over cap",
			req:  &containerCreateRequest{Labels: makeStringMap(containerCreateReuseCap + 1)},
			want: true,
		},
		{
			name: "sysctls over cap",
			req: &containerCreateRequest{HostConfig: containerCreateHostConfig{
				Sysctls: makeStringMap(containerCreateReuseCap + 1),
			}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.req == nil {
				releaseContainerCreateRequest(tt.req)
				return
			}
			if got := tt.req.oversizedForReuse(); got != tt.want {
				t.Fatalf("oversizedForReuse() = %v, want %v", got, tt.want)
			}
			releaseContainerCreateRequest(tt.req)
		})
	}
}

func makeStringMap(n int) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		m[fmt.Sprintf("k%d", i)] = "v"
	}
	return m
}

func TestAcquireContainerCreateRequestReturnsACleanTarget(t *testing.T) {
	dirty := acquireContainerCreateRequest()
	fillContainerCreateRequestFields(reflect.ValueOf(dirty).Elem())
	releaseContainerCreateRequest(dirty)

	// The pool is free to hand back either the target just released or a
	// fresh one; both must arrive clean.
	for range 8 {
		got := acquireContainerCreateRequest()
		if residue := containerCreateResidue(reflect.ValueOf(got).Elem(), "containerCreateRequest"); len(residue) > 0 {
			t.Fatalf("acquireContainerCreateRequest() returned residue in %v", residue)
		}
		releaseContainerCreateRequest(got)
	}
}

// ---------------------------------------------------------------------------
// Decoded fields are the inspected fields
// ---------------------------------------------------------------------------

// refImageVerifier denies exactly the image references whose name contains
// "untrusted", so the Image case below can tell "the field was decoded" apart
// from "the field decoded to the empty string", which denies for a different
// reason.
type refImageVerifier struct{}

func (refImageVerifier) Verify(_ context.Context, imageRef, _ string, _ verify.SignedEntity) error {
	if strings.Contains(imageRef, "untrusted") {
		return fmt.Errorf("no trusted signature for %s", imageRef)
	}
	return nil
}

func imageTrustEnforcePolicy() containerCreatePolicy {
	policy := newContainerCreatePolicy(ContainerCreateOptions{})
	policy.imageTrustVerifier = refImageVerifier{}
	policy.imageFetcher = oneCandidateFetcher()
	policy.imageTrustCfg = imagetrust.Config{Mode: imagetrust.ModeEnforce}
	return policy
}

// TestContainerCreateDecodedFieldsAreTheInspectedFields pins every field the
// container-create policy reads out of the decoded body to a pair of bodies
// that differ only in that field: one the policy must deny and one it must
// allow. A field dropped from the decode reads back as its zero value, which
// breaks one side of the pair or the other — the deny case for a field whose
// hostile value is non-zero, the allow case for a field whose absence is what
// the policy denies. Both directions are asserted for every entry, so this
// fails whichever way a field goes missing.
func TestContainerCreateDecodedFieldsAreTheInspectedFields(t *testing.T) {
	bindPolicy := newContainerCreatePolicy(ContainerCreateOptions{AllowedBindMounts: []string{"/srv"}})
	devicePolicy := newContainerCreatePolicy(ContainerCreateOptions{AllowedDevices: []string{"/dev/null"}})
	deviceRequestPolicy := func(entry AllowedDeviceRequestEntry) containerCreatePolicy {
		return newContainerCreatePolicy(ContainerCreateOptions{AllowedDeviceRequests: []AllowedDeviceRequestEntry{entry}})
	}
	maxCount := 1

	tests := []struct {
		field  string
		policy containerCreatePolicy
		deny   string
		allow  string
	}{
		{
			field:  "Image",
			policy: imageTrustEnforcePolicy(),
			deny:   `{"Image":"registry.example.com/untrusted:v1"}`,
			allow:  `{"Image":"registry.example.com/trusted:v1"}`,
		},
		{
			field:  "User",
			policy: newContainerCreatePolicy(ContainerCreateOptions{RequireNonRootUser: true}),
			deny:   `{"User":"0"}`,
			allow:  `{"User":"1000"}`,
		},
		{
			field:  "Labels",
			policy: newContainerCreatePolicy(ContainerCreateOptions{RequiredLabels: []string{"team"}}),
			deny:   `{"Labels":{"other":"x"}}`,
			allow:  `{"Labels":{"team":"core"}}`,
		},
		{
			field:  "MacAddress",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"MacAddress":"02:42:ac:11:00:02"}`,
			allow:  `{"MacAddress":"   "}`,
		},
		{
			field:  "NetworkingConfig.EndpointsConfig",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"NetworkingConfig":{"EndpointsConfig":{"frontend":{"IPAddress":"10.0.0.5"}}}}`,
			allow:  `{"NetworkingConfig":{"EndpointsConfig":{"frontend":{}}}}`,
		},
		{
			field:  "HostConfig.Privileged",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"HostConfig":{"Privileged":true}}`,
			allow:  `{"HostConfig":{"Privileged":false}}`,
		},
		{
			field:  "HostConfig.NetworkMode",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"HostConfig":{"NetworkMode":"host"}}`,
			allow:  `{"HostConfig":{"NetworkMode":"bridge"}}`,
		},
		{
			field:  "HostConfig.PidMode",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"HostConfig":{"PidMode":"host"}}`,
			allow:  `{"HostConfig":{"PidMode":"private"}}`,
		},
		{
			field:  "HostConfig.IpcMode",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"HostConfig":{"IpcMode":"host"}}`,
			allow:  `{"HostConfig":{"IpcMode":"private"}}`,
		},
		{
			field:  "HostConfig.UsernsMode",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"HostConfig":{"UsernsMode":"host"}}`,
			allow:  `{"HostConfig":{"UsernsMode":"private"}}`,
		},
		{
			field:  "HostConfig.CgroupnsMode",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"HostConfig":{"CgroupnsMode":"host"}}`,
			allow:  `{"HostConfig":{"CgroupnsMode":"private"}}`,
		},
		{
			field:  "HostConfig.Binds",
			policy: bindPolicy,
			deny:   `{"HostConfig":{"Binds":["/etc:/etc"]}}`,
			allow:  `{"HostConfig":{"Binds":["/srv/data:/data"]}}`,
		},
		{
			field:  "HostConfig.Mounts[].Type",
			policy: bindPolicy,
			deny:   `{"HostConfig":{"Mounts":[{"Type":"cluster","Source":"/srv/data"}]}}`,
			allow:  `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"data"}]}}`,
		},
		{
			field:  "HostConfig.Mounts[].Source",
			policy: bindPolicy,
			deny:   `{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/etc"}]}}`,
			allow:  `{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/srv/data"}]}}`,
		},
		{
			field:  "HostConfig.Mounts[].VolumeOptions.Subpath",
			policy: bindPolicy,
			deny:   `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"data","VolumeOptions":{"Subpath":"../escape"}}]}}`,
			allow:  `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"data","VolumeOptions":{"Subpath":"nested/dir"}}]}}`,
		},
		{
			field:  "HostConfig.Mounts[].VolumeOptions.DriverConfig",
			policy: bindPolicy,
			deny:   `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"data","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/etc"}}}}]}}`,
			allow:  `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"data","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/srv/data"}}}}]}}`,
		},
		{
			field:  "HostConfig.Mounts[].ImageOptions.Subpath",
			policy: bindPolicy,
			deny:   `{"HostConfig":{"Mounts":[{"Type":"image","Source":"alpine:3.19","ImageOptions":{"Subpath":"../escape"}}]}}`,
			allow:  `{"HostConfig":{"Mounts":[{"Type":"image","Source":"alpine:3.19","ImageOptions":{"Subpath":"nested/dir"}}]}}`,
		},
		{
			field:  "HostConfig.Mounts[].TmpfsOptions.Options",
			policy: bindPolicy,
			deny:   `{"HostConfig":{"Mounts":[{"Type":"tmpfs","TmpfsOptions":{"Options":[["exec"]]}}]}}`,
			allow:  `{"HostConfig":{"Mounts":[{"Type":"tmpfs","TmpfsOptions":{"Options":[["mode","1770"]]}}]}}`,
		},
		{
			field:  "HostConfig.Devices[].PathOnHost",
			policy: devicePolicy,
			deny:   `{"HostConfig":{"Devices":[{"PathOnHost":"/dev/sda"}]}}`,
			allow:  `{"HostConfig":{"Devices":[{"PathOnHost":"/dev/null"}]}}`,
		},
		{
			field:  "HostConfig.DeviceRequests[].Driver",
			policy: deviceRequestPolicy(AllowedDeviceRequestEntry{Driver: "nvidia"}),
			deny:   `{"HostConfig":{"DeviceRequests":[{"Driver":"amd"}]}}`,
			allow:  `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia"}]}}`,
		},
		{
			field:  "HostConfig.DeviceRequests[].Count",
			policy: deviceRequestPolicy(AllowedDeviceRequestEntry{Driver: "nvidia", MaxCount: &maxCount}),
			deny:   `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":2}]}}`,
			allow:  `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":1}]}}`,
		},
		{
			field:  "HostConfig.DeviceRequests[].Capabilities",
			policy: deviceRequestPolicy(AllowedDeviceRequestEntry{Driver: "nvidia", AllowedCapabilities: [][]string{{"gpu"}}}),
			deny:   `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Capabilities":[["gpu","compute"]]}]}}`,
			allow:  `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Capabilities":[["gpu"]]}]}}`,
		},
		{
			field:  "HostConfig.DeviceCgroupRules",
			policy: newContainerCreatePolicy(ContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:3 rw"}}),
			deny:   `{"HostConfig":{"DeviceCgroupRules":["c 10:200 rwm"]}}`,
			allow:  `{"HostConfig":{"DeviceCgroupRules":["c 1:3 rw"]}}`,
		},
		{
			field:  "HostConfig.SecurityOpt",
			policy: newContainerCreatePolicy(ContainerCreateOptions{DenyUnconfinedSeccomp: true}),
			deny:   `{"HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`,
			allow:  `{"HostConfig":{"SecurityOpt":["seccomp=runtime/default"]}}`,
		},
		{
			field:  "HostConfig.CapAdd",
			policy: newContainerCreatePolicy(ContainerCreateOptions{AllowedCapabilities: []string{"NET_BIND_SERVICE"}}),
			deny:   `{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`,
			allow:  `{"HostConfig":{"CapAdd":["NET_BIND_SERVICE"]}}`,
		},
		{
			field:  "HostConfig.CapDrop",
			policy: newContainerCreatePolicy(ContainerCreateOptions{RequireDropAllCapabilities: true}),
			deny:   `{"HostConfig":{"CapDrop":["NET_RAW"]}}`,
			allow:  `{"HostConfig":{"CapDrop":["ALL"]}}`,
		},
		{
			field:  "HostConfig.ReadonlyRootfs",
			policy: newContainerCreatePolicy(ContainerCreateOptions{RequireReadonlyRootfs: true}),
			deny:   `{"HostConfig":{"ReadonlyRootfs":false}}`,
			allow:  `{"HostConfig":{"ReadonlyRootfs":true}}`,
		},
		{
			field:  "HostConfig.Memory",
			policy: newContainerCreatePolicy(ContainerCreateOptions{RequireMemoryLimit: true}),
			deny:   `{"HostConfig":{"Memory":0}}`,
			allow:  `{"HostConfig":{"Memory":67108864}}`,
		},
		{
			field:  "HostConfig.NanoCpus",
			policy: newContainerCreatePolicy(ContainerCreateOptions{RequireCPULimit: true}),
			deny:   `{"HostConfig":{"NanoCpus":0}}`,
			allow:  `{"HostConfig":{"NanoCpus":500000000}}`,
		},
		{
			field:  "HostConfig.CpuQuota",
			policy: newContainerCreatePolicy(ContainerCreateOptions{RequireCPULimitHard: true}),
			deny:   `{"HostConfig":{"CpuShares":512}}`,
			allow:  `{"HostConfig":{"CpuQuota":50000}}`,
		},
		{
			field:  "HostConfig.CpuPeriod",
			policy: newContainerCreatePolicy(ContainerCreateOptions{RequireCPULimit: true}),
			deny:   `{"HostConfig":{"CpuPeriod":0}}`,
			allow:  `{"HostConfig":{"CpuPeriod":100000}}`,
		},
		{
			field:  "HostConfig.CpuShares",
			policy: newContainerCreatePolicy(ContainerCreateOptions{RequireCPULimit: true}),
			deny:   `{"HostConfig":{"CpuShares":0}}`,
			allow:  `{"HostConfig":{"CpuShares":512}}`,
		},
		{
			field:  "HostConfig.PidsLimit",
			policy: newContainerCreatePolicy(ContainerCreateOptions{RequirePidsLimit: true}),
			deny:   `{"HostConfig":{"PidsLimit":0}}`,
			allow:  `{"HostConfig":{"PidsLimit":256}}`,
		},
		{
			field:  "HostConfig.Sysctls",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"HostConfig":{"Sysctls":{"net.ipv4.ip_forward":"1"}}}`,
			allow:  `{"HostConfig":{"Sysctls":{}}}`,
		},
		{
			field:  "HostConfig.VolumesFrom",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"HostConfig":{"VolumesFrom":["other"]}}`,
			allow:  `{"HostConfig":{"VolumesFrom":[]}}`,
		},
		{
			field:  "HostConfig.UTSMode",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"HostConfig":{"UTSMode":"host"}}`,
			allow:  `{"HostConfig":{"UTSMode":"private"}}`,
		},
		{
			field:  "HostConfig.CgroupParent",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"HostConfig":{"CgroupParent":"/custom"}}`,
			allow:  `{"HostConfig":{"CgroupParent":"   "}}`,
		},
		{
			field:  "HostConfig.GroupAdd",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"HostConfig":{"GroupAdd":["docker"]}}`,
			allow:  `{"HostConfig":{"GroupAdd":[]}}`,
		},
		{
			field:  "HostConfig.ExtraHosts",
			policy: newContainerCreatePolicy(ContainerCreateOptions{}),
			deny:   `{"HostConfig":{"ExtraHosts":["db:10.0.0.5"]}}`,
			allow:  `{"HostConfig":{"ExtraHosts":[]}}`,
		},
		{
			field:  "HostConfig.Runtime",
			policy: newContainerCreatePolicy(ContainerCreateOptions{AllowedRuntimes: []string{"runsc"}}),
			deny:   `{"HostConfig":{"Runtime":"kata"}}`,
			allow:  `{"HostConfig":{"Runtime":"runsc"}}`,
		},
		{
			field:  "HostConfig.MaskedPaths",
			policy: newContainerCreatePolicy(ContainerCreateOptions{DenyUnconfinedSystemPaths: true}),
			deny:   `{"HostConfig":{"MaskedPaths":[]}}`,
			allow:  `{"HostConfig":{"MaskedPaths":["/proc/kcore"]}}`,
		},
		{
			field:  "HostConfig.ReadonlyPaths",
			policy: newContainerCreatePolicy(ContainerCreateOptions{DenyUnconfinedSystemPaths: true}),
			deny:   `{"HostConfig":{"ReadonlyPaths":[]}}`,
			allow:  `{"HostConfig":{"ReadonlyPaths":["/proc/sys"]}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			denyReason, err := tt.policy.inspect(nil, makeInspectRequest(t, tt.deny), "/containers/create")
			if err != nil {
				t.Fatalf("inspect(%s) error = %v", tt.deny, err)
			}
			if denyReason == "" {
				t.Fatalf("inspect(%s) allowed the request; the field is not being read", tt.deny)
			}

			allowReason, err := tt.policy.inspect(nil, makeInspectRequest(t, tt.allow), "/containers/create")
			if err != nil {
				t.Fatalf("inspect(%s) error = %v", tt.allow, err)
			}
			if allowReason != "" {
				t.Fatalf("inspect(%s) denied with %q; the field is not being read", tt.allow, allowReason)
			}
		})
	}
}

// TestContainerCreateDecodeTypeErrorsStillDeny pins the fail-closed posture
// the struct decode gives a body whose field types do not match the schema.
// The pooled decode target has to keep it: json.Unmarshal still runs against
// the same type, so a value of the wrong JSON type is still an error and the
// request is still denied as malformed.
func TestContainerCreateDecodeTypeErrorsStillDeny(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{})
	bodies := []string{
		`{"Image":5}`,
		`{"Labels":5}`,
		`{"Labels":{"team":5}}`,
		`{"User":[]}`,
		`{"HostConfig":{"Privileged":"yes"}}`,
		`{"HostConfig":{"Memory":1.5}}`,
		`{"HostConfig":{"Memory":99999999999999999999}}`,
		`{"HostConfig":{"Binds":"/etc:/etc"}}`,
		`{"HostConfig":{"Binds":[5]}}`,
		`{"HostConfig":{"MaskedPaths":{}}}`,
		`{"HostConfig":{"Mounts":{}}}`,
		`{"HostConfig":{"DeviceRequests":[{"Count":"4"}]}}`,
	}

	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			reason, err := policy.inspect(nil, makeInspectRequest(t, body), "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "container create denied: malformed JSON request body" {
				t.Fatalf("inspect() reason = %q, want the malformed-body denial", reason)
			}
		})
	}
}
