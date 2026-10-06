package ownership

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
)

// testImageID and testOtherImageID are full image IDs, the only way a create
// may name an image volume.
const (
	testImageID      = "1111111111111111111111111111111111111111111111111111111111111111"
	testOtherImageID = "2222222222222222222222222222222222222222222222222222222222222222"
)

func decodeLibpodCreateBody(t *testing.T, body string) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return decoded
}

// libpodCreateRefStrings renders each reference as
// "<kind> <identifier> <- <source>", in the order it will be looked up.
func libpodCreateRefStrings(refs *libpodCreateReferences) []string {
	if refs == nil {
		return nil
	}
	out := make([]string, 0, len(refs.resources))
	for _, ref := range refs.resources {
		out = append(out, fmt.Sprintf("%s %s <- %s", ref.kind, ref.identifier, ref.source))
	}
	return out
}

func TestLibpodContainerCreateReferencesReadsEveryReferenceField(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		want []string
	}{
		{name: "nothing named", body: `{"image":"alpine"}`},
		{
			name: "every field",
			body: `{
				"volumes_from":["web:ro","db"],
				"dependencyContainers":["cache"],
				"Networks":{"b-net":{},"a-net":{"aliases":["x"]}},
				"cni_networks":["c-net"],
				"volumes":[{"Name":"data","Dest":"/data"}],
				"image_volumes":[{"Source":"` + testImageID + `","Destination":"/tools"},{"Source":"sha256:` + testOtherImageID + `"}]
			}`,
			want: []string{
				"containers web <- container create volumes_from",
				"containers db <- container create volumes_from",
				"containers cache <- container create dependencyContainers",
				"networks a-net <- container create Networks",
				"networks b-net <- container create Networks",
				"networks c-net <- container create cni_networks",
				"volumes data <- container create volumes",
				"images " + testImageID + " <- container create image_volumes",
				"images sha256:" + testOtherImageID + " <- container create image_volumes",
			},
		},
		{
			name: "one resource named twice is looked up once",
			body: `{"volumes_from":["web","web:ro"],"dependencyContainers":["web"],"Networks":{"net":{}},"cni_networks":["net"]}`,
			want: []string{
				"containers web <- container create volumes_from",
				"networks net <- container create Networks",
			},
		},
		{
			name: "a volumes_from entry is cut at its first colon",
			body: `{"volumes_from":["web:ro,z:extra"]}`,
			want: []string{"containers web <- container create volumes_from"},
		},
		{
			name: "references go to the lookup untrimmed",
			body: `{"volumes_from":[" web"],"volumes":[{"Name":"data "}],"Networks":{" net":{}}}`,
			want: []string{
				"containers  web <- container create volumes_from",
				"networks  net <- container create Networks",
				"volumes data  <- container create volumes",
			},
		},
		{
			name: "anonymous volumes name nothing",
			body: `{"volumes":[{"Dest":"/a"},{"Name":"","Dest":"/b"},{"Name":null,"Dest":"/c"}]}`,
		},
		{
			name: "an anonymous flag doesn't stop a name being looked up",
			body: `{"volumes":[{"Name":"data","Dest":"/a","IsAnonymous":true}]}`,
			want: []string{"volumes data <- container create volumes"},
		},
		{
			name: "the default network key isn't looked up",
			body: `{"Networks":{"default":{}},"cni_networks":["default"]}`,
		},
		{
			name: "only the exact key default is the default network",
			body: `{"Networks":{"Default":{},"bridge":{},"host":{},"none":{},"podman":{}}}`,
			want: []string{
				"networks Default <- container create Networks",
				"networks bridge <- container create Networks",
				"networks host <- container create Networks",
				"networks none <- container create Networks",
				"networks podman <- container create Networks",
			},
		},
		{
			name: "null fields name nothing",
			body: `{"volumes_from":null,"dependencyContainers":null,"Networks":null,"cni_networks":null,"volumes":null,"image_volumes":null,"artifact_volumes":null}`,
		},
		{
			name: "empty fields name nothing",
			body: `{"volumes_from":[],"dependencyContainers":[],"Networks":{},"cni_networks":[],"volumes":[],"image_volumes":[],"artifact_volumes":[]}`,
		},
		{
			name: "keys in another case",
			body: `{"VOLUMES_FROM":["web"],"DependencyContainers":["cache"],"networks":{"net":{}},"CNI_Networks":["cni"],"Volumes":[{"name":"data"}],"Image_Volumes":[{"SOURCE":"` + testImageID + `"}]}`,
			want: []string{
				"containers web <- container create volumes_from",
				"containers cache <- container create dependencyContainers",
				"networks net <- container create Networks",
				"networks cni <- container create cni_networks",
				"volumes data <- container create volumes",
				"images " + testImageID + " <- container create image_volumes",
			},
		},
		{
			// encoding/json folds the long s (U+017F) onto "s" and the Kelvin
			// sign (U+212A) onto "k".
			name: "keys in a Unicode case fold",
			body: `{"volumeſ_from":["web"],"networKs":{"net":{}}}`,
			want: []string{
				"containers web <- container create volumes_from",
				"networks net <- container create Networks",
			},
		},
		{
			name: "a pod's service container isn't a container create field",
			body: `{"serviceContainerID":"web"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			refs := libpodContainerCreateReferences(decodeLibpodCreateBody(t, tt.body))
			if refs != nil && refs.denyReason != "" {
				t.Fatalf("denyReason = %q, want none", refs.denyReason)
			}
			if got := libpodCreateRefStrings(refs); !slices.Equal(got, tt.want) {
				t.Fatalf("references = %q, want %q", got, tt.want)
			}
			if tt.want == nil && refs != nil {
				t.Fatalf("references = %+v, want nil for a body that names nothing", refs)
			}
		})
	}
}

func TestLibpodPodCreateReferencesReadsEveryReferenceField(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		want []string
	}{
		{name: "nothing named", body: `{"name":"web"}`},
		{
			name: "every field",
			body: `{
				"volumes_from":["web:ro"],
				"serviceContainerID":"service",
				"Networks":{"net":{}},
				"cni_networks":["cni"],
				"volumes":[{"Name":"data","Dest":"/data"}],
				"image_volumes":[{"Source":"` + testImageID + `","Destination":"/tools"}]
			}`,
			want: []string{
				"containers web <- pod create volumes_from",
				"containers service <- pod create serviceContainerID",
				"networks net <- pod create Networks",
				"networks cni <- pod create cni_networks",
				"volumes data <- pod create volumes",
				"images " + testImageID + " <- pod create image_volumes",
			},
		},
		{name: "an empty service container names nothing", body: `{"serviceContainerID":""}`},
		{name: "a null service container names nothing", body: `{"serviceContainerID":null}`},
		{
			name: "the service container key in another case",
			body: `{"ServiceContainerId":"service"}`,
			want: []string{"containers service <- pod create serviceContainerID"},
		},
		{
			// PodSpecGenerator has no such field, so Podman drops it.
			name: "dependencyContainers isn't a pod create field",
			body: `{"dependencyContainers":["web"]}`,
		},
		{
			name: "artifact_volumes isn't a pod create field",
			body: `{"artifact_volumes":[{"source":"models","destination":"/models"}]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			refs := libpodPodCreateReferences(decodeLibpodCreateBody(t, tt.body))
			if refs != nil && refs.denyReason != "" {
				t.Fatalf("denyReason = %q, want none", refs.denyReason)
			}
			if got := libpodCreateRefStrings(refs); !slices.Equal(got, tt.want) {
				t.Fatalf("references = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestLibpodPodCreateReferencesWithoutAnInfraContainer pins what a pod create
// is checked for when it has no infra container. Podman hands a pod's
// volumes, networks and volumes_from to the infra container and to nothing
// else, so with `no_infra` true it attaches none of them, and only the
// service container is left to check. Read from Podman 5.8.6
// pkg/api/handlers/libpod/pods.go:43-75 and
// pkg/specgen/generate/pod_create.go:76-113.
//
// Anything short of the one key holding true keeps every check: that's a pod
// Podman gives an infra container, or a body its decode refuses.
func TestLibpodPodCreateReferencesWithoutAnInfraContainer(t *testing.T) {
	t.Parallel()
	const (
		infraFields = `"volumes_from":["web"],"Networks":{"net":{}},"cni_networks":["cni"],"volumes":[{"Name":"data"}],"image_volumes":[{"Source":"` + testImageID + `"}]`
		service     = `"serviceContainerID":"service"`
	)
	onlyService := []string{"containers service <- pod create serviceContainerID"}
	everything := []string{
		"containers web <- pod create volumes_from",
		"containers service <- pod create serviceContainerID",
		"networks net <- pod create Networks",
		"networks cni <- pod create cni_networks",
		"volumes data <- pod create volumes",
		"images " + testImageID + " <- pod create image_volumes",
	}
	tests := []struct {
		name string
		body string
		want []string
	}{
		{name: "no_infra true", body: `{"no_infra":true,` + infraFields + `,` + service + `}`, want: onlyService},
		{name: "no_infra true and no service container", body: `{"no_infra":true,` + infraFields + `}`},
		{
			// Podman never decodes these into anything it reads, so their
			// shape isn't this check's to refuse.
			name: "no_infra true with fields the infra checks would refuse",
			body: `{"no_infra":true,"volumes_from":[""],"Networks":{"":{}},"cni_networks":[""],"volumes":[{"Name":"data"}],"image_volumes":[{"Source":"tools"}],` + service + `}`,
			want: onlyService,
		},
		{name: "the key in another case", body: `{"NO_Infra":true,` + infraFields + `,` + service + `}`, want: onlyService},
		{name: "the last of a repeated key is true", body: `{"no_infra":false,"no_infra":true,` + infraFields + `,` + service + `}`, want: onlyService},
		{name: "the last of a repeated key is false", body: `{"no_infra":true,"no_infra":false,` + infraFields + `,` + service + `}`, want: everything},
		{name: "no_infra false", body: `{"no_infra":false,` + infraFields + `,` + service + `}`, want: everything},
		{name: "no_infra null", body: `{"no_infra":null,` + infraFields + `,` + service + `}`, want: everything},
		{name: "no_infra absent", body: `{` + infraFields + `,` + service + `}`, want: everything},
		// Podman's decode refuses these, and they're checked all the same.
		{name: "no_infra as a string", body: `{"no_infra":"true",` + infraFields + `,` + service + `}`, want: everything},
		{name: "no_infra as a number", body: `{"no_infra":1,` + infraFields + `,` + service + `}`, want: everything},
		{name: "no_infra as a list", body: `{"no_infra":[true],` + infraFields + `,` + service + `}`, want: everything},
		// A key Podman reads into another field, or into none.
		{name: "a key that isn't no_infra", body: `{"noinfra":true,"no-infra":true,"no_infra ":true,` + infraFields + `,` + service + `}`, want: everything},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			refs := libpodPodCreateReferences(decodeLibpodCreateBody(t, tt.body))
			if refs != nil && refs.denyReason != "" {
				t.Fatalf("denyReason = %q, want none", refs.denyReason)
			}
			if got := libpodCreateRefStrings(refs); !slices.Equal(got, tt.want) {
				t.Fatalf("references = %q, want %q", got, tt.want)
			}
		})
	}

	// mutateJSONBody refuses a body that spells the key two ways before the
	// reader sees it. On its own the reader can't say which one Podman would
	// keep, so it keeps every check.
	for name, body := range map[string]map[string]any{
		"two spellings, true and false": {"no_infra": true, "No_Infra": false, "volumes_from": []any{"web"}},
		"two spellings, both true":      {"no_infra": true, "NO_INFRA": true, "volumes_from": []any{"web"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			want := []string{"containers web <- pod create volumes_from"}
			if got := libpodCreateRefStrings(libpodPodCreateReferences(body)); !slices.Equal(got, want) {
				t.Fatalf("references = %q, want %q", got, want)
			}
		})
	}

	t.Run("the service container is still refused when it can't be read", func(t *testing.T) {
		t.Parallel()
		refs := libpodPodCreateReferences(decodeLibpodCreateBody(t, `{"no_infra":true,"serviceContainerID":["service"]}`))
		want := fmt.Sprintf(libpodCreateDenyUnreadable, "pod create", "serviceContainerID")
		if refs == nil || refs.denyReason != want {
			t.Fatalf("references = %+v, want denyReason %q", refs, want)
		}
	})

	t.Run("a container create has no such key", func(t *testing.T) {
		t.Parallel()
		refs := libpodContainerCreateReferences(decodeLibpodCreateBody(t, `{"no_infra":true,"volumes_from":["web"]}`))
		want := []string{"containers web <- container create volumes_from"}
		if got := libpodCreateRefStrings(refs); !slices.Equal(got, want) {
			t.Fatalf("references = %q, want %q", got, want)
		}
	})
}

// TestLibpodCreateReferencesRefuseWhatTheyCannotRead pins the fail-closed
// half: a checked field whose value isn't the shape Podman decodes, or that
// names a resource with an empty reference, refuses the create instead of
// being read as naming nothing.
func TestLibpodCreateReferencesRefuseWhatTheyCannotRead(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		pod   bool
		body  string
		field string
	}{
		{name: "volumes_from as a string", body: `{"volumes_from":"web"}`, field: "volumes_from"},
		{name: "volumes_from as an object", body: `{"volumes_from":{"web":{}}}`, field: "volumes_from"},
		{name: "volumes_from holding a number", body: `{"volumes_from":["web",5]}`, field: "volumes_from"},
		{name: "volumes_from holding a list", body: `{"volumes_from":[["web"]]}`, field: "volumes_from"},
		{name: "volumes_from holding an empty string", body: `{"volumes_from":[""]}`, field: "volumes_from"},
		{name: "volumes_from holding a null", body: `{"volumes_from":[null]}`, field: "volumes_from"},
		{name: "volumes_from holding only options", body: `{"volumes_from":[":ro"]}`, field: "volumes_from"},
		{name: "dependencyContainers as a string", body: `{"dependencyContainers":"web"}`, field: "dependencyContainers"},
		{name: "dependencyContainers holding an empty string", body: `{"dependencyContainers":[""]}`, field: "dependencyContainers"},
		{name: "dependencyContainers holding an object", body: `{"dependencyContainers":[{}]}`, field: "dependencyContainers"},
		{name: "Networks as a list", body: `{"Networks":["net"]}`, field: "Networks"},
		{name: "Networks as a string", body: `{"Networks":"net"}`, field: "Networks"},
		{name: "Networks with an empty name", body: `{"Networks":{"":{}}}`, field: "Networks"},
		{name: "cni_networks as a string", body: `{"cni_networks":"net"}`, field: "cni_networks"},
		{name: "cni_networks holding an empty string", body: `{"cni_networks":[""]}`, field: "cni_networks"},
		{name: "cni_networks holding a number", body: `{"cni_networks":[1]}`, field: "cni_networks"},
		{name: "volumes as an object", body: `{"volumes":{"Name":"data"}}`, field: "volumes"},
		{name: "volumes as a string", body: `{"volumes":"data"}`, field: "volumes"},
		{name: "volumes holding a string", body: `{"volumes":["data"]}`, field: "volumes"},
		{name: "volumes holding a null", body: `{"volumes":[null]}`, field: "volumes"},
		{name: "volumes with a name that isn't a string", body: `{"volumes":[{"Name":["data"]}]}`, field: "volumes"},
		{name: "volumes with a numeric name", body: `{"volumes":[{"Name":5}]}`, field: "volumes"},
		{name: "image_volumes as an object", body: `{"image_volumes":{"Source":"tools"}}`, field: "image_volumes"},
		{name: "image_volumes holding a null", body: `{"image_volumes":[null]}`, field: "image_volumes"},
		{name: "image_volumes with a source that isn't a string", body: `{"image_volumes":[{"Source":{}}]}`, field: "image_volumes"},
		{name: "artifact_volumes as an object", body: `{"artifact_volumes":{"source":"models"}}`, field: "artifact_volumes"},
		{name: "artifact_volumes as a string", body: `{"artifact_volumes":"models"}`, field: "artifact_volumes"},
		{name: "pod serviceContainerID as a list", pod: true, body: `{"serviceContainerID":["web"]}`, field: "serviceContainerID"},
		{name: "pod serviceContainerID as a number", pod: true, body: `{"serviceContainerID":7}`, field: "serviceContainerID"},
		{name: "pod volumes_from as a string", pod: true, body: `{"volumes_from":"web"}`, field: "volumes_from"},
		{name: "pod volumes holding a null", pod: true, body: `{"volumes":[null]}`, field: "volumes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			read, create := libpodContainerCreateReferences, "container create"
			if tt.pod {
				read, create = libpodPodCreateReferences, "pod create"
			}
			refs := read(decodeLibpodCreateBody(t, tt.body))
			want := fmt.Sprintf(libpodCreateDenyUnreadable, create, tt.field)
			if refs == nil || refs.denyReason != want {
				t.Fatalf("references = %+v, want denyReason %q", refs, want)
			}
		})
	}
}

// TestLibpodCreateReferencesRefuseAKeySpelledTwoWays covers the reader on its
// own. mutateJSONBody refuses such a body before the reader sees it, and the
// reader doesn't rely on that: with two keys for one field it can't say which
// value Podman would keep.
func TestLibpodCreateReferencesRefuseAKeySpelledTwoWays(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		body  map[string]any
		field string
	}{
		{
			name:  "top-level field",
			body:  map[string]any{"volumes_from": []any{"mine"}, "Volumes_From": []any{"theirs"}},
			field: "volumes_from",
		},
		{
			name:  "Networks",
			body:  map[string]any{"Networks": map[string]any{"mine": map[string]any{}}, "networks": map[string]any{"theirs": map[string]any{}}},
			field: "Networks",
		},
		{
			name:  "cni_networks",
			body:  map[string]any{"cni_networks": []any{"mine"}, "CNI_NETWORKS": []any{"theirs"}},
			field: "cni_networks",
		},
		{
			name:  "volumes",
			body:  map[string]any{"volumes": []any{}, "Volumes": []any{map[string]any{"Name": "theirs"}}},
			field: "volumes",
		},
		{
			name:  "a volume's name",
			body:  map[string]any{"volumes": []any{map[string]any{"Name": "mine", "name": "theirs"}}},
			field: "volumes",
		},
		{
			name:  "image_volumes",
			body:  map[string]any{"image_volumes": []any{}, "IMAGE_VOLUMES": []any{map[string]any{"Source": "theirs"}}},
			field: "image_volumes",
		},
		{
			name:  "an image volume's source",
			body:  map[string]any{"image_volumes": []any{map[string]any{"Source": testImageID, "source": testOtherImageID}}},
			field: "image_volumes",
		},
		{
			name:  "artifact_volumes",
			body:  map[string]any{"artifact_volumes": []any{}, "Artifact_Volumes": []any{map[string]any{"source": "theirs"}}},
			field: "artifact_volumes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			refs := libpodContainerCreateReferences(tt.body)
			want := fmt.Sprintf(libpodCreateDenyUnreadable, "container create", tt.field)
			if refs == nil || refs.denyReason != want {
				t.Fatalf("references = %+v, want denyReason %q", refs, want)
			}
		})
	}

	t.Run("pod service container", func(t *testing.T) {
		t.Parallel()
		refs := libpodPodCreateReferences(map[string]any{"serviceContainerID": "mine", "servicecontainerid": "theirs"})
		want := fmt.Sprintf(libpodCreateDenyUnreadable, "pod create", "serviceContainerID")
		if refs == nil || refs.denyReason != want {
			t.Fatalf("references = %+v, want denyReason %q", refs, want)
		}
	})
}

// TestLibpodCreateReferencesRefuseAnImageVolumeNotNamedByFullID pins the one
// reference a lookup at create can't vouch for as written. Podman looks an
// image volume's source up again at every start, by name before ID prefix, so
// only a full image ID is sure to be the same image then.
func TestLibpodCreateReferencesRefuseAnImageVolumeNotNamedByFullID(t *testing.T) {
	t.Parallel()
	sources := map[string]string{
		"a name":                       `"tools"`,
		"a name and tag":               `"registry.example/team/tools:1.2"`,
		"a short ID":                   `"111111111111"`,
		"an ID one digit short":        `"` + testImageID[:63] + `"`,
		"an ID one digit long":         `"` + testImageID + `1"`,
		"an uppercase ID":              `"` + strings.ToUpper(strings.Repeat("ab", 32)) + `"`,
		"an ID with a non-hex digit":   `"` + testImageID[:63] + `g"`,
		"a padded ID":                  `" ` + testImageID + `"`,
		"a digest of another kind":     `"sha512:` + testImageID + `"`,
		"a doubled prefix":             `"sha256:sha256:` + testImageID + `"`,
		"a name with a digest":         `"tools@sha256:` + testImageID + `"`,
		"an empty source":              `""`,
		"a null source":                `null`,
		"a name after an ID":           `"` + testImageID + `"},{"Source":"tools"`,
		"a containers-storage address": `"containers-storage:` + testImageID + `"`,
	}
	for _, create := range []struct {
		name string
		read func(map[string]any) *libpodCreateReferences
	}{
		{name: "container create", read: libpodContainerCreateReferences},
		{name: "pod create", read: libpodPodCreateReferences},
	} {
		want := fmt.Sprintf(libpodCreateDenyImageVolumeName, create.name)
		for name, source := range sources {
			t.Run(create.name+"/"+name, func(t *testing.T) {
				t.Parallel()
				refs := create.read(decodeLibpodCreateBody(t, `{"image_volumes":[{"Source":`+source+`,"Destination":"/tools"}]}`))
				if refs == nil || refs.denyReason != want {
					t.Fatalf("references = %+v, want denyReason %q", refs, want)
				}
			})
		}
		t.Run(create.name+"/no source", func(t *testing.T) {
			t.Parallel()
			refs := create.read(decodeLibpodCreateBody(t, `{"image_volumes":[{"Destination":"/tools"}]}`))
			if refs == nil || refs.denyReason != want {
				t.Fatalf("references = %+v, want denyReason %q", refs, want)
			}
		})
	}
}

// TestLibpodContainerCreateReferencesRefuseAnArtifactVolume pins that a
// container create mounting any artifact is refused: an artifact carries no
// labels, so there's no owner for a lookup to report.
func TestLibpodContainerCreateReferencesRefuseAnArtifactVolume(t *testing.T) {
	t.Parallel()
	want := fmt.Sprintf(libpodCreateDenyArtifactVolume, "container create")
	for name, body := range map[string]string{
		"an artifact by name":     `{"artifact_volumes":[{"source":"quay.io/team/models:latest","destination":"/models"}]}`,
		"an artifact by digest":   `{"artifact_volumes":[{"source":"sha256:` + testImageID + `","destination":"/models"}]}`,
		"an entry with no name":   `{"artifact_volumes":[{}]}`,
		"a null entry":            `{"artifact_volumes":[null]}`,
		"an entry of any shape":   `{"artifact_volumes":["models"]}`,
		"the key in another case": `{"Artifact_Volumes":[{"source":"models"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			refs := libpodContainerCreateReferences(decodeLibpodCreateBody(t, body))
			if refs == nil || refs.denyReason != want {
				t.Fatalf("references = %+v, want denyReason %q", refs, want)
			}
		})
	}
}

// TestLibpodCreateReferencesKeepTheFirstRefusal pins that a later field can't
// replace the reason an earlier one was refused for.
func TestLibpodCreateReferencesKeepTheFirstRefusal(t *testing.T) {
	t.Parallel()
	refs := libpodContainerCreateReferences(decodeLibpodCreateBody(t, `{"volumes_from":"web","volumes":"data"}`))
	want := fmt.Sprintf(libpodCreateDenyUnreadable, "container create", "volumes_from")
	if refs == nil || refs.denyReason != want {
		t.Fatalf("references = %+v, want denyReason %q", refs, want)
	}
}

func TestLibpodCreateReferencesAreBounded(t *testing.T) {
	t.Parallel()
	list := func(count int, format string) string {
		entries := make([]string, 0, count)
		for i := range count {
			entries = append(entries, fmt.Sprintf(format, i))
		}
		return strings.Join(entries, ",")
	}
	tooMany := fmt.Sprintf(libpodCreateDenyTooMany, "container create")

	t.Run("at the bound", func(t *testing.T) {
		t.Parallel()
		refs := libpodContainerCreateReferences(decodeLibpodCreateBody(t, `{"volumes_from":[`+list(libpodCreateMaxReferences, `"ctr-%d"`)+`]}`))
		if refs == nil || refs.denyReason != "" || len(refs.resources) != libpodCreateMaxReferences {
			t.Fatalf("references = %+v, want %d and no refusal", refs, libpodCreateMaxReferences)
		}
	})
	t.Run("repeats don't count", func(t *testing.T) {
		t.Parallel()
		body := `{"volumes_from":[` + list(libpodCreateMaxReferences, `"ctr-%d"`) + `,` + list(libpodCreateMaxReferences, `"ctr-%d"`) + `]}`
		refs := libpodContainerCreateReferences(decodeLibpodCreateBody(t, body))
		if refs == nil || refs.denyReason != "" || len(refs.resources) != libpodCreateMaxReferences {
			t.Fatalf("references = %+v, want %d and no refusal", refs, libpodCreateMaxReferences)
		}
	})
	for field, body := range map[string]string{
		"volumes_from":  `{"volumes_from":[` + list(libpodCreateMaxReferences+1, `"ctr-%d"`) + `]}`,
		"Networks":      `{"Networks":{` + list(libpodCreateMaxReferences+1, `"net-%d":{}`) + `}}`,
		"cni_networks":  `{"cni_networks":[` + list(libpodCreateMaxReferences+1, `"net-%d"`) + `]}`,
		"volumes":       `{"volumes":[` + list(libpodCreateMaxReferences+1, `{"Name":"vol-%d"}`) + `]}`,
		"image_volumes": `{"image_volumes":[` + list(libpodCreateMaxReferences+1, `{"Source":"%064x"}`) + `]}`,
		"across fields": `{"volumes_from":[` + list(libpodCreateMaxReferences, `"ctr-%d"`) + `],"volumes":[{"Name":"data"}]}`,
	} {
		t.Run("past the bound in "+field, func(t *testing.T) {
			t.Parallel()
			refs := libpodContainerCreateReferences(decodeLibpodCreateBody(t, body))
			if refs == nil || refs.denyReason != tooMany {
				t.Fatalf("denyReason = %+v, want %q", refs, tooMany)
			}
		})
	}
}

func TestCheckLibpodCreateReferencesWithNothingNamedPassesThrough(t *testing.T) {
	t.Parallel()
	verdict, reason, err := checkLibpodCreateReferences(t.Context(), fakeInspector{}.inspectResource, nil, Options{Owner: "job-123", LabelKey: DefaultLabelKey})
	if verdict != verdictPassThrough || reason != "" || err != nil {
		t.Fatalf("check = (%v, %q, %v), want pass-through", verdict, reason, err)
	}
}

// TestMiddlewareChecksLibpodCreateReferences drives each reference of both
// creates through the middleware: another owner's resource and one with no
// owner label are a 403, one the daemon can't resolve is a 404, a failed
// lookup is a 502, and the caller's own is forwarded.
func TestMiddlewareChecksLibpodCreateReferences(t *testing.T) {
	t.Parallel()
	references := []struct {
		name   string
		path   string
		body   string
		kind   dockerresource.Kind
		id     string
		noun   string
		source string
	}{
		{name: "container volumes_from", path: "/libpod/containers/create", body: `{"volumes_from":["target:ro"]}`, kind: dockerresource.KindContainer, id: "target", noun: "container", source: "container create volumes_from"},
		{name: "container dependencyContainers", path: "/libpod/containers/create", body: `{"dependencyContainers":["target"]}`, kind: dockerresource.KindContainer, id: "target", noun: "container", source: "container create dependencyContainers"},
		{name: "container Networks", path: "/libpod/containers/create", body: `{"Networks":{"target":{}}}`, kind: dockerresource.KindNetwork, id: "target", noun: "network", source: "container create Networks"},
		{name: "container cni_networks", path: "/libpod/containers/create", body: `{"cni_networks":["target"]}`, kind: dockerresource.KindNetwork, id: "target", noun: "network", source: "container create cni_networks"},
		{name: "container volumes", path: "/libpod/containers/create", body: `{"volumes":[{"Name":"target","Dest":"/data"}]}`, kind: dockerresource.KindVolume, id: "target", noun: "volume", source: "container create volumes"},
		{name: "container image_volumes", path: "/libpod/containers/create", body: `{"image_volumes":[{"Source":"` + testImageID + `","Destination":"/img"}]}`, kind: dockerresource.KindImage, id: testImageID, noun: "image", source: "container create image_volumes"},
		{name: "pod volumes_from", path: "/libpod/pods/create", body: `{"volumes_from":["target"]}`, kind: dockerresource.KindContainer, id: "target", noun: "container", source: "pod create volumes_from"},
		{name: "pod serviceContainerID", path: "/libpod/pods/create", body: `{"serviceContainerID":"target"}`, kind: dockerresource.KindContainer, id: "target", noun: "container", source: "pod create serviceContainerID"},
		{name: "pod Networks", path: "/libpod/pods/create", body: `{"Networks":{"target":{}}}`, kind: dockerresource.KindNetwork, id: "target", noun: "network", source: "pod create Networks"},
		{name: "pod cni_networks", path: "/libpod/pods/create", body: `{"cni_networks":["target"]}`, kind: dockerresource.KindNetwork, id: "target", noun: "network", source: "pod create cni_networks"},
		{name: "pod volumes", path: "/libpod/pods/create", body: `{"volumes":[{"Name":"target","Dest":"/data"}]}`, kind: dockerresource.KindVolume, id: "target", noun: "volume", source: "pod create volumes"},
		{name: "pod image_volumes", path: "/libpod/pods/create", body: `{"image_volumes":[{"Source":"` + testImageID + `","Destination":"/img"}]}`, kind: dockerresource.KindImage, id: testImageID, noun: "image", source: "pod create image_volumes"},
	}
	outcomes := []struct {
		name       string
		result     *inspectResult
		wantStatus int
		wantReason string
	}{
		{
			name:       "another owner's",
			result:     &inspectResult{labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
			wantStatus: http.StatusForbidden,
			wantReason: "libpod owner policy denied access to %s %q referenced by %s",
		},
		{
			name:       "no owner label",
			result:     &inspectResult{labels: map[string]string{}, found: true},
			wantStatus: http.StatusForbidden,
			wantReason: "libpod owner policy denied access to %s %q referenced by %s",
		},
		{
			name:       "unresolved",
			wantStatus: http.StatusNotFound,
			wantReason: "libpod owner policy could not resolve %s %q referenced by %s",
		},
		{
			name:       "lookup failure",
			result:     &inspectResult{err: errors.New("upstream returned 500")},
			wantStatus: http.StatusBadGateway,
		},
		{
			name:       "the caller's own",
			result:     &inspectResult{labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
			wantStatus: http.StatusAccepted,
		},
	}
	for _, reference := range references {
		for _, outcome := range outcomes {
			t.Run(reference.name+"/"+outcome.name, func(t *testing.T) {
				t.Parallel()
				fi := &recordingInspector{resources: map[string]map[string]inspectResult{}}
				if outcome.result != nil {
					fi.resources[string(reference.kind)] = map[string]inspectResult{reference.id: *outcome.result}
				}
				forwarded := false
				handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					forwarded = true
					w.WriteHeader(http.StatusAccepted)
				}))

				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, reference.path, strings.NewReader(reference.body)))

				if rec.Code != outcome.wantStatus {
					t.Fatalf("status = %d, want %d; body: %s", rec.Code, outcome.wantStatus, rec.Body.String())
				}
				if forwarded != (outcome.wantStatus == http.StatusAccepted) {
					t.Fatalf("forwarded = %v with status %d", forwarded, rec.Code)
				}
				if !slices.Contains(fi.calls, resourceInspectCall{kind: reference.kind, id: reference.id}) {
					t.Fatalf("inspect calls = %#v, want %s %q", fi.calls, reference.kind, reference.id)
				}
				if outcome.wantReason == "" {
					return
				}
				var denial struct {
					Message string `json:"message"`
				}
				want := fmt.Sprintf(outcome.wantReason, reference.noun, reference.id, reference.source)
				if err := json.Unmarshal(rec.Body.Bytes(), &denial); err != nil || denial.Message != want {
					t.Fatalf("body = %s, want message %q", rec.Body.String(), want)
				}
			})
		}
	}
}

// TestMiddlewareRefusesUnreadableLibpodCreateReferencesWithoutALookup pins
// that a body refused for its shape is a 403 on the verdict path, with
// nothing asked of the daemon for the references it names.
func TestMiddlewareRefusesUnreadableLibpodCreateReferencesWithoutALookup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		body string
		want string
	}{
		{
			name: "container create",
			path: "/libpod/containers/create",
			body: `{"volumes_from":["mine"],"dependencyContainers":"mine"}`,
			want: "libpod owner policy denied container create with a dependencyContainers reference it can't look up",
		},
		{
			name: "pod create",
			path: "/libpod/pods/create",
			body: `{"volumes_from":["mine"],"serviceContainerID":{}}`,
			want: "libpod owner policy denied pod create with a serviceContainerID reference it can't look up",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fi := &recordingInspector{resources: map[string]map[string]inspectResult{
				"containers": {"mine": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
			}}
			handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("a create with an unreadable reference was forwarded")
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body)))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			var denial struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &denial); err != nil || denial.Message != tt.want {
				t.Fatalf("body = %s, want message %q", rec.Body.String(), tt.want)
			}
			if len(fi.calls) != 0 {
				t.Fatalf("inspect calls = %#v, want none", fi.calls)
			}
		})
	}
}

// TestMiddlewareLibpodPodCreateWithoutAnInfraContainer drives a pod create
// with `no_infra` through the middleware. Podman reads the key with
// encoding/json: in any letter case, the last of a repeated key winning. The
// body forwarded is the one that was decoded, so Podman sees `no_infra` once,
// with the value the check went by.
func TestMiddlewareLibpodPodCreateWithoutAnInfraContainer(t *testing.T) {
	t.Parallel()
	const theirs = `"volumes":[{"Name":"theirs","Dest":"/data"}],"volumes_from":["theirs"],"cni_networks":["theirs"],"image_volumes":[{"Source":"theirs"}]`
	tests := []struct {
		name        string
		body        string
		wantStatus  int
		wantReason  string
		wantLookups []resourceInspectCall
	}{
		{
			name:       "no infra container, infra-only fields naming another owner's resources",
			body:       `{"no_infra":true,` + theirs + `}`,
			wantStatus: http.StatusAccepted,
		},
		{
			name:       "the key in another case",
			body:       `{"No_Infra":true,` + theirs + `}`,
			wantStatus: http.StatusAccepted,
		},
		{
			name:       "the key given twice, true last",
			body:       `{"no_infra":false,` + theirs + `,"no_infra":true}`,
			wantStatus: http.StatusAccepted,
		},
		{
			name:        "the key given twice, false last",
			body:        `{"no_infra":true,"volumes_from":["theirs"],"no_infra":false}`,
			wantStatus:  http.StatusForbidden,
			wantReason:  `libpod owner policy denied access to container "theirs" referenced by pod create volumes_from`,
			wantLookups: []resourceInspectCall{{kind: dockerresource.KindContainer, id: "theirs"}},
		},
		{
			// Two spellings of one key: nothing here can say which Podman
			// would keep once the body is re-encoded, so it's refused.
			name:       "the key spelled two ways",
			body:       `{"no_infra":true,"NO_INFRA":false,"volumes_from":["theirs"]}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:        "no_infra that isn't a bool",
			body:        `{"no_infra":"true","volumes_from":["theirs"]}`,
			wantStatus:  http.StatusForbidden,
			wantReason:  `libpod owner policy denied access to container "theirs" referenced by pod create volumes_from`,
			wantLookups: []resourceInspectCall{{kind: dockerresource.KindContainer, id: "theirs"}},
		},
		{
			name:        "no infra container, another owner's service container",
			body:        `{"no_infra":true,"serviceContainerID":"theirs"}`,
			wantStatus:  http.StatusForbidden,
			wantReason:  `libpod owner policy denied access to container "theirs" referenced by pod create serviceContainerID`,
			wantLookups: []resourceInspectCall{{kind: dockerresource.KindContainer, id: "theirs"}},
		},
		{
			name:        "no infra container, the caller's own service container",
			body:        `{"no_infra":true,"serviceContainerID":"mine",` + theirs + `}`,
			wantStatus:  http.StatusAccepted,
			wantLookups: []resourceInspectCall{{kind: dockerresource.KindContainer, id: "mine"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			foreign := inspectResult{labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true}
			fi := &recordingInspector{resources: map[string]map[string]inspectResult{
				"containers": {"theirs": foreign, "mine": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
				"networks":   {"theirs": foreign},
				"volumes":    {"theirs": foreign},
				"images":     {"theirs": foreign},
			}}
			var forwarded []byte
			handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded, _ = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusAccepted)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(tt.body)))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if !slices.Equal(fi.calls, tt.wantLookups) {
				t.Fatalf("inspect calls = %#v, want %#v", fi.calls, tt.wantLookups)
			}
			if tt.wantReason != "" {
				var denial struct {
					Message string `json:"message"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &denial); err != nil || denial.Message != tt.wantReason {
					t.Fatalf("body = %s, want message %q", rec.Body.String(), tt.wantReason)
				}
			}
			if tt.wantStatus != http.StatusAccepted {
				if forwarded != nil {
					t.Fatalf("a refused create was forwarded: %s", forwarded)
				}
				return
			}
			// What Podman decodes from the forwarded body is a pod with no
			// infra container, from a key that's there once.
			var pod struct {
				NoInfra bool              `json:"no_infra"`
				Labels  map[string]string `json:"labels"`
			}
			if err := json.Unmarshal(forwarded, &pod); err != nil {
				t.Fatalf("decode forwarded body %s: %v", forwarded, err)
			}
			if !pod.NoInfra {
				t.Fatalf("forwarded body %s decodes to a pod with an infra container", forwarded)
			}
			if got := strings.Count(strings.ToLower(string(forwarded)), `"no_infra"`); got != 1 {
				t.Fatalf("forwarded body %s carries no_infra %d times, want once", forwarded, got)
			}
			if pod.Labels["com.sockguard.owner"] != "job-123" {
				t.Fatalf("forwarded labels = %v, want the owner label stamped", pod.Labels)
			}
		})
	}
}

// TestMiddlewareLibpodCreateImageVolumeFollowsUnownedImagePolicy pins that an
// image mounted as a volume gets the same answer as the image a container is
// created from: one with no owner label is usable only with
// allow_unowned_images.
func TestMiddlewareLibpodCreateImageVolumeFollowsUnownedImagePolicy(t *testing.T) {
	t.Parallel()
	for _, allowUnowned := range []bool{true, false} {
		t.Run(fmt.Sprintf("allow_unowned_images=%v", allowUnowned), func(t *testing.T) {
			t.Parallel()
			fi := fakeInspector{resources: map[string]map[string]inspectResult{
				"images": {testImageID: {labels: map[string]string{}, found: true}},
			}}
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: allowUnowned}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusAccepted)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/libpod/containers/create", strings.NewReader(`{"image_volumes":[{"Source":"`+testImageID+`","Destination":"/img"}]}`)))

			want := http.StatusForbidden
			if allowUnowned {
				want = http.StatusAccepted
			}
			if rec.Code != want {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, want, rec.Body.String())
			}
		})
	}
}

// TestMiddlewareChecksLibpodCgroupNamespaceTarget covers cgroupns joining the
// other five namespaces: a container create whose cgroup namespace is another
// owner's container is refused, and the namespace-sharing opt-out covers it
// like the rest.
func TestMiddlewareChecksLibpodCgroupNamespaceTarget(t *testing.T) {
	t.Parallel()
	const body = `{"cgroupns":{"nsmode":"container","value":"target"}}`
	tests := []struct {
		name       string
		owner      string
		allowCross bool
		wantStatus int
	}{
		{name: "another owner's container", owner: "job-999", wantStatus: http.StatusForbidden},
		{name: "the caller's own container", owner: "job-123", wantStatus: http.StatusAccepted},
		{name: "another owner's container with namespace sharing allowed", owner: "job-999", allowCross: true, wantStatus: http.StatusAccepted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fi := fakeInspector{resources: map[string]map[string]inspectResult{
				"containers": {"target": {labels: map[string]string{"com.sockguard.owner": tt.owner}, found: true}},
			}}
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowCrossOwnerNamespaceSharing: tt.allowCross}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusAccepted)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/libpod/containers/create", strings.NewReader(body)))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantStatus == http.StatusForbidden && !strings.Contains(rec.Body.String(), `namespace-sharing target container \"target\"`) {
				t.Fatalf("deny body = %s, want the namespace-sharing target reason", rec.Body.String())
			}
		})
	}
}

// TestMiddlewareNamespaceSharingOptOutLeavesLibpodCreateReferencesChecked pins
// that allow_cross_owner_namespace_sharing opens namespace targets and
// nothing else a create names.
func TestMiddlewareNamespaceSharingOptOutLeavesLibpodCreateReferencesChecked(t *testing.T) {
	t.Parallel()
	fi := fakeInspector{resources: map[string]map[string]inspectResult{
		"containers": {"target": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true}},
	}}
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowCrossOwnerNamespaceSharing: true}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("a create with another owner's volumes_from container was forwarded")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/libpod/containers/create", strings.NewReader(`{"volumes_from":["target"]}`)))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}
