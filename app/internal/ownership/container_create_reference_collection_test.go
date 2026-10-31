package ownership

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/dockerresource"
)

func TestContainerCreateReferenceCollectionPreservesSources(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"Image":" image ","HostConfig":{"Binds":["data:/data","data:/again","/host:/host","no-colon",17],"Mounts":[{"Type":"volume","Source":"other"},{"Type":"bind","Source":"ignored"},{"Type":"volume","Source":"data"},null],"NetworkMode":"net"}}`,
		`{"image":" image ","hostconfig":{"binds":["data:/data","data:/again","/host:/host","no-colon",17],"mounts":[{"type":"VOLUME","source":"other"},{"type":"bind","source":"ignored"},{"type":"volume","source":"data"},null],"networkmode":"net"}}`,
	} {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatal(err)
		}
		want := []embeddedOwnershipReference{
			{dockerresource.KindImage, "image", "container Image"},
			{dockerresource.KindVolume, "data", "container HostConfig.Binds"},
			{dockerresource.KindVolume, "other", "container HostConfig.Mounts"},
			{dockerresource.KindNetwork, "net", "container HostConfig.NetworkMode"},
		}
		if got := containerCreateEmbeddedOwnershipReferences(decoded); !reflect.DeepEqual(got, want) {
			t.Fatalf("references = %#v, want %#v", got, want)
		}
	}
}

func TestContainerCreateEndpointReferencesStaySorted(t *testing.T) {
	t.Parallel()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(`{"networkingconfig":{"endpointsconfig":{"z-net":{"networkid":"z-id"},"bridge":{"NetworkID":"bridge-id"},"a-net":{"NetworkID":"a-id"}}}}`), &decoded); err != nil {
		t.Fatal(err)
	}
	want := []embeddedOwnershipReference{
		{dockerresource.KindNetwork, "a-net", "container NetworkingConfig.EndpointsConfig"},
		{dockerresource.KindNetwork, "a-id", "container NetworkingConfig.EndpointsConfig.NetworkID"},
		{dockerresource.KindNetwork, "bridge-id", "container NetworkingConfig.EndpointsConfig.NetworkID"},
		{dockerresource.KindNetwork, "z-net", "container NetworkingConfig.EndpointsConfig"},
		{dockerresource.KindNetwork, "z-id", "container NetworkingConfig.EndpointsConfig.NetworkID"},
	}
	for range 20 {
		if got := containerCreateEmbeddedOwnershipReferences(decoded); !reflect.DeepEqual(got, want) {
			t.Fatalf("references = %#v, want %#v", got, want)
		}
	}
}

func TestContainerCreateReferenceCollectionChecksEveryCaseVariant(t *testing.T) {
	t.Parallel()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(`{"HostConfig":{"Binds":["first:/one"]},"hostconfig":{"binds":["second:/two"],"mounts":[{"TYPE":"volume","source":"third"}]},"NetworkingConfig":{"EndpointsConfig":{"fourth":{}}},"networkingconfig":{"endpointsconfig":{"fifth":{}}}}`), &decoded); err != nil {
		t.Fatal(err)
	}
	got := make(map[string]dockerresource.Kind)
	for _, ref := range containerCreateEmbeddedOwnershipReferences(decoded) {
		got[ref.identifier] = ref.kind
	}
	want := map[string]dockerresource.Kind{
		"first": dockerresource.KindVolume, "second": dockerresource.KindVolume, "third": dockerresource.KindVolume,
		"fourth": dockerresource.KindNetwork, "fifth": dockerresource.KindNetwork,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("references = %#v, want %#v", got, want)
	}
}
