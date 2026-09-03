package config

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/filter"
)

func TestContainerRemoveConfigLoadsValidatesAndWiresAllControls(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
request_body:
  container_remove:
    allow_force: true
    allow_remove_volumes: true
    allow_remove_links: true
`))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}
	if err := ValidateStructural(cfg); err != nil {
		t.Fatalf("ValidateStructural() error = %v", err)
	}

	wantConfig := ContainerRemoveRequestBodyConfig{
		AllowForce:         true,
		AllowRemoveVolumes: true,
		AllowRemoveLinks:   true,
	}
	if got := cfg.RequestBody.ContainerRemove; !reflect.DeepEqual(got, wantConfig) {
		t.Errorf("RequestBody.ContainerRemove = %#v, want %#v", got, wantConfig)
	}

	wantPolicy := filter.ContainerRemoveOptions{
		AllowForce:         true,
		AllowRemoveVolumes: true,
		AllowRemoveLinks:   true,
	}
	if got := cfg.RequestBody.ToFilterOptions().ContainerRemove; !reflect.DeepEqual(got, wantPolicy) {
		t.Errorf("ToFilterOptions().ContainerRemove = %#v, want %#v", got, wantPolicy)
	}
}

func TestMultiListenerPresetScopesContainerRemoveControlsToCIProfile(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "multi-listener.yaml"))
	if err != nil {
		t.Fatalf("load multi-listener.yaml: %v", err)
	}

	want := ContainerRemoveRequestBodyConfig{
		AllowForce:         true,
		AllowRemoveVolumes: true,
	}
	for _, profile := range cfg.Clients.Profiles {
		switch profile.Name {
		case "ci":
			if got := profile.RequestBody.ContainerRemove; !reflect.DeepEqual(got, want) {
				t.Errorf("ci container remove config = %#v, want %#v", got, want)
			}
		case "ops":
			if got := profile.RequestBody.ContainerRemove; !reflect.DeepEqual(got, ContainerRemoveRequestBodyConfig{}) {
				t.Errorf("ops container remove config = %#v, want secure defaults", got)
			}
		}
	}
}
