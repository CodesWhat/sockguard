package dockerresource

import (
	"strings"
	"testing"
)

func TestDecodeLabelsAllKinds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		kind  Kind
		body  string
		wantK string
		wantV string
	}{
		{
			name:  "container",
			kind:  KindContainer,
			body:  `{"Config":{"Labels":{"env":"prod"}}}`,
			wantK: "env", wantV: "prod",
		},
		{
			name:  "image config labels",
			kind:  KindImage,
			body:  `{"Config":{"Labels":{"tier":"web"}},"ContainerConfig":{"Labels":{}}}`,
			wantK: "tier", wantV: "web",
		},
		{
			name:  "image fallback to ContainerConfig",
			kind:  KindImage,
			body:  `{"Config":{"Labels":{}},"ContainerConfig":{"Labels":{"tier":"db"}}}`,
			wantK: "tier", wantV: "db",
		},
		{
			name:  "network",
			kind:  KindNetwork,
			body:  `{"Labels":{"net":"overlay"}}`,
			wantK: "net", wantV: "overlay",
		},
		{
			name:  "volume",
			kind:  KindVolume,
			body:  `{"Labels":{"vol":"data"}}`,
			wantK: "vol", wantV: "data",
		},
		{
			name:  "service",
			kind:  KindService,
			body:  `{"Spec":{"Labels":{"svc":"api"}}}`,
			wantK: "svc", wantV: "api",
		},
		{
			name:  "secret",
			kind:  KindSecret,
			body:  `{"Spec":{"Labels":{"sec":"key"}}}`,
			wantK: "sec", wantV: "key",
		},
		{
			name:  "config",
			kind:  KindConfig,
			body:  `{"Spec":{"Labels":{"cfg":"app"}}}`,
			wantK: "cfg", wantV: "app",
		},
		{
			name:  "node",
			kind:  KindNode,
			body:  `{"Spec":{"Labels":{"role":"worker"}}}`,
			wantK: "role", wantV: "worker",
		},
		{
			name:  "swarm",
			kind:  KindSwarm,
			body:  `{"Spec":{"Labels":{"cluster":"prod"}}}`,
			wantK: "cluster", wantV: "prod",
		},
		{
			name:  "task with top-level labels",
			kind:  KindTask,
			body:  `{"Labels":{"t":"1"},"Spec":{"ContainerSpec":{"Labels":{"t":"2"}}}}`,
			wantK: "t", wantV: "1",
		},
		{
			name:  "task fallback to ContainerSpec",
			kind:  KindTask,
			body:  `{"Labels":{},"Spec":{"ContainerSpec":{"Labels":{"t":"2"}}}}`,
			wantK: "t", wantV: "2",
		},
		{
			name:  "libpod pod",
			kind:  KindLibpodPod,
			body:  `{"Labels":{"team":"a"}}`,
			wantK: "team", wantV: "a",
		},
		{
			name:  "libpod network lowercase labels",
			kind:  KindLibpodNetwork,
			body:  `{"labels":{"net":"custom"}}`,
			wantK: "net", wantV: "custom",
		},
		{
			name:  "libpod network array-wrapped response",
			kind:  KindLibpodNetwork,
			body:  `[{"labels":{"net":"custom"}}]`,
			wantK: "net", wantV: "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels, err := DecodeLabels(strings.NewReader(tt.body), tt.kind)
			if err != nil {
				t.Fatalf("DecodeLabels error = %v", err)
			}
			if labels[tt.wantK] != tt.wantV {
				t.Fatalf("labels[%q] = %q, want %q", tt.wantK, labels[tt.wantK], tt.wantV)
			}
		})
	}
}

func TestDecodeLabelsUnsupportedKind(t *testing.T) {
	t.Parallel()
	_, err := DecodeLabels(strings.NewReader(`{}`), "bogus")
	if err == nil || !strings.Contains(err.Error(), "unsupported resource kind") {
		t.Fatalf("error = %v, want unsupported resource kind", err)
	}
}

func TestDecodeLabelsDecodeErrors(t *testing.T) {
	t.Parallel()
	kinds := []Kind{
		KindContainer,
		KindImage,
		KindNetwork,
		KindVolume,
		KindService,
		KindSecret,
		KindConfig,
		KindNode,
		KindSwarm,
		KindTask,
		KindLibpodPod,
		KindLibpodNetwork,
	}
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			_, err := DecodeLabels(strings.NewReader(`not-json`), kind)
			if err == nil {
				t.Fatalf("DecodeLabels(bad JSON, %s) expected decode error", kind)
			}
		})
	}
}

func TestDecodeLibpodLabelsUnsupportedKind(t *testing.T) {
	t.Parallel()
	_, err := DecodeLibpodLabels(strings.NewReader(`{}`), KindContainer)
	if err == nil || !strings.Contains(err.Error(), "unsupported libpod resource kind") {
		t.Fatalf("error = %v, want unsupported libpod resource kind", err)
	}
}

func TestDecodeLibpodLabelsNetworkEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		body       string
		wantLabels map[string]string
		wantErr    bool
	}{
		{
			name:       "bare object",
			body:       `{"labels":{"net":"custom"}}`,
			wantLabels: map[string]string{"net": "custom"},
		},
		{
			name:       "single-element array",
			body:       `[{"labels":{"net":"custom"}}]`,
			wantLabels: map[string]string{"net": "custom"},
		},
		{name: "empty array", body: `[]`, wantErr: true},
		{name: "multiple objects", body: `[{"labels":{}},{"labels":{}}]`, wantErr: true},
		{name: "null object", body: `[null]`, wantErr: true},
		{name: "bare null", body: `null`, wantErr: true},
		{
			name:       "array with leading whitespace",
			body:       "  \n[{\"labels\":{\"net\":\"custom\"}}]",
			wantLabels: map[string]string{"net": "custom"},
		},
		{
			name:    "malformed array element",
			body:    `[{"labels": not-json}]`,
			wantErr: true,
		},
		{
			name:    "malformed object",
			body:    `{"labels": not-json}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels, err := DecodeLibpodLabels(strings.NewReader(tt.body), KindLibpodNetwork)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("DecodeLibpodLabels(%q) expected error", tt.body)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeLibpodLabels(%q) error = %v", tt.body, err)
			}
			if len(labels) != len(tt.wantLabels) {
				t.Fatalf("labels = %#v, want %#v", labels, tt.wantLabels)
			}
			for k, v := range tt.wantLabels {
				if labels[k] != v {
					t.Fatalf("labels[%q] = %q, want %q", k, labels[k], v)
				}
			}
		})
	}
}
