package filter

import "testing"

func TestOverlayLibpodUnifiedResources(t *testing.T) {
	ptr := func(n int64) *int64 { return &n }
	tests := []struct {
		name    string
		start   containerCreateHostConfig
		unified map[string]string
		want    containerCreateHostConfig
	}{
		{"memory.max max clears", containerCreateHostConfig{Memory: 5}, map[string]string{"memory.max": "max"}, containerCreateHostConfig{}},
		{"memory.max number sets", containerCreateHostConfig{}, map[string]string{"memory.max": "1024"}, containerCreateHostConfig{Memory: 1024}},
		{"memory.max garbage clears", containerCreateHostConfig{Memory: 5}, map[string]string{"memory.max": "lots"}, containerCreateHostConfig{}},
		{"memory.high untouched", containerCreateHostConfig{Memory: 5}, map[string]string{"memory.high": "1"}, containerCreateHostConfig{Memory: 5}},
		{"pids.max max clears", containerCreateHostConfig{PidsLimit: ptr(50)}, map[string]string{"pids.max": "max"}, containerCreateHostConfig{PidsLimit: ptr(-1)}},
		{"pids.max number sets", containerCreateHostConfig{}, map[string]string{"pids.max": "64"}, containerCreateHostConfig{PidsLimit: ptr(64)}},
		{"cpu.max max clears quota", containerCreateHostConfig{CpuQuota: 50000, NanoCpus: 5e8}, map[string]string{"cpu.max": "max 100000"}, containerCreateHostConfig{CpuPeriod: 100000}},
		{"cpu.max quota and period", containerCreateHostConfig{}, map[string]string{"cpu.max": "50000 100000"}, containerCreateHostConfig{CpuQuota: 50000, CpuPeriod: 100000}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.start
			overlayLibpodUnifiedResources(&got, tt.unified)
			if got.Memory != tt.want.Memory || got.CpuQuota != tt.want.CpuQuota || got.CpuPeriod != tt.want.CpuPeriod || got.NanoCpus != tt.want.NanoCpus {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
			if (got.PidsLimit == nil) != (tt.want.PidsLimit == nil) || (got.PidsLimit != nil && *got.PidsLimit != *tt.want.PidsLimit) {
				t.Errorf("PidsLimit got %v, want %v", got.PidsLimit, tt.want.PidsLimit)
			}
		})
	}
}
