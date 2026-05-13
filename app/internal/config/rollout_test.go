package config

import "testing"

func TestParseRolloutMode(t *testing.T) {
	tests := []struct {
		input    string
		wantMode RolloutMode
		wantOK   bool
	}{
		{"", RolloutEnforce, true},
		{"enforce", RolloutEnforce, true},
		{"ENFORCE", RolloutEnforce, true},
		{"  enforce  ", RolloutEnforce, true},
		{"warn", RolloutWarn, true},
		{"Warn", RolloutWarn, true},
		{"audit", RolloutAudit, true},
		{"AUDIT", RolloutAudit, true},
		{"observe", RolloutEnforce, false},
		{"true", RolloutEnforce, false},
		{"1", RolloutEnforce, false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, ok := ParseRolloutMode(tt.input)
			if got != tt.wantMode || ok != tt.wantOK {
				t.Fatalf("ParseRolloutMode(%q) = (%q, %v), want (%q, %v)",
					tt.input, got, ok, tt.wantMode, tt.wantOK)
			}
		})
	}
}

func TestRolloutMode_AllowsPassThrough(t *testing.T) {
	tests := []struct {
		mode RolloutMode
		want bool
	}{
		{RolloutEnforce, false},
		{RolloutWarn, true},
		{RolloutAudit, true},
		{RolloutMode("unknown"), false},
	}
	for _, tt := range tests {
		t.Run(tt.mode.String(), func(t *testing.T) {
			if got := tt.mode.AllowsPassThrough(); got != tt.want {
				t.Fatalf("AllowsPassThrough() = %v, want %v", got, tt.want)
			}
		})
	}
}
