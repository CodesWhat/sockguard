package config

import "testing"

func TestRolloutModeString(t *testing.T) {
	tests := []struct {
		mode RolloutMode
		want string
	}{
		{RolloutEnforce, "enforce"},
		{RolloutWarn, "warn"},
		{RolloutAudit, "audit"},
		{RolloutMode("custom"), "custom"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.mode.String()
			if got != tt.want {
				t.Errorf("RolloutMode(%q).String() = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

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
