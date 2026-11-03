package filter

import "testing"

func TestTmpfsPostureEnablesPrivilege(t *testing.T) {
	tests := []struct {
		name string
		opts []string
		want bool
	}{
		{"empty", nil, false},
		{"restrictions only", []string{"noexec,nosuid,nodev"}, false},
		{"size only", []string{"size=64m,mode=1777"}, false},
		{"exec", []string{"exec"}, true},
		{"suid", []string{"suid"}, true},
		{"dev", []string{"dev"}, true},
		{"exec in capitals", []string{"EXEC"}, true},
		{"last wins restricts", []string{"exec,noexec"}, false},
		{"last wins enables", []string{"noexec,exec"}, true},
		{"last wins across elements", []string{"exec", "noexec"}, false},
		{"suid=1", []string{"suid=1"}, true},
		{"dev=true", []string{"dev=true"}, true},
		{"exec= with no value", []string{"exec="}, true},
		{"exec=yes", []string{"exec=yes"}, true},
		{"exec=0 restricts", []string{"exec=0"}, false},
		{"suid=off restricts", []string{"suid=off"}, false},
		{"noexec=0 enables exec", []string{"noexec=0"}, true},
		{"noexec=1 restricts", []string{"noexec=1"}, false},
		{"spaces around tokens", []string{" nosuid , dev "}, true},
		{"capital NOEXEC restricts nothing", []string{"exec,NOEXEC"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tmpfsPostureOfList(tt.opts...).enablesPrivilege(); got != tt.want {
				t.Errorf("tmpfsPostureOfList(%q).enablesPrivilege() = %t, want %t", tt.opts, got, tt.want)
			}
		})
	}
}
