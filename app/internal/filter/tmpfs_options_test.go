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

func TestCheckStructuredTmpfsOptions(t *testing.T) {
	tests := []struct {
		name    string
		options [][]string
		want    tmpfsStructuredVerdict
	}{
		{"none", nil, tmpfsStructuredOK},
		{"size", [][]string{{"size", "64m"}}, tmpfsStructuredOK},
		{"noexec", [][]string{{"noexec"}}, tmpfsStructuredOK},
		{"exec key", [][]string{{"exec"}}, tmpfsStructuredPrivileged},
		{"exec key with falsy value is still refused", [][]string{{"exec", "0"}}, tmpfsStructuredPrivileged},
		{"later noexec entry does not clear exec", [][]string{{"exec"}, {"noexec"}}, tmpfsStructuredPrivileged},
		{"suid=1 in one element", [][]string{{"suid=1"}}, tmpfsStructuredPrivileged},
		{"comma list ending in dev", [][]string{{"nosuid,dev"}}, tmpfsStructuredPrivileged},
		{"comma list restricted last", [][]string{{"exec,noexec"}}, tmpfsStructuredOK},
		{"empty entry", [][]string{{}}, tmpfsStructuredMalformed},
		{"three elements", [][]string{{"a", "b", "c"}}, tmpfsStructuredMalformed},
		{"blank key", [][]string{{" "}}, tmpfsStructuredMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := checkStructuredTmpfsOptions(tt.options); got != tt.want {
				t.Errorf("checkStructuredTmpfsOptions(%q) = %d, want %d", tt.options, got, tt.want)
			}
		})
	}
}
