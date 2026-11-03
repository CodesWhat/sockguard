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
		{"exec in capitals is no option", []string{"EXEC"}, false},
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
		{"padded token is no option", []string{" nosuid , dev "}, false},
		{"capital NOEXEC restricts nothing", []string{"exec,NOEXEC"}, true},
		{"dev with value 1", []string{"dev=1"}, true},
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

func TestTmpfsPostureFullyRestricted(t *testing.T) {
	tests := []struct {
		name string
		opts string
		want bool
	}{
		{"empty", "", false},
		{"noexec only", "noexec", false},
		{"missing nodev", "noexec,nosuid", false},
		{"all three", "nosuid,nodev,noexec", true},
		{"all three with a size", "rw,noexec,nosuid,nodev,size=64m", true},
		{"exec after all three", "noexec,nosuid,nodev,exec", false},
		{"exec before all three", "exec,noexec,nosuid,nodev", true},
		{"suid=1 after all three", "noexec,nosuid,nodev,suid=1", false},
		{"nosuid=0 after all three", "noexec,nodev,nosuid,nosuid=0", false},
		{"capital NOEXEC does not count", "NOEXEC,nosuid,nodev", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tmpfsPostureOfList(tt.opts).fullyRestricted(); got != tt.want {
				t.Errorf("tmpfsPostureOfList(%q).fullyRestricted() = %t, want %t", tt.opts, got, tt.want)
			}
		})
	}
}
