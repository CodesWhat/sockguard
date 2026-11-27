package filter_test

import "net/http"

// systemPathsDeniedCases returns the create-hardening rows every write
// preset must refuse: unmasking /proc and /sys (systempaths=unconfined or an
// explicit MaskedPaths/ReadonlyPaths list) and disabling SELinux labelling.
// base is the opening of an otherwise allowed create body, without its
// closing brace. withSeccompApparmor adds the seccomp and AppArmor rows for
// the presets whose create block carries those rails.
func systemPathsDeniedCases(base string, withSeccompApparmor bool) []presetCase {
	hc := func(inner string) string { return base + `,"HostConfig":{` + inner + `}}` }
	secOpt := func(opt string) string { return hc(`"SecurityOpt":["` + opt + `"]`) }
	cases := []presetCase{
		{"create-systempaths-unconfined-denied", http.MethodPost, "/containers/create", secOpt("systempaths=unconfined"), false},
		{"create-selinux-disable-denied", http.MethodPost, "/containers/create", secOpt("label=disable"), false},
		{"create-selinux-disable-colon-denied", http.MethodPost, "/containers/create", secOpt("label:disable"), false},
		{"create-masked-paths-empty-denied", http.MethodPost, "/containers/create", hc(`"MaskedPaths":[]`), false},
		{"create-readonly-paths-empty-denied", http.MethodPost, "/containers/create", hc(`"ReadonlyPaths":[]`), false},
		{"create-readonly-paths-list-denied", http.MethodPost, "/containers/create", hc(`"ReadonlyPaths":["/x"]`), false},
		{"create-masked-paths-list-denied", http.MethodPost, "/containers/create", hc(`"MaskedPaths":["/x"]`), false},
		{"create-no-new-privileges-allowed", http.MethodPost, "/containers/create", secOpt("no-new-privileges:true"), true},
	}
	if withSeccompApparmor {
		cases = append(cases,
			presetCase{"create-unconfined-apparmor-denied", http.MethodPost, "/containers/create", secOpt("apparmor=unconfined"), false},
			presetCase{"create-unconfined-seccomp-denied", http.MethodPost, "/containers/create", secOpt("seccomp=unconfined"), false},
			presetCase{"create-unconfined-seccomp-colon-denied", http.MethodPost, "/containers/create", secOpt("seccomp:unconfined"), false},
			presetCase{"create-inline-seccomp-denied", http.MethodPost, "/containers/create", secOpt(`seccomp={\"defaultAction\":\"SCMP_ACT_ALLOW\"}`), false},
		)
	}
	return cases
}
