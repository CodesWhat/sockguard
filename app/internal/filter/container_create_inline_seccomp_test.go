package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestContainerCreateInlineSeccompProfile(t *testing.T) {
	const denied = "container create denied: an inline seccomp profile is not allowed while deny_unconfined_seccomp is set"
	deny := ContainerCreateOptions{AllowAllCapabilities: true, DenyUnconfinedSeccomp: true}
	tests := []struct {
		name string
		opts ContainerCreateOptions
		body string
		want string
	}{
		{"empty object", deny, `{"HostConfig":{"SecurityOpt":["seccomp={}"]}}`, denied},
		{"allow-all document", deny, `{"HostConfig":{"SecurityOpt":["seccomp={\"defaultAction\":\"SCMP_ACT_ALLOW\"}"]}}`, denied},
		{"colon separator", deny, `{"HostConfig":{"SecurityOpt":["seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\"}"]}}`, denied},
		{"null", deny, `{"HostConfig":{"SecurityOpt":["seccomp=null"]}}`, denied},
		{"whitespace padded", deny, `{"HostConfig":{"SecurityOpt":["seccomp=  {} "]}}`, denied},
		{"array", deny, `{"HostConfig":{"SecurityOpt":["seccomp=[]"]}}`, denied},
		{"upper-case key", deny, `{"HostConfig":{"SecurityOpt":["SECCOMP={}"]}}`, denied},
		{"inline wins over an allowlist that names it", ContainerCreateOptions{AllowAllCapabilities: true, DenyUnconfinedSeccomp: true, AllowedSeccompProfiles: []string{"{}"}}, `{"HostConfig":{"SecurityOpt":["seccomp={}"]}}`, denied},
		{"named profile passes", deny, `{"HostConfig":{"SecurityOpt":["seccomp=/etc/sockguard/profile.json"]}}`, ""},
		{"builtin passes", deny, `{"HostConfig":{"SecurityOpt":["seccomp=builtin"]}}`, ""},
		{"omitted passes", deny, `{"HostConfig":{}}`, ""},
		{"inline passes when deny_unconfined_seccomp is off", ContainerCreateOptions{AllowAllCapabilities: true}, `{"HostConfig":{"SecurityOpt":["seccomp={}"]}}`, ""},
		{"allowlist still rejects an unlisted inline document", ContainerCreateOptions{AllowAllCapabilities: true, AllowedSeccompProfiles: []string{"default"}}, `{"HostConfig":{"SecurityOpt":["seccomp={}"]}}`, `container create denied: seccomp profile "{}" is not in the allowed list`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))
			reason, err := newContainerCreatePolicy(tt.opts).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.want {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.want)
			}
		})
	}
}

func TestLibpodContainerCreateInlineSeccompProfile(t *testing.T) {
	const (
		denyUnconfined = "libpod container create denied: an inline seccomp profile (seccomp_profile) is not allowed while deny_unconfined_seccomp is set"
		denyAllowlist  = "libpod container create denied: an inline seccomp profile (seccomp_profile) is not in the allowed list"
	)
	cases := []struct {
		name string
		opts LibpodContainerCreateOptions
		body string
		want string
	}{
		{"empty object", LibpodContainerCreateOptions{DenyUnconfinedSeccomp: true}, `{"image":"alpine","systemd":"false","seccomp_profile":"{}"}`, denyUnconfined},
		{"allow-all document", LibpodContainerCreateOptions{DenyUnconfinedSeccomp: true}, `{"image":"alpine","systemd":"false","seccomp_profile":"{\"defaultAction\":\"SCMP_ACT_ALLOW\"}"}`, denyUnconfined},
		{"null string", LibpodContainerCreateOptions{DenyUnconfinedSeccomp: true}, `{"image":"alpine","systemd":"false","seccomp_profile":"null"}`, denyUnconfined},
		{"whitespace only", LibpodContainerCreateOptions{DenyUnconfinedSeccomp: true}, `{"image":"alpine","systemd":"false","seccomp_profile":" "}`, denyUnconfined},
		{"another key case", LibpodContainerCreateOptions{DenyUnconfinedSeccomp: true}, `{"image":"alpine","systemd":"false","Seccomp_Profile":"{}"}`, denyUnconfined},
		{"both separators", LibpodContainerCreateOptions{DenyUnconfinedSeccomp: true}, `{"image":"alpine","systemd":"false","seccomp_profile":"{}","seccomp_profile_path":"default"}`, denyUnconfined},
		{"allowlist without the content", LibpodContainerCreateOptions{AllowedSeccompProfiles: []string{"default"}}, `{"image":"alpine","systemd":"false","seccomp_profile":"{}"}`, denyAllowlist},
		{"allowlist naming the content passes", LibpodContainerCreateOptions{AllowedSeccompProfiles: []string{"{}"}}, `{"image":"alpine","systemd":"false","seccomp_profile":"{}"}`, ""},
		{"omitted with default allowlist passes", LibpodContainerCreateOptions{DenyUnconfinedSeccomp: true, AllowedSeccompProfiles: []string{"default"}}, `{"image":"alpine","systemd":"false"}`, ""},
		{"empty string passes", LibpodContainerCreateOptions{DenyUnconfinedSeccomp: true}, `{"image":"alpine","systemd":"false","seccomp_profile":""}`, ""},
		{"inline passes with no gate configured", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","seccomp_profile":"{}"}`, ""},
		{"path still gated", LibpodContainerCreateOptions{DenyUnconfinedSeccomp: true}, `{"image":"alpine","systemd":"false","seccomp_profile_path":"unconfined"}`, "libpod container create denied: unconfined seccomp profile is not allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inspectLibpod(t, newLibpodContainerCreatePolicy(tc.opts), []byte(tc.body))
			if got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}
