package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestContainerCreatePolicyEnforcesHardeningRails(t *testing.T) {
	tests := []struct {
		name       string
		opts       ContainerCreateOptions
		body       string
		wantReason string
	}{
		{
			name:       "no-new-privileges missing",
			opts:       ContainerCreateOptions{RequireNoNewPrivileges: true, AllowAllCapabilities: true},
			body:       `{"HostConfig":{}}`,
			wantReason: "container create denied: no-new-privileges is required (set HostConfig.SecurityOpt to include \"no-new-privileges:true\")",
		},
		{
			name:       "no-new-privileges set wrong value",
			opts:       ContainerCreateOptions{RequireNoNewPrivileges: true, AllowAllCapabilities: true},
			body:       `{"HostConfig":{"SecurityOpt":["no-new-privileges:false"]}}`,
			wantReason: "container create denied: no-new-privileges is required (set HostConfig.SecurityOpt to include \"no-new-privileges:true\")",
		},
		{
			name: "no-new-privileges satisfied colon form",
			opts: ContainerCreateOptions{RequireNoNewPrivileges: true, AllowAllCapabilities: true},
			body: `{"HostConfig":{"SecurityOpt":["no-new-privileges:true"]}}`,
		},
		{
			name: "no-new-privileges satisfied equals form",
			opts: ContainerCreateOptions{RequireNoNewPrivileges: true, AllowAllCapabilities: true},
			body: `{"HostConfig":{"SecurityOpt":["no-new-privileges=true"]}}`,
		},
		{
			name: "no-new-privileges satisfied bare token",
			opts: ContainerCreateOptions{RequireNoNewPrivileges: true, AllowAllCapabilities: true},
			body: `{"HostConfig":{"SecurityOpt":["no-new-privileges"]}}`,
		},
		{
			name:       "non-root user missing",
			opts:       ContainerCreateOptions{RequireNonRootUser: true, AllowAllCapabilities: true},
			body:       `{}`,
			wantReason: "container create denied: non-root user is required (set Config.User to a non-zero UID or non-root username)",
		},
		{
			name:       "non-root user explicitly root",
			opts:       ContainerCreateOptions{RequireNonRootUser: true, AllowAllCapabilities: true},
			body:       `{"User":"root"}`,
			wantReason: "container create denied: non-root user is required (set Config.User to a non-zero UID or non-root username)",
		},
		{
			name:       "non-root user uid zero",
			opts:       ContainerCreateOptions{RequireNonRootUser: true, AllowAllCapabilities: true},
			body:       `{"User":"0:0"}`,
			wantReason: "container create denied: non-root user is required (set Config.User to a non-zero UID or non-root username)",
		},
		{
			name: "non-root user uid",
			opts: ContainerCreateOptions{RequireNonRootUser: true, AllowAllCapabilities: true},
			body: `{"User":"1000:1000"}`,
		},
		{
			name: "non-root user name",
			opts: ContainerCreateOptions{RequireNonRootUser: true, AllowAllCapabilities: true},
			body: `{"User":"app"}`,
		},
		{
			name:       "readonly rootfs required",
			opts:       ContainerCreateOptions{RequireReadonlyRootfs: true, AllowAllCapabilities: true},
			body:       `{"HostConfig":{"ReadonlyRootfs":false}}`,
			wantReason: "container create denied: read-only root filesystem is required (set HostConfig.ReadonlyRootfs to true)",
		},
		{
			name: "readonly rootfs satisfied",
			opts: ContainerCreateOptions{RequireReadonlyRootfs: true, AllowAllCapabilities: true},
			body: `{"HostConfig":{"ReadonlyRootfs":true}}`,
		},
		{
			name:       "user namespace host denied by default",
			opts:       ContainerCreateOptions{AllowAllCapabilities: true},
			body:       `{"HostConfig":{"UsernsMode":"host"}}`,
			wantReason: "container create denied: host user namespace mode is not allowed",
		},
		{
			name: "user namespace host allowed when opted in",
			opts: ContainerCreateOptions{AllowAllCapabilities: true, AllowHostUserNS: true},
			body: `{"HostConfig":{"UsernsMode":"host"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))
			reason, err := newContainerCreatePolicy(tt.opts).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestContainerCreatePolicyEnforcesCapabilityAllowlist(t *testing.T) {
	tests := []struct {
		name       string
		opts       ContainerCreateOptions
		body       string
		wantReason string
	}{
		{
			name:       "CapAdd denied by default",
			opts:       ContainerCreateOptions{},
			body:       `{"HostConfig":{"CapAdd":["NET_ADMIN"]}}`,
			wantReason: `container create denied: capability "NET_ADMIN" is not in the allowed list`,
		},
		{
			name: "CapAdd allowlist matches with CAP_ prefix",
			opts: ContainerCreateOptions{AllowedCapabilities: []string{"NET_ADMIN"}},
			body: `{"HostConfig":{"CapAdd":["CAP_NET_ADMIN","cap_net_admin"]}}`,
		},
		{
			name: "CapAdd permitted when AllowAllCapabilities",
			opts: ContainerCreateOptions{AllowAllCapabilities: true},
			body: `{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`,
		},
		{
			name:       "CapAdd allowlist rejects unlisted",
			opts:       ContainerCreateOptions{AllowedCapabilities: []string{"NET_ADMIN"}},
			body:       `{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`,
			wantReason: `container create denied: capability "SYS_ADMIN" is not in the allowed list`,
		},
		{
			name:       "CapDrop ALL required",
			opts:       ContainerCreateOptions{RequireDropAllCapabilities: true, AllowAllCapabilities: true},
			body:       `{"HostConfig":{}}`,
			wantReason: `container create denied: HostConfig.CapDrop must include "ALL"`,
		},
		{
			name: "CapDrop ALL satisfied case-insensitive",
			opts: ContainerCreateOptions{RequireDropAllCapabilities: true, AllowAllCapabilities: true},
			body: `{"HostConfig":{"CapDrop":["all"]}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))
			reason, err := newContainerCreatePolicy(tt.opts).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestContainerCreatePolicyEnforcesResourceLimits(t *testing.T) {
	tests := []struct {
		name       string
		opts       ContainerCreateOptions
		body       string
		wantReason string
	}{
		{
			name:       "memory limit required missing",
			opts:       ContainerCreateOptions{RequireMemoryLimit: true, AllowAllCapabilities: true},
			body:       `{"HostConfig":{}}`,
			wantReason: "container create denied: a memory limit is required (set HostConfig.Memory)",
		},
		{
			name: "memory limit satisfied",
			opts: ContainerCreateOptions{RequireMemoryLimit: true, AllowAllCapabilities: true},
			body: `{"HostConfig":{"Memory":536870912}}`,
		},
		{
			name:       "cpu limit required missing",
			opts:       ContainerCreateOptions{RequireCPULimit: true, AllowAllCapabilities: true},
			body:       `{"HostConfig":{}}`,
			wantReason: "container create denied: a CPU limit is required (set HostConfig.NanoCpus, CpuQuota, CpuPeriod, or CpuShares)",
		},
		{
			name: "cpu limit satisfied with NanoCpus",
			opts: ContainerCreateOptions{RequireCPULimit: true, AllowAllCapabilities: true},
			body: `{"HostConfig":{"NanoCpus":500000000}}`,
		},
		{
			name: "cpu limit satisfied with CpuShares",
			opts: ContainerCreateOptions{RequireCPULimit: true, AllowAllCapabilities: true},
			body: `{"HostConfig":{"CpuShares":512}}`,
		},
		{
			name:       "pids limit required missing",
			opts:       ContainerCreateOptions{RequirePidsLimit: true, AllowAllCapabilities: true},
			body:       `{"HostConfig":{}}`,
			wantReason: "container create denied: a PIDs limit is required (set HostConfig.PidsLimit to a positive value)",
		},
		{
			name:       "pids limit zero denied",
			opts:       ContainerCreateOptions{RequirePidsLimit: true, AllowAllCapabilities: true},
			body:       `{"HostConfig":{"PidsLimit":0}}`,
			wantReason: "container create denied: a PIDs limit is required (set HostConfig.PidsLimit to a positive value)",
		},
		{
			name: "pids limit satisfied",
			opts: ContainerCreateOptions{RequirePidsLimit: true, AllowAllCapabilities: true},
			body: `{"HostConfig":{"PidsLimit":100}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))
			reason, err := newContainerCreatePolicy(tt.opts).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestContainerCreatePolicyEnforcesSecurityProfiles(t *testing.T) {
	tests := []struct {
		name       string
		opts       ContainerCreateOptions
		body       string
		wantReason string
	}{
		{
			name:       "seccomp unconfined denied when configured",
			opts:       ContainerCreateOptions{DenyUnconfinedSeccomp: true, AllowAllCapabilities: true},
			body:       `{"HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`,
			wantReason: "container create denied: unconfined seccomp profile is not allowed",
		},
		{
			name: "seccomp unconfined allowed by default",
			opts: ContainerCreateOptions{AllowAllCapabilities: true},
			body: `{"HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`,
		},
		{
			name:       "seccomp profile not in allowlist",
			opts:       ContainerCreateOptions{AllowedSeccompProfiles: []string{"runtime/default", "custom.json"}, AllowAllCapabilities: true},
			body:       `{"HostConfig":{"SecurityOpt":["seccomp=other.json"]}}`,
			wantReason: `container create denied: seccomp profile "other.json" is not in the allowed list`,
		},
		{
			name: "seccomp profile in allowlist",
			opts: ContainerCreateOptions{AllowedSeccompProfiles: []string{"runtime/default"}, AllowAllCapabilities: true},
			body: `{"HostConfig":{"SecurityOpt":["seccomp=runtime/default"]}}`,
		},
		{
			name:       "seccomp profile missing entirely when allowlist set",
			opts:       ContainerCreateOptions{AllowedSeccompProfiles: []string{"runtime/default"}, AllowAllCapabilities: true},
			body:       `{"HostConfig":{}}`,
			wantReason: "container create denied: a seccomp profile is required (set HostConfig.SecurityOpt to include seccomp=<profile>)",
		},
		{
			name: "seccomp missing profile allowed when 'default' allowlisted",
			opts: ContainerCreateOptions{AllowedSeccompProfiles: []string{"default"}, AllowAllCapabilities: true},
			body: `{"HostConfig":{}}`,
		},
		{
			name:       "apparmor unconfined denied when configured",
			opts:       ContainerCreateOptions{DenyUnconfinedAppArmor: true, AllowAllCapabilities: true},
			body:       `{"HostConfig":{"SecurityOpt":["apparmor=unconfined"]}}`,
			wantReason: "container create denied: unconfined apparmor profile is not allowed",
		},
		{
			name:       "apparmor profile missing when allowlist set",
			opts:       ContainerCreateOptions{AllowedAppArmorProfiles: []string{"my-profile"}, AllowAllCapabilities: true},
			body:       `{"HostConfig":{}}`,
			wantReason: "container create denied: an apparmor profile is required (set HostConfig.SecurityOpt to include apparmor=<profile>)",
		},
		{
			name: "apparmor missing allowed when docker-default allowlisted",
			opts: ContainerCreateOptions{AllowedAppArmorProfiles: []string{"docker-default"}, AllowAllCapabilities: true},
			body: `{"HostConfig":{}}`,
		},
		{
			name: "apparmor profile in allowlist",
			opts: ContainerCreateOptions{AllowedAppArmorProfiles: []string{"my-profile"}, AllowAllCapabilities: true},
			body: `{"HostConfig":{"SecurityOpt":["apparmor=my-profile"]}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))
			reason, err := newContainerCreatePolicy(tt.opts).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestContainerCreatePolicyEnforcesRequiredLabels(t *testing.T) {
	tests := []struct {
		name       string
		opts       ContainerCreateOptions
		body       string
		wantReason string
	}{
		{
			name:       "label missing",
			opts:       ContainerCreateOptions{RequiredLabels: []string{"com.example.owner"}, AllowAllCapabilities: true},
			body:       `{"Labels":{"com.other.tag":"v1"}}`,
			wantReason: `container create denied: required label "com.example.owner" is missing or empty`,
		},
		{
			name:       "label empty value",
			opts:       ContainerCreateOptions{RequiredLabels: []string{"com.example.owner"}, AllowAllCapabilities: true},
			body:       `{"Labels":{"com.example.owner":""}}`,
			wantReason: `container create denied: required label "com.example.owner" is missing or empty`,
		},
		{
			name: "label satisfied",
			opts: ContainerCreateOptions{RequiredLabels: []string{"com.example.owner"}, AllowAllCapabilities: true},
			body: `{"Labels":{"com.example.owner":"team-platform"}}`,
		},
		{
			name:       "first missing label wins",
			opts:       ContainerCreateOptions{RequiredLabels: []string{"a", "b"}, AllowAllCapabilities: true},
			body:       `{"Labels":{"b":"v"}}`,
			wantReason: `container create denied: required label "a" is missing or empty`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))
			reason, err := newContainerCreatePolicy(tt.opts).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestContainerCreatePolicyHardeningSkipsNonCreateRequests(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		RequireNoNewPrivileges:     true,
		RequireNonRootUser:         true,
		RequireReadonlyRootfs:      true,
		RequireDropAllCapabilities: true,
		RequireMemoryLimit:         true,
		RequireCPULimit:            true,
		RequirePidsLimit:           true,
		DenyUnconfinedSeccomp:      true,
		DenyUnconfinedAppArmor:     true,
		AllowAllCapabilities:       true,
		RequiredLabels:             []string{"owner"},
	})
	// A request to a different path must not be inspected even though every
	// hardening rail is enabled. The policy only governs /containers/create.
	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(`{}`))
	reason, err := policy.inspect(nil, req, "/containers/json")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestNormalizeCapabilityStripsPrefix(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "NET_ADMIN", want: "NET_ADMIN"},
		{in: "cap_net_admin", want: "NET_ADMIN"},
		{in: "  cap_sys_admin  ", want: "SYS_ADMIN"},
		{in: "", want: ""},
	}
	for _, tt := range tests {
		got := normalizeCapability(tt.in)
		if got != tt.want {
			t.Fatalf("normalizeCapability(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestContainerCreatePolicyBoundaryMutationCoverage closes the surviving-
// mutant cluster VISION.md flags around container_create.go's boundary and
// negation checks. Each case is built to differ between original code and a
// specific named mutation, so the suite acts as a regression gate against
// any future drift in the inspector.
func TestContainerCreatePolicyBoundaryMutationCoverage(t *testing.T) {
	tests := []struct {
		name       string
		opts       ContainerCreateOptions
		body       string
		wantReason string
	}{
		// denyRequiredLabelsReason: `!ok || strings.TrimSpace(value) == ""` —
		// a mutation that drops TrimSpace would let a whitespace-only label
		// satisfy the requirement. The existing "label empty value" test
		// passes both original and mutated because TrimSpace("") == "" too.
		// Whitespace-only differentiates them.
		{
			name:       "required label whitespace-only value treated as empty",
			opts:       ContainerCreateOptions{RequiredLabels: []string{"com.example.owner"}, AllowAllCapabilities: true},
			body:       `{"Labels":{"com.example.owner":"   "}}`,
			wantReason: `container create denied: required label "com.example.owner" is missing or empty`,
		},
		// denyResourceLimitReason: `hostConfig.Memory <= 0` — explicitly set
		// to 0 (not via the "missing" default) ensures the boundary check
		// triggers on the documented zero value, not just on absent fields.
		{
			name:       "memory limit zero rejected explicitly",
			opts:       ContainerCreateOptions{RequireMemoryLimit: true, AllowAllCapabilities: true},
			body:       `{"HostConfig":{"Memory":0}}`,
			wantReason: "container create denied: a memory limit is required (set HostConfig.Memory)",
		},
		// `hostConfig.Memory <= 0` — mutation `<= 0` → `< 0` would accept
		// Memory=0; mutation `< 0` → `<= 0` would reject Memory<0 which is
		// fine. The strict-on-boundary case is Memory=1 (must pass).
		{
			name: "memory limit one accepted (boundary above <=0)",
			opts: ContainerCreateOptions{RequireMemoryLimit: true, AllowAllCapabilities: true},
			body: `{"HostConfig":{"Memory":1}}`,
		},
		// denyHardeningReason: `requireNoNewPrivileges && !hasNoNewPrivileges`
		// — explicitly check the satisfied path. SecurityOpt with
		// "no-new-privileges:true" should clear the deny, even when other
		// hardening rails are also enabled.
		{
			name: "no-new-privileges satisfied with all rails enabled",
			opts: ContainerCreateOptions{
				RequireNoNewPrivileges:     true,
				RequireDropAllCapabilities: true,
				AllowAllCapabilities:       true,
			},
			body: `{"HostConfig":{"SecurityOpt":["no-new-privileges:true"],"CapDrop":["ALL"]}}`,
		},
		// `!isNonRootUser(req.User)` — explicit non-root User "1000" must
		// pass; the satisfied case differentiates the negation flip.
		{
			name: "non-root user numeric uid accepted",
			opts: ContainerCreateOptions{RequireNonRootUser: true, AllowAllCapabilities: true},
			body: `{"User":"1000","HostConfig":{}}`,
		},
		// "0" (numeric root) must reject so the original/mutation isolation
		// is bidirectional.
		{
			name:       "non-root user numeric zero rejected",
			opts:       ContainerCreateOptions{RequireNonRootUser: true, AllowAllCapabilities: true},
			body:       `{"User":"0","HostConfig":{}}`,
			wantReason: "container create denied: non-root user is required (set Config.User to a non-zero UID or non-root username)",
		},
		// denySecurityOptReason: the three apparmor "default-class" names —
		// "default", "docker-default", "runtime/default" — should each
		// independently clear the missing-profile check. The existing tests
		// only cover "docker-default"; mutations that drop either of the
		// other two slices.Contains() short-circuits would survive without
		// the additional cases below.
		{
			name: "apparmor missing allowed when default allowlisted",
			opts: ContainerCreateOptions{AllowedAppArmorProfiles: []string{"default"}, AllowAllCapabilities: true},
			body: `{"HostConfig":{}}`,
		},
		{
			name: "apparmor missing allowed when runtime/default allowlisted",
			opts: ContainerCreateOptions{AllowedAppArmorProfiles: []string{"runtime/default"}, AllowAllCapabilities: true},
			body: `{"HostConfig":{}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))
			reason, err := newContainerCreatePolicy(tt.opts).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestBindPathAllowedBoundaryMutationCoverage extends TestBindPathAllowed
// with the cases that differentiate the strict-prefix semantics from a
// careless contains-check. A mutation that drops the trailing slash in
// `strings.HasPrefix(source, allowed+"/")` would let "/srv/database" pass
// when "/srv/data" is allowlisted — already covered by the existing
// "sibling prefix rejected" case. The cases below close the parallel gaps:
//   - empty source string with allowlist (must reject; bindPathAllowed
//     should not match anything when source is "")
//   - multiple allowlist entries (any-match semantics)
//   - root-only source against subdir allowlist (must reject)
func TestBindPathAllowedBoundaryMutationCoverage(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		allowed []string
		want    bool
	}{
		{name: "empty source with explicit allowlist rejected", source: "", allowed: []string{"/srv"}, want: false},
		{name: "empty source with root allowlist accepted", source: "", allowed: []string{"/"}, want: true},
		{name: "multi-entry allowlist matches second", source: "/var/lib/app", allowed: []string{"/srv", "/var/lib/app"}, want: true},
		{name: "multi-entry allowlist no match", source: "/var/log", allowed: []string{"/srv", "/var/lib/app"}, want: false},
		{name: "root source against subdir allowlist rejected", source: "/", allowed: []string{"/srv/data"}, want: false},
		// The trailing-slash variation: "/srv/data/" vs allowlist ["/srv/data"]
		// — exact match doesn't apply because the source has a trailing slash,
		// HasPrefix("srv/data/", "srv/data/") fires only if the allowlist
		// entry doesn't carry the trailing slash. Boundary case for the
		// allowed+"/" construction.
		{name: "source with trailing slash exactly matches allowlist", source: "/srv/data/", allowed: []string{"/srv/data"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bindPathAllowed(tt.source, tt.allowed); got != tt.want {
				t.Fatalf("bindPathAllowed(%q, %v) = %v, want %v", tt.source, tt.allowed, got, tt.want)
			}
		})
	}
}

func TestNewContainerCreatePolicyDeduplicatesCapabilityList(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowedCapabilities: []string{"NET_ADMIN", "cap_net_admin", "CAP_SYS_PTRACE", " "},
	})
	want := []string{"NET_ADMIN", "SYS_PTRACE"}
	if len(policy.allowedCapabilities) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(policy.allowedCapabilities), len(want), policy.allowedCapabilities)
	}
	for i, w := range want {
		if policy.allowedCapabilities[i] != w {
			t.Fatalf("[%d] = %q, want %q", i, policy.allowedCapabilities[i], w)
		}
	}
}
