package compliance

import "github.com/codeswhat/sockguard/v3/app/internal/config"

// Control is one row of the machine-readable control table. It mirrors the
// three tables in docs/content/docs/cis-docker-benchmark.mdx; a drift test
// keeps the IDs in step. Evaluate is nil for outside_scope controls.
type Control struct {
	ID       string
	Title    string
	Category Category
	Reason   string // outside_scope only
	Evaluate func(*config.Config) ControlResult
}

func cc(rb *config.RequestBodyConfig) *config.ContainerCreateRequestBodyConfig {
	return &rb.ContainerCreate
}

const (
	execNote = "Applies when a rule permits exec; with no exec rule the gate is never reached."
)

// controls is ordered: enforced, influenced, outside_scope, each in the order
// the docs list them.
var controls = []Control{
	{ID: "5.3", Title: "Linux kernel capabilities restricted", Category: CategoryEnforced, Evaluate: bodyControl(nil,
		boolCheck("container_create.allow_all_capabilities", false, func(rb *config.RequestBodyConfig) bool { return cc(rb).AllowAllCapabilities }),
		emptyCheck("container_create.allowed_capabilities", func(rb *config.RequestBodyConfig) int { return len(cc(rb).AllowedCapabilities) }),
		boolCheck("container_create.require_drop_all_capabilities", true, func(rb *config.RequestBodyConfig) bool { return cc(rb).RequireDropAllCapabilities }),
	)},
	{ID: "5.4", Title: "Privileged containers not used", Category: CategoryEnforced, Evaluate: bodyControl(nil,
		boolCheck("container_create.allow_privileged", false, func(rb *config.RequestBodyConfig) bool { return cc(rb).AllowPrivileged }),
	)},
	{ID: "5.5", Title: "Sensitive host directories not mounted", Category: CategoryEnforced, Evaluate: bodyControl(nil,
		emptyCheck("container_create.allowed_bind_mounts", func(rb *config.RequestBodyConfig) int { return len(cc(rb).AllowedBindMounts) }),
	)},
	{ID: "5.9", Title: "Host network namespace not shared", Category: CategoryEnforced, Evaluate: bodyControl(nil,
		boolCheck("container_create.allow_host_network", false, func(rb *config.RequestBodyConfig) bool { return cc(rb).AllowHostNetwork }),
	)},
	{ID: "5.10", Title: "Memory usage limited", Category: CategoryEnforced, Evaluate: bodyControl(nil,
		boolCheck("container_create.require_memory_limit", true, func(rb *config.RequestBodyConfig) bool { return cc(rb).RequireMemoryLimit }),
	)},
	{ID: "5.11", Title: "CPU priority set", Category: CategoryEnforced, Evaluate: bodyControl(
		[]string{"Either require_cpu_limit or require_cpu_limit_hard satisfies this control."},
		check{
			path:     "container_create.require_cpu_limit",
			expected: "true (require_cpu_limit or require_cpu_limit_hard)",
			eval: func(rb *config.RequestBodyConfig) (bool, string) {
				v := cc(rb).RequireCPULimit
				return v || cc(rb).RequireCPULimitHard, boolStr(v)
			},
		},
		check{
			path:          "container_create.require_cpu_limit_hard",
			expected:      "true (require_cpu_limit or require_cpu_limit_hard)",
			informational: true,
			eval: func(rb *config.RequestBodyConfig) (bool, string) {
				v := cc(rb).RequireCPULimitHard
				return v, boolStr(v)
			},
		},
	)},
	{ID: "5.12", Title: "Container root filesystem mounted read-only", Category: CategoryEnforced, Evaluate: bodyControl(nil,
		boolCheck("container_create.require_readonly_rootfs", true, func(rb *config.RequestBodyConfig) bool { return cc(rb).RequireReadonlyRootfs }),
	)},
	{ID: "5.15", Title: "Host PID namespace not shared", Category: CategoryEnforced, Evaluate: bodyControl(nil,
		boolCheck("container_create.allow_host_pid", false, func(rb *config.RequestBodyConfig) bool { return cc(rb).AllowHostPID }),
	)},
	{ID: "5.16", Title: "Host IPC namespace not shared", Category: CategoryEnforced, Evaluate: bodyControl(nil,
		boolCheck("container_create.allow_host_ipc", false, func(rb *config.RequestBodyConfig) bool { return cc(rb).AllowHostIPC }),
	)},
	{ID: "5.17", Title: "Host devices not directly exposed", Category: CategoryEnforced, Evaluate: bodyControl(nil,
		boolCheck("container_create.allow_all_devices", false, func(rb *config.RequestBodyConfig) bool { return cc(rb).AllowAllDevices }),
		emptyCheck("container_create.allowed_devices", func(rb *config.RequestBodyConfig) int { return len(cc(rb).AllowedDevices) }),
	)},
	{ID: "5.20", Title: "Host UTS namespace not shared", Category: CategoryEnforced, Evaluate: structuralControl(
		"No knob: HostConfig.UTSMode host is rejected structurally.")},
	{ID: "5.21", Title: "Default seccomp profile not disabled", Category: CategoryEnforced, Evaluate: bodyControl(nil,
		boolCheck("container_create.deny_unconfined_seccomp", true, func(rb *config.RequestBodyConfig) bool { return cc(rb).DenyUnconfinedSeccomp }),
	)},
	{ID: "5.22", Title: "Docker exec without --privileged", Category: CategoryEnforced, Evaluate: execBlindWritesNote(bodyControl([]string{execNote},
		boolCheck("exec.allow_privileged", false, func(rb *config.RequestBodyConfig) bool { return rb.Exec.AllowPrivileged }),
	))},
	{ID: "5.23", Title: "Docker exec without --user=root", Category: CategoryEnforced, Evaluate: execBlindWritesNote(bodyControl([]string{execNote},
		boolCheck("exec.allow_root_user", false, func(rb *config.RequestBodyConfig) bool { return rb.Exec.AllowRootUser }),
	))},
	{ID: "5.24", Title: "Cgroup usage confirmed", Category: CategoryEnforced, Evaluate: structuralControl(
		"No knob: a non-empty HostConfig.CgroupParent is rejected structurally.")},
	{ID: "5.25", Title: "Acquiring additional privileges restricted", Category: CategoryEnforced, Evaluate: bodyControl(nil,
		boolCheck("container_create.require_no_new_privileges", true, func(rb *config.RequestBodyConfig) bool { return cc(rb).RequireNoNewPrivileges }),
	)},
	{ID: "5.28", Title: "PIDs cgroup limit used", Category: CategoryEnforced, Evaluate: bodyControl(nil,
		boolCheck("container_create.require_pids_limit", true, func(rb *config.RequestBodyConfig) bool { return cc(rb).RequirePidsLimit }),
	)},
	{ID: "5.30", Title: "Host user namespace not shared", Category: CategoryEnforced, Evaluate: bodyControl(nil,
		boolCheck("container_create.allow_host_userns", false, func(rb *config.RequestBodyConfig) bool { return cc(rb).AllowHostUserNS }),
	)},
	{ID: "5.31", Title: "Docker socket not mounted inside containers", Category: CategoryEnforced, Evaluate: dockerSocketControl},

	{ID: "2.6", Title: "TLS authentication for Docker daemon", Category: CategoryInfluenced, Evaluate: tlsListenersControl},
	{ID: "4.5", Title: "Content trust for Docker", Category: CategoryInfluenced, Evaluate: bodyControl(
		[]string{"Libpod and service image trust are reported as evidence only and do not change the status."},
		trustCheck("container_create.image_trust.mode", false, func(rb *config.RequestBodyConfig) string { return cc(rb).ImageTrust.Mode }),
		trustCheck("libpod_container_create.image_trust.mode", true, func(rb *config.RequestBodyConfig) string { return rb.LibpodContainerCreate.ImageTrust.Mode }),
		trustCheck("service.image_trust.mode", true, func(rb *config.RequestBodyConfig) string { return rb.Service.ImageTrust.Mode }),
	)},
	{ID: "5.22/5.23", Title: "Exec hardening", Category: CategoryInfluenced, Evaluate: execBlindWritesNote(bodyControl([]string{execNote},
		boolCheck("exec.allow_privileged", false, func(rb *config.RequestBodyConfig) bool { return rb.Exec.AllowPrivileged }),
		boolCheck("exec.allow_root_user", false, func(rb *config.RequestBodyConfig) bool { return rb.Exec.AllowRootUser }),
	))},
	{ID: "7.x", Title: "Swarm controls (operations)", Category: CategoryInfluenced, Evaluate: swarmControl},

	{ID: "1.x", Title: "Host configuration", Category: CategoryOutsideScope,
		Reason: "OS hardening, audit daemon and mount points are below the Docker API. Recommended check: docker-bench-security."},
	{ID: "2.x", Title: "Daemon configuration", Category: CategoryOutsideScope,
		Reason: "live-restore, default logging driver, default ulimit and registry trust are dockerd settings. Recommended check: dockerd flags and docker-bench-security."},
	{ID: "3.x", Title: "Daemon configuration files", Category: CategoryOutsideScope,
		Reason: "File permissions on daemon.json and key and cert ownership are host filesystem state. Recommended check: filesystem audit."},
	{ID: "4.x", Title: "Container images", Category: CategoryOutsideScope,
		Reason: "Base image scanning, HEALTHCHECK and image freshness (4.6, 4.7) live in the image and registry. Recommended check: Trivy or Grype on the image and registry-side controls."},
	{ID: "5.x", Title: "Container runtime, uninspectable", Category: CategoryOutsideScope,
		Reason: "5.6 SSH in container, 5.7/5.8 ports, 5.13 traffic binding, 5.14 restart policy, 5.18 ulimit override, 5.19 mount propagation, 5.26 runtime healthcheck, 5.27 updated image and 5.29 default bridge are not inspected. Recommended check: image scanner, dockerd flags and container-runtime audit."},
	{ID: "6.x", Title: "Security operations", Category: CategoryOutsideScope,
		Reason: "Image lifecycle policy is operational process. Recommended check: registry-side governance."},
}
