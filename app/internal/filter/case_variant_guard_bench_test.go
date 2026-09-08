package filter

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/logging"
)

// benchCaseVariantContainerCreateBody is a realistic Docker container-create
// body: the shape rewriteJSONImageField re-marshals when image trust pins a
// verified digest, and the shape the duplicate-case-variant guard walks first.
var benchCaseVariantContainerCreateBody = []byte(`{
	"Image":"registry.example.com/team/api:1.4.2",
	"Cmd":["/usr/local/bin/api","--config","/etc/api/config.yaml","--verbose"],
	"Entrypoint":["/sbin/tini","--"],
	"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","API_ADDR=0.0.0.0:8080","API_LOG_LEVEL=info","API_DB_HOST=db.internal","API_DB_PORT=5432"],
	"User":"1000:1000",
	"WorkingDir":"/srv/app",
	"Labels":{"com.example.app":"api","com.example.team":"platform","com.example.env":"prod","com.example.commit":"9f2c1ab"},
	"ExposedPorts":{"8080/tcp":{},"9090/tcp":{}},
	"Volumes":{"/var/cache/api":{}},
	"HostConfig":{
		"NetworkMode":"bridge",
		"Binds":["/srv/data:/data:ro","/srv/conf:/etc/api:ro"],
		"Memory":268435456,
		"MemorySwap":268435456,
		"NanoCpus":1500000000,
		"CpuShares":512,
		"PidsLimit":256,
		"CapAdd":["NET_BIND_SERVICE"],
		"CapDrop":["ALL"],
		"SecurityOpt":["seccomp=runtime/default","apparmor=docker-default","no-new-privileges:true"],
		"ReadonlyRootfs":true,
		"RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0},
		"LogConfig":{"Type":"json-file","Config":{"max-size":"10m","max-file":"3"}},
		"Sysctls":{"net.ipv4.ip_unprivileged_port_start":"0"},
		"Tmpfs":{"/tmp":"rw,noexec,nosuid,size=64m"},
		"PortBindings":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"18080"}]},
		"Ulimits":[{"Name":"nofile","Soft":1024,"Hard":4096}]
	},
	"NetworkingConfig":{"EndpointsConfig":{"app-net":{"NetworkID":"c0ffee","Aliases":["api","api-v1"],"DriverOpts":{"com.docker.network.endpoint.sysctls":"net.ipv4.conf.IFNAME.log_martians=1"}}}}
}`)

// benchCaseVariantLibpodCreateBody mirrors the Docker body above in libpod's
// lowercase-field spec shape, which rewriteLibpodJSONImageField rewrites.
var benchCaseVariantLibpodCreateBody = []byte(`{
	"image":"registry.example.com/team/api:1.4.2",
	"name":"api",
	"command":["/usr/local/bin/api","--config","/etc/api/config.yaml","--verbose"],
	"entrypoint":["/sbin/tini","--"],
	"env":{"PATH":"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","API_ADDR":"0.0.0.0:8080","API_LOG_LEVEL":"info","API_DB_HOST":"db.internal"},
	"labels":{"com.example.app":"api","com.example.team":"platform","com.example.env":"prod"},
	"user":"1000:1000",
	"work_dir":"/srv/app",
	"privileged":false,
	"read_only_filesystem":true,
	"cap_add":["NET_BIND_SERVICE"],
	"cap_drop":["ALL"],
	"mounts":[{"destination":"/data","source":"/srv/data","type":"bind","options":["ro","rbind"]},{"destination":"/etc/api","source":"/srv/conf","type":"bind","options":["ro","rbind"]}],
	"portmappings":[{"container_port":8080,"host_port":18080,"host_ip":"127.0.0.1","protocol":"tcp"}],
	"resource_limits":{"memory":{"limit":268435456,"swap":268435456},"cpu":{"shares":512,"quota":150000,"period":100000},"pids":{"limit":256}},
	"sysctl":{"net.ipv4.ip_unprivileged_port_start":"0"},
	"annotations":{"io.podman.annotations.autoremove":"FALSE"}
}`)

// benchCaseVariantServiceCreateBody is a realistic swarm service spec, the
// shape rewriteServiceImage navigates three levels into.
var benchCaseVariantServiceCreateBody = []byte(`{
	"Name":"api",
	"Labels":{"com.example.app":"api","com.example.team":"platform"},
	"TaskTemplate":{
		"ContainerSpec":{
			"Image":"registry.example.com/team/api:1.4.2",
			"Command":["/usr/local/bin/api"],
			"Args":["--config","/etc/api/config.yaml","--verbose"],
			"Env":["API_ADDR=0.0.0.0:8080","API_LOG_LEVEL=info","API_DB_HOST=db.internal"],
			"User":"1000:1000",
			"Dir":"/srv/app",
			"Labels":{"com.example.app":"api"},
			"Mounts":[{"Type":"bind","Source":"/srv/data","Target":"/data","ReadOnly":true},{"Type":"volume","Source":"api-cache","Target":"/var/cache/api"}],
			"Privileges":{"CredentialSpec":null,"SELinuxContext":null},
			"StopGracePeriod":10000000000,
			"ReadOnly":true
		},
		"Resources":{"Limits":{"MemoryBytes":268435456,"NanoCPUs":1500000000,"Pids":256},"Reservations":{"MemoryBytes":134217728,"NanoCPUs":500000000}},
		"RestartPolicy":{"Condition":"any","Delay":5000000000,"MaxAttempts":3},
		"Placement":{"Constraints":["node.role==worker"],"MaxReplicas":4},
		"Networks":[{"Target":"app-net","Aliases":["api","api-v1"]}],
		"LogDriver":{"Name":"json-file","Options":{"max-size":"10m","max-file":"3"}}
	},
	"Mode":{"Replicated":{"Replicas":3}},
	"UpdateConfig":{"Parallelism":1,"Delay":10000000000,"FailureAction":"rollback","Order":"start-first"},
	"EndpointSpec":{"Mode":"vip","Ports":[{"Protocol":"tcp","TargetPort":8080,"PublishedPort":18080,"PublishMode":"ingress"}]}
}`)

// benchCaseVariantContainerUpdateBody is the resource-limit guard's input on
// POST /containers/{id}/update: the guard runs the duplicate-case-variant walk
// and then decodes the same bytes into a typed patch struct.
const benchCaseVariantContainerUpdateBody = `{
	"Memory":268435456,
	"MemorySwap":268435456,
	"MemoryReservation":134217728,
	"NanoCpus":1500000000,
	"CpuShares":512,
	"CpuQuota":150000,
	"CpuPeriod":100000,
	"CpusetCpus":"0-3",
	"CpusetMems":"0",
	"PidsLimit":256,
	"BlkioWeight":500,
	"RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0}
}`

// BenchmarkRejectDuplicateCaseVariantJSONKeys measures the shared guard the
// four raw-bytes call sites run before their own decode.
func BenchmarkRejectDuplicateCaseVariantJSONKeys(b *testing.B) {
	cases := []struct {
		name string
		body []byte
	}{
		{"container_create", benchCaseVariantContainerCreateBody},
		{"libpod_create", benchCaseVariantLibpodCreateBody},
		{"service_create", benchCaseVariantServiceCreateBody},
		{"container_update", []byte(benchCaseVariantContainerUpdateBody)},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := RejectDuplicateCaseVariantJSONKeys(tc.body); err != nil {
					b.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v", err)
				}
			}
		})
	}
}

// BenchmarkRewriteJSONImageField measures the container-create image-pin
// rewrite, guard walk included.
func BenchmarkRewriteJSONImageField(b *testing.B) {
	const pinned = "registry.example.com/team/api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	b.ReportAllocs()
	for b.Loop() {
		if _, err := rewriteJSONImageField(benchCaseVariantContainerCreateBody, pinned); err != nil {
			b.Fatalf("rewriteJSONImageField() error = %v", err)
		}
	}
}

// BenchmarkRewriteLibpodJSONImageField measures the libpod container-create
// image-pin rewrite, guard walk included.
func BenchmarkRewriteLibpodJSONImageField(b *testing.B) {
	const pinned = "registry.example.com/team/api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	b.ReportAllocs()
	for b.Loop() {
		if _, err := rewriteLibpodJSONImageField(benchCaseVariantLibpodCreateBody, pinned); err != nil {
			b.Fatalf("rewriteLibpodJSONImageField() error = %v", err)
		}
	}
}

// BenchmarkRewriteServiceImage measures the swarm service image-pin rewrite,
// guard walk included.
func BenchmarkRewriteServiceImage(b *testing.B) {
	const pinned = "registry.example.com/team/api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	b.ReportAllocs()
	for b.Loop() {
		if _, err := rewriteServiceImage(benchCaseVariantServiceCreateBody, pinned); err != nil {
			b.Fatalf("rewriteServiceImage() error = %v", err)
		}
	}
}

// BenchmarkResourceLimitGuardContainerUpdate measures the whole guard hop for
// POST /containers/{id}/update, where the duplicate-case-variant walk runs
// ahead of a typed decode of the same bytes.
func BenchmarkResourceLimitGuardContainerUpdate(b *testing.B) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	handler := ResourceLimitGuardWithOptions(nil, ResourceLimitGuardOptions{
		PolicyConfig: PolicyConfig{ContainerUpdate: ContainerUpdateOptions{
			AllowResourceUpdates: true,
			RequireMemoryLimit:   true,
			RequireCPULimit:      true,
			RequirePidsLimit:     true,
		}},
		InspectContainer: func(context.Context, string) (ContainerUpdateInspectResult, bool, error) {
			return ContainerUpdateInspectResult{Memory: 1 << 28, NanoCpus: 1500000000, PidsLimit: int64Ptr(256)}, true, nil
		},
	})(next)

	b.ReportAllocs()
	for b.Loop() {
		req := httptest.NewRequest(http.MethodPost, "/containers/bench/update", strings.NewReader(benchCaseVariantContainerUpdateBody))
		req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{}))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("guard status = %d, want %d, body %s", rec.Code, http.StatusOK, rec.Body.String())
		}
	}
}
