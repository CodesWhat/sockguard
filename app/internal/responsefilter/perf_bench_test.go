package responsefilter

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// containerInspectBenchBody is a GET /containers/{id}/json body shaped like
// what dockerd answers: every block modifyContainerInspect reads (Config.Env,
// the host-path fields, GraphDriver.Data, Mounts, HostConfig.Binds,
// NetworkSettings) plus the surrounding fields it walks past.
const containerInspectBenchBody = `{
  "Id": "3f2c1b0a9e8d7c6b5a4938271605f4e3d2c1b0a99887766554433221100ffeedd",
  "Created": "2026-01-14T09:12:44.123456789Z",
  "Path": "/usr/local/bin/api-server",
  "Args": ["--config", "/etc/api/config.yaml", "--log-level", "info"],
  "State": {"Status": "running", "Running": true, "Paused": false, "Restarting": false, "OOMKilled": false, "Dead": false, "Pid": 48231, "ExitCode": 0, "Error": "", "StartedAt": "2026-01-14T09:12:45.556677889Z", "FinishedAt": "0001-01-01T00:00:00Z"},
  "Image": "sha256:aa11bb22cc33dd44ee55ff6677889900aabbccddeeff00112233445566778899",
  "ResolvConfPath": "/var/lib/docker/containers/3f2c1b0a9e8d/resolv.conf",
  "HostnamePath": "/var/lib/docker/containers/3f2c1b0a9e8d/hostname",
  "HostsPath": "/var/lib/docker/containers/3f2c1b0a9e8d/hosts",
  "LogPath": "/var/lib/docker/containers/3f2c1b0a9e8d/3f2c1b0a9e8d-json.log",
  "Name": "/api-server",
  "RestartCount": 0,
  "Driver": "overlay2",
  "Platform": "linux",
  "MountLabel": "",
  "ProcessLabel": "",
  "AppArmorProfile": "docker-default",
  "ExecIDs": null,
  "HostConfig": {
    "Binds": ["/srv/secrets:/run/secrets:ro", "/srv/data:/var/lib/api:rw", "apilogs:/var/log/api"],
    "ContainerIDFile": "",
    "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "3"}},
    "NetworkMode": "api_backend",
    "PortBindings": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18080"}]},
    "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
    "AutoRemove": false,
    "VolumeDriver": "",
    "VolumesFrom": null,
    "CapAdd": null,
    "CapDrop": ["ALL"],
    "CgroupnsMode": "private",
    "Dns": [], "DnsOptions": [], "DnsSearch": [],
    "ExtraHosts": ["host.docker.internal:host-gateway"],
    "IpcMode": "private", "Cgroup": "", "Links": null,
    "OomScoreAdj": 0, "PidMode": "", "Privileged": false,
    "PublishAllPorts": false, "ReadonlyRootfs": true,
    "SecurityOpt": ["no-new-privileges:true"], "UTSMode": "", "UsernsMode": "",
    "ShmSize": 67108864, "Runtime": "runc",
    "CpuShares": 0, "Memory": 536870912, "NanoCpus": 1500000000,
    "CpusetCpus": "", "CpusetMems": "", "PidsLimit": 512
  },
  "GraphDriver": {"Data": {"LowerDir": "/var/lib/docker/overlay2/l/AAAA:/var/lib/docker/overlay2/l/BBBB", "MergedDir": "/var/lib/docker/overlay2/abcd/merged", "UpperDir": "/var/lib/docker/overlay2/abcd/diff", "WorkDir": "/var/lib/docker/overlay2/abcd/work"}, "Name": "overlay2"},
  "Mounts": [
    {"Type": "bind", "Source": "/srv/secrets", "Destination": "/run/secrets", "Mode": "ro", "RW": false, "Propagation": "rprivate"},
    {"Type": "bind", "Source": "/srv/data", "Destination": "/var/lib/api", "Mode": "rw", "RW": true, "Propagation": "rprivate"},
    {"Type": "volume", "Name": "apilogs", "Source": "/var/lib/docker/volumes/apilogs/_data", "Destination": "/var/log/api", "Driver": "local", "Mode": "z", "RW": true, "Propagation": ""}
  ],
  "Config": {
    "Hostname": "3f2c1b0a9e8d", "Domainname": "", "User": "10001:10001",
    "AttachStdin": false, "AttachStdout": false, "AttachStderr": false,
    "ExposedPorts": {"8080/tcp": {}},
    "Tty": false, "OpenStdin": false, "StdinOnce": false,
    "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "API_DB_PASSWORD=hunter2", "API_SIGNING_KEY=s3cr3t-signing-key", "LANG=C.UTF-8"],
    "Cmd": null,
    "Image": "registry.example.com/team/api-server:2.4.1",
    "Volumes": null, "WorkingDir": "/srv/app",
    "Entrypoint": ["/usr/local/bin/api-server"],
    "Labels": {"com.docker.compose.project": "platform", "com.docker.compose.service": "api", "org.opencontainers.image.revision": "9f8e7d6c"}
  },
  "NetworkSettings": {
    "Bridge": "", "SandboxID": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
    "HairpinMode": false, "LinkLocalIPv6Address": "", "LinkLocalIPv6PrefixLen": 0,
    "Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18080"}]},
    "SandboxKey": "/var/run/docker/netns/1a2b3c4d5e6f",
    "SecondaryIPAddresses": null, "SecondaryIPv6Addresses": null,
    "EndpointID": "", "Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0,
    "IPAddress": "", "IPPrefixLen": 0, "IPv6Gateway": "", "MacAddress": "",
    "Networks": {"api_backend": {"IPAMConfig": null, "Links": null, "Aliases": ["api"], "NetworkID": "c0ffee11c0ffee22c0ffee33c0ffee44c0ffee55c0ffee66c0ffee77c0ffee88", "EndpointID": "de1e7ed0de1e7ed1de1e7ed2de1e7ed3de1e7ed4de1e7ed5de1e7ed6de1e7ed7", "Gateway": "172.24.0.1", "IPAddress": "172.24.0.9", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:09", "DriverOpts": null}}
  }
}`

// newBenchResponse builds the *http.Response ModifyResponse is handed, reading
// body from a fresh reader so each iteration starts from the same bytes.
func newBenchResponse(method, path string, body []byte) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request: &http.Request{
			Method: method,
			URL:    &url.URL{Path: path},
		},
	}
}

// drainBenchResponse consumes the rewritten body so the benchmark measures the
// whole path a client would exercise, not just the rewrite.
func drainBenchResponse(b *testing.B, resp *http.Response) {
	b.Helper()
	if resp.Body == nil {
		return
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		b.Fatalf("drain body: %v", err)
	}
	_ = resp.Body.Close()
}

// BenchmarkModifyResponseInspect measures the whole-body read/decode/rewrite
// path: GET /containers/{id}/json goes through withResponseBody, so this is
// where the response-body read buffer shows up in the allocation count.
func BenchmarkModifyResponseInspect(b *testing.B) {
	f := New(Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
	})
	body := []byte(containerInspectBenchBody)
	path := "/v1.53/containers/3f2c1b0a9e8d/json"

	resp := newBenchResponse(http.MethodGet, path, body)
	if err := f.ModifyResponse(resp); err != nil {
		b.Fatalf("warmup ModifyResponse: %v", err)
	}
	drainBenchResponse(b, resp)

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for b.Loop() {
		resp := newBenchResponse(http.MethodGet, path, body)
		if err := f.ModifyResponse(resp); err != nil {
			b.Fatalf("ModifyResponse: %v", err)
		}
		drainBenchResponse(b, resp)
	}
}

// containerListBenchBody builds a GET /containers/json body with n entries in
// the shape dockerd answers with.
func containerListBenchBody(n int) []byte {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i := range n {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, `{"Id":"%064x","Names":["/svc-%d"],"Image":"registry.example.com/team/svc:2.4.1","ImageID":"sha256:%064x","Command":"/usr/local/bin/svc --config /etc/svc/config.yaml","Created":%d,"Ports":[{"IP":"0.0.0.0","PrivatePort":8080,"PublicPort":%d,"Type":"tcp"}],"Labels":{"com.docker.compose.project":"platform","com.docker.compose.service":"svc-%d","org.opencontainers.image.revision":"9f8e7d6c"},"State":"running","Status":"Up 6 hours (healthy)","HostConfig":{"NetworkMode":"api_backend"},"NetworkSettings":{"Networks":{"api_backend":{"IPAMConfig":null,"Links":null,"Aliases":null,"NetworkID":"c0ffee11c0ffee22c0ffee33c0ffee44c0ffee55c0ffee66c0ffee77c0ffee88","EndpointID":"%064x","Gateway":"172.24.0.1","IPAddress":"172.24.%d.%d","IPPrefixLen":16,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"MacAddress":"02:42:ac:18:00:%02x","DriverOpts":null}}},"Mounts":[{"Type":"volume","Name":"svclogs-%d","Source":"/var/lib/docker/volumes/svclogs-%d/_data","Destination":"/var/log/svc","Driver":"local","Mode":"z","RW":true,"Propagation":""}]}`,
			i*7919, i, i*104729, 1768000000+i, 18080+i, i, i*15485863, i/250, i%250, i%256, i, i)
	}
	buf.WriteByte(']')
	return buf.Bytes()
}

// BenchmarkModifyResponseContainerList measures the streaming array path over a
// 500-entry list, the size a busy host's `docker ps` actually returns.
func BenchmarkModifyResponseContainerList(b *testing.B) {
	f := New(Options{RedactMountPaths: true, RedactNetworkTopology: true})
	body := containerListBenchBody(500)
	path := "/v1.53/containers/json"

	resp := newBenchResponse(http.MethodGet, path, body)
	if err := f.ModifyResponse(resp); err != nil {
		b.Fatalf("warmup ModifyResponse: %v", err)
	}
	drainBenchResponse(b, resp)

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for b.Loop() {
		resp := newBenchResponse(http.MethodGet, path, body)
		if err := f.ModifyResponse(resp); err != nil {
			b.Fatalf("ModifyResponse: %v", err)
		}
		drainBenchResponse(b, resp)
	}
}
