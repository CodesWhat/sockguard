package responsefilter

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"
)

const maxResponseFuzzBytes = 16 << 10

func FuzzFilterModifyResponse(f *testing.F) {
	f.Add("/v1.53/containers/abc123/json", []byte(`{"Config":{"Env":["A=B"]},"HostConfig":{"Binds":["/srv/secrets:/run/secrets:ro"]},"Mounts":[{"Source":"/srv/secrets"}],"NetworkSettings":{"IPAddress":"172.18.0.5"}}`))
	f.Add("/v1.53/containers/json", []byte(`[{"Mounts":[{"Source":"/srv/secrets"}],"NetworkSettings":{"Networks":{"default":{"IPAddress":"172.18.0.5","NetworkID":"network-123"}}}}]`))
	f.Add("/v1.53/networks/net-123", []byte(`{"IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{"abc":{"IPv4Address":"172.18.0.5/16"}},"Peers":[{"IP":"10.0.0.2"}]}`))
	f.Add("/v1.53/volumes", []byte(`{"Volumes":[{"Mountpoint":"/var/lib/docker/volumes/cache/_data"}]}`))
	f.Add("/v1.53/containers/abc123/json", []byte(`{"Config":`))
	f.Add("/_ping", []byte("not-json"))

	// Swarm-resource seeds: exercise redactServicePayload, redactTaskPayload,
	// redactSecretPayload, redactConfigPayload, redactNodePayload, and redactSwarmPayload.
	f.Add("/v1.53/services", []byte(`[{"ID":"srv-1","Spec":{"TaskTemplate":{"ContainerSpec":{"Env":["SECRET_TOKEN=shh"],"Mounts":[{"Type":"bind","Source":"/srv/data","Target":"/app"}],"Secrets":[{"SecretID":"sec-1","SecretName":"prod-db"}],"Configs":[{"ConfigID":"cfg-1","ConfigName":"app.conf"}]}}},"Endpoint":{"VirtualIPs":[{"NetworkID":"net-1","Addr":"10.0.0.2/24"}]}}]`))
	f.Add("/v1.53/services/srv-abc", []byte(`{"ID":"srv-abc","Spec":{"TaskTemplate":{"ContainerSpec":{"Env":["DB_PASS=secret"],"Mounts":[{"Type":"volume","Source":"myvolume","Target":"/data"}],"Secrets":[{"SecretID":"sec-abc","SecretName":"tls-cert"}],"Configs":[{"ConfigID":"cfg-abc","ConfigName":"nginx.conf"}]}}},"Endpoint":{"VirtualIPs":[{"NetworkID":"net-2","Addr":"10.1.0.5/24"}]}}`))
	f.Add("/v1.53/tasks", []byte(`[{"ID":"task-1","ServiceID":"srv-1","NodeID":"node-1","Spec":{"ContainerSpec":{"Env":["API_KEY=xyz"],"Mounts":[{"Type":"bind","Source":"/srv/tasks","Target":"/work"}]}},"Status":{"ContainerStatus":{"ContainerID":"ctr-1","PID":42}},"NetworksAttachments":[{"Addresses":["10.0.0.10/24"],"Network":{"ID":"net-1"}}]}]`))
	f.Add("/v1.53/tasks/task-abc", []byte(`{"ID":"task-abc","ServiceID":"srv-abc","NodeID":"node-abc","Spec":{"ContainerSpec":{"Env":["TOKEN=s3cr3t"],"Mounts":[{"Type":"bind","Source":"/run/secrets","Target":"/secrets"}]}},"Status":{"ContainerStatus":{"ContainerID":"ctr-abc","PID":99}},"NetworksAttachments":[{"Addresses":["10.0.1.5/24"],"Network":{"ID":"net-2"}}]}`))
	f.Add("/v1.53/secrets", []byte(`[{"ID":"sec-1","Spec":{"Name":"prod-db","Data":"c3VwZXJzZWNyZXQ=","Labels":{"env":"prod"}}}]`))
	f.Add("/v1.53/secrets/sec-abc", []byte(`{"ID":"sec-abc","Spec":{"Name":"tls-key","Data":"cHJpdmF0ZWtleQ==","Labels":{"env":"staging"}}}`))
	f.Add("/v1.53/configs", []byte(`[{"ID":"cfg-1","Spec":{"Name":"app.conf","Data":"Y29uZmlnLWRhdGE=","Labels":{"tier":"backend"}}}]`))
	f.Add("/v1.53/configs/cfg-abc", []byte(`{"ID":"cfg-abc","Spec":{"Name":"nginx.conf","Data":"c2VydmVyIHt9","Labels":{"tier":"frontend"}}}`))
	f.Add("/v1.53/nodes", []byte(`[{"ID":"node-1","Status":{"Addr":"10.0.0.5"},"ManagerStatus":{"Addr":"10.0.0.5:2377"},"Description":{"TLSInfo":{"TrustRoot":"pem-data","CertIssuerSubject":"subj","CertIssuerPublicKey":"pub"}},"Spec":{"Labels":{"role":"worker"}}}]`))
	f.Add("/v1.53/nodes/node-abc", []byte(`{"ID":"node-abc","Status":{"Addr":"10.0.1.2"},"ManagerStatus":{"Addr":"10.0.1.2:2377","Leader":true},"Description":{"TLSInfo":{"TrustRoot":"pem-root","CertIssuerSubject":"cn=manager","CertIssuerPublicKey":"pubkey"}},"Spec":{"Labels":{"zone":"us-east-1"}}}`))
	f.Add("/v1.53/swarm", []byte(`{"ID":"swarm-1","JoinTokens":{"Worker":"SWMTKN-1-worker","Manager":"SWMTKN-1-manager"},"TLSInfo":{"TrustRoot":"pem-root","CertIssuerSubject":"cn=swarm","CertIssuerPublicKey":"pubkey"},"DefaultAddrPool":["10.10.0.0/16"],"Spec":{"CAConfig":{"SigningCACert":"pem-cert","SigningCAKey":"pem-key","ExternalCAs":[{"URL":"https://ca.example.com","CACert":"pem"}]}}}`))

	filter := New(Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
		RedactSensitiveData:   true,
	})

	f.Fuzz(func(t *testing.T, path string, body []byte) {
		body = truncateResponseFuzzBytes(body, maxResponseFuzzBytes)

		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Header:        make(http.Header),
			Body:          io.NopCloser(bytes.NewReader(body)),
			ContentLength: int64(len(body)),
			Request: &http.Request{
				Method: http.MethodGet,
				URL:    &url.URL{Path: path},
			},
		}

		_ = filter.ModifyResponse(resp)

		if resp.Body != nil {
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
	})
}

func truncateResponseFuzzBytes(body []byte, max int) []byte {
	if len(body) > max {
		return body[:max]
	}
	return body
}
