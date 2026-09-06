package ownership

import (
	"bytes"
	"net/http"
	"testing"
)

// benchmarkContainerCreateBody is a realistic ~3.9 KB POST /containers/create
// payload: the shape a production deployment actually posts, with the fields
// ownership reads (Image, Labels, HostConfig, NetworkingConfig) surrounded by
// the Env/Cmd/Healthcheck/port bulk it never looks at. Body size is what drives
// the cost of this pass, so the benchmark is only worth anything against a body
// of the size real clients send.
const benchmarkContainerCreateBody = `{"Hostname":"app-7f4c9",` +
	`"Domainname":"",` +
	`"User":"1000:1000",` +
	`"AttachStdin":false,` +
	`"AttachStdout":true,` +
	`"AttachStderr":true,` +
	`"Tty":false,` +
	`"OpenStdin":false,` +
	`"StdinOnce":false,` +
	`"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","LANG=C.UTF-8","APP_ENV=production","APP_REGION=us-east-1","DATABASE_URL=postgres://app@db.internal:5432/app?sslmode=require","REDIS_URL=redis://cache.internal:6379/0","LOG_LEVEL=info","OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.internal:4317","OTEL_RESOURCE_ATTRIBUTES=service.name=checkout-api,deployment.environment=production","FEATURE_FLAGS=checkout_v2,search_rerank,inline_receipts","S3_BUCKET=example-platform-checkout-uploads","S3_REGION=us-east-1","SMTP_HOST=smtp.internal","SMTP_PORT=587","TZ=Etc/UTC","SENTRY_DSN=https://public@sentry.internal/42","SENTRY_TRACES_SAMPLE_RATE=0.05","STATSD_ADDR=metrics.internal:8125","HTTP_IDLE_TIMEOUT=120s","HTTP_READ_TIMEOUT=30s","HTTP_WRITE_TIMEOUT=30s","GOMAXPROCS=8","GOMEMLIMIT=1800MiB","CHECKOUT_PROVIDER_BASE_URL=https://payments.partner.example.com/v3","CHECKOUT_WEBHOOK_PATH=/hooks/payments","SEARCH_INDEX_NAME=catalog-v9"],` +
	`"Cmd":["/usr/local/bin/app","serve","--config","/etc/app/config.yaml","--workers","8"],` +
	`"Entrypoint":["/usr/local/bin/entrypoint.sh"],` +
	`"Image":"registry.example.com/platform/app@sha256:3f9d2c1b8a7e6540f1c2d3b4a59687d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f70",` +
	`"WorkingDir":"/srv/app",` +
	`"Labels":{"com.example.team":"platform","com.example.service":"checkout-api","com.example.version":"1.42.0","org.opencontainers.image.revision":"9f1c2d3","com.example.tier":"backend","com.example.cost-center":"cc-4471","com.example.owner-email":"platform@example.com","com.example.deploy-id":"deploy-2026-09-05-014"},` +
	`"Volumes":{"/srv/app/tmp":{},"/var/log/app":{}},` +
	`"ExposedPorts":{"8080/tcp":{},"9090/tcp":{}},` +
	`"StopSignal":"SIGTERM",` +
	`"StopTimeout":30,` +
	`"Healthcheck":{"Test":["CMD","/usr/local/bin/app","healthcheck"],"Interval":10000000000,"Timeout":2000000000,"Retries":3,"StartPeriod":15000000000},` +
	`"HostConfig":{"Binds":["app-data:/srv/app/data","app-cache:/srv/app/cache","/etc/localtime:/etc/localtime:ro","app-logs:/var/log/app"],"NetworkMode":"appnet","PortBindings":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"18080"}],"9090/tcp":[{"HostIp":"127.0.0.1","HostPort":"19090"}]},"RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0},"AutoRemove":false,"VolumesFrom":[],"CapAdd":["NET_BIND_SERVICE"],"CapDrop":["ALL"],"Dns":["10.0.0.2"],"DnsSearch":["internal"],"ExtraHosts":["db.internal:10.0.1.15","cache.internal:10.0.1.16","smtp.internal:10.0.1.17","metrics.internal:10.0.1.18","sentry.internal:10.0.1.19","otel-collector.internal:10.0.1.20"],"LogConfig":{"Type":"json-file","Config":{"max-size":"10m","max-file":"3"}},"Memory":2147483648,"MemorySwap":2147483648,"MemoryReservation":1073741824,"NanoCpus":2000000000,"CpuShares":1024,"PidsLimit":512,"SecurityOpt":["no-new-privileges:true","seccomp=/etc/docker/seccomp/app.json"],"ReadonlyRootfs":true,"Tmpfs":{"/tmp":"rw,noexec,nosuid,size=64m","/run":"rw,noexec,nosuid,size=16m"},"Sysctls":{"net.ipv4.tcp_syncookies":"1","net.core.somaxconn":"1024","net.ipv4.ip_local_port_range":"10240 65535","net.ipv4.tcp_keepalive_time":"120"},"Ulimits":[{"Name":"nofile","Soft":65536,"Hard":65536},{"Name":"nproc","Soft":4096,"Hard":4096}],"Mounts":[{"Type":"volume","Source":"app-uploads","Target":"/srv/app/uploads","ReadOnly":false},{"Type":"volume","Source":"app-secrets","Target":"/run/secrets","ReadOnly":true},{"Type":"tmpfs","Target":"/srv/app/scratch","TmpfsOptions":{"SizeBytes":33554432}}]},` +
	`"NetworkingConfig":{"EndpointsConfig":{"appnet":{"Aliases":["app","checkout-api"],"NetworkID":"appnet","IPAMConfig":{"IPv4Address":"10.0.1.42"},"DriverOpts":{"com.docker.network.endpoint.sysctls":"net.ipv4.conf.IFNAME.arp_ignore=1"}},"obsnet":{"Aliases":["app-metrics"],"NetworkID":"obsnet","IPAMConfig":{"IPv4Address":"10.0.2.42"}}}}}`

// benchmarkRequestBody is a rewindable request body, so the benchmark measures
// the mutation pass rather than per-iteration reader allocation.
type benchmarkRequestBody struct {
	*bytes.Reader
}

func (benchmarkRequestBody) Close() error { return nil }

func benchmarkCreateRequest(reader *bytes.Reader, body []byte) *http.Request {
	reader.Reset(body)
	return &http.Request{Method: http.MethodPost, Body: benchmarkRequestBody{reader}}
}

// BenchmarkMutateContainerCreateOwnershipBody measures the whole owner-label
// injection pass over a realistic create body: read it, reject an ambiguous
// one, stamp the owner label, collect the cross-owner references, re-encode.
func BenchmarkMutateContainerCreateOwnershipBody(b *testing.B) {
	body := []byte(benchmarkContainerCreateBody)
	reader := bytes.NewReader(body)

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		req := benchmarkCreateRequest(reader, body)
		if _, err := mutateContainerCreateOwnershipBody(req, DefaultLabelKey, "job-123"); err != nil {
			b.Fatalf("mutateContainerCreateOwnershipBody() error = %v", err)
		}
	}
}

// TestMutateContainerCreateOwnershipBodyDecodesTheBodyOnce is the regression
// guard on the double decode. Running the ambiguity check against the raw
// bytes builds a second map[string]any of the entire body and throws it away,
// which measured at 1415 allocations for the body below against 808 for the
// single-decode pass. The ceiling sits between the two: it fails the moment
// the body is parsed twice again, and leaves room for ordinary churn.
func TestMutateContainerCreateOwnershipBodyDecodesTheBodyOnce(t *testing.T) {
	if raceBuild {
		t.Skip("race instrumentation inflates allocation counts")
	}
	const maxAllocs = 1000

	body := []byte(benchmarkContainerCreateBody)
	reader := bytes.NewReader(body)

	got := testing.AllocsPerRun(50, func() {
		req := benchmarkCreateRequest(reader, body)
		if _, err := mutateContainerCreateOwnershipBody(req, DefaultLabelKey, "job-123"); err != nil {
			t.Fatalf("mutateContainerCreateOwnershipBody() error = %v", err)
		}
	})
	if got > maxAllocs {
		t.Fatalf("mutateContainerCreateOwnershipBody allocations = %.0f, want at most %d — the body is being decoded more than once", got, maxAllocs)
	}
}
