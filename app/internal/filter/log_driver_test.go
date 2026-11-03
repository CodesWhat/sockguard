package filter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLogDriverPolicyOffByDefault pins that an empty allowlist enforces
// nothing, whatever the driver or option names, so default behavior is
// unchanged.
func TestLogDriverPolicyOffByDefault(t *testing.T) {
	p := newLogDriverPolicy(nil, []string{"syslog-address"})
	if p.enabled() {
		t.Fatal("policy with no drivers reports enabled")
	}
	if reason := p.denyMapReason("container create", "syslog", map[string]string{"syslog-address": "tcp://evil:514"}); reason != "" {
		t.Fatalf("disabled policy denied: %q", reason)
	}
}

func TestLogDriverPolicyArgs(t *testing.T) {
	p := newLogDriverPolicy([]string{"json-file", "local", " "}, []string{"Fluentd-Address"})
	tests := []struct {
		name   string
		driver string
		args   []string
		want   string
	}{
		{name: "allowed driver", driver: "json-file"},
		{name: "second allowed driver with size options", driver: "local", args: []string{"max-size=10m", "max-file=3"}},
		{name: "empty driver is the daemon default", driver: ""},
		{name: "unlisted driver", driver: "syslog", want: `x denied: log driver "syslog" is not allowed (see allowed_log_drivers)`},
		{name: "driver case variant", driver: "JSON-file", want: `x denied: log driver "JSON-file" is not allowed (see allowed_log_drivers)`},
		{name: "driver padded", driver: "json-file ", want: `x denied: log driver "json-file " is not allowed (see allowed_log_drivers)`},
		{name: "driver option replaces driver", driver: "json-file", args: []string{"driver=syslog"}, want: `x denied: log driver "syslog" is not allowed (see allowed_log_drivers)`},
		{name: "driver option in capitals", driver: "json-file", args: []string{"DRIVER=gelf"}, want: `x denied: log driver "gelf" is not allowed (see allowed_log_drivers)`},
		{name: "driver carried in the key", driver: "json-file", args: []string{"driver=gelf=x"}, want: `x denied: log driver "gelf=x" is not allowed (see allowed_log_drivers)`},
		{name: "driver option naming an allowed driver", driver: "json-file", args: []string{"driver=local"}},
		{name: "driver option with no value", driver: "json-file", args: []string{"driver"}, want: `x denied: log driver "" is not allowed (see allowed_log_drivers)`},
		{name: "syslog address", driver: "json-file", args: []string{"syslog-address=tcp://evil:514"}, want: `x denied: log option "syslog-address" sets a log destination and is not allowed (see allowed_log_endpoint_options)`},
		{name: "gelf address in capitals", driver: "json-file", args: []string{"GELF-ADDRESS=udp://evil:12201"}, want: `x denied: log option "gelf-address" sets a log destination and is not allowed (see allowed_log_endpoint_options)`},
		{name: "loki proxy url", driver: "json-file", args: []string{"loki-proxy-url=http://evil"}, want: `x denied: log option "loki-proxy-url" sets a log destination and is not allowed (see allowed_log_endpoint_options)`},
		{name: "loki url", driver: "", args: []string{"loki-url=https://evil"}, want: `x denied: log option "loki-url" sets a log destination and is not allowed (see allowed_log_endpoint_options)`},
		{name: "splunk url", driver: "json-file", args: []string{"splunk-url=https://evil"}, want: `x denied: log option "splunk-url" sets a log destination and is not allowed (see allowed_log_endpoint_options)`},
		{name: "awslogs endpoint", driver: "json-file", args: []string{"awslogs-endpoint=https://evil"}, want: `x denied: log option "awslogs-endpoint" sets a log destination and is not allowed (see allowed_log_endpoint_options)`},
		{name: "endpoint padded", driver: "json-file", args: []string{" syslog-address =x"}, want: `x denied: log option "syslog-address" sets a log destination and is not allowed (see allowed_log_endpoint_options)`},
		{name: "endpoint carried in the key", driver: "json-file", args: []string{"syslog-address=a=b"}, want: `x denied: log option "syslog-address" sets a log destination and is not allowed (see allowed_log_endpoint_options)`},
		{name: "listed endpoint option, any case", driver: "json-file", args: []string{"fluentd-address=unix:///run/f.sock"}},
		{name: "tag and labels", driver: "json-file", args: []string{"tag={{.Name}}", "labels=team", "env=TIER"}},
		{name: "value that mentions an endpoint key", driver: "json-file", args: []string{"tag=syslog-address"}},
		{name: "certificate paths are not destinations", driver: "json-file", args: []string{"syslog-tls-ca-cert=/etc/ca.pem"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.denyArgsReason("x", tt.driver, tt.args); got != tt.want {
				t.Fatalf("denyArgsReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestContainerCreatePolicyLogDrivers(t *testing.T) {
	logConfig := func(value string) string {
		return `{"Image":"alpine","HostConfig":{"LogConfig":` + value + `}}`
	}
	opts := ContainerCreateOptions{AllowedLogDrivers: []string{"json-file", "local"}}
	const (
		driverDenied   = `container create denied: log driver "syslog" is not allowed (see allowed_log_drivers)`
		endpointDenied = `container create denied: log option "syslog-address" sets a log destination and is not allowed (see allowed_log_endpoint_options)`
	)
	tests := []struct {
		name string
		opts ContainerCreateOptions
		body string
		want string
	}{
		{name: "off: any driver", body: logConfig(`{"Type":"syslog","Config":{"syslog-address":"tcp://evil:514"}}`)},
		{name: "unlisted driver", opts: opts, body: logConfig(`{"Type":"syslog"}`), want: driverDenied},
		{name: "unlisted driver in lowercase struct keys", opts: opts, body: `{"hostconfig":{"logconfig":{"type":"syslog"}}}`, want: driverDenied},
		{name: "driver replaced by an option", opts: opts, body: logConfig(`{"Type":"json-file","Config":{"driver":"syslog"}}`), want: driverDenied},
		{name: "endpoint under an allowed driver", opts: opts, body: logConfig(`{"Type":"json-file","Config":{"syslog-address":"tcp://evil:514"}}`), want: endpointDenied},
		{name: "endpoint with no driver", opts: opts, body: logConfig(`{"Config":{"syslog-address":"tcp://evil:514"}}`), want: endpointDenied},
		{name: "listed driver", opts: opts, body: logConfig(`{"Type":"json-file","Config":{"max-size":"10m"}}`)},
		{name: "no LogConfig", opts: opts, body: `{"Image":"alpine","HostConfig":{}}`},
		{name: "empty LogConfig", opts: opts, body: logConfig(`{}`)},
		{name: "null LogConfig", opts: opts, body: logConfig(`null`)},
		{
			name: "listed endpoint option under a listed driver",
			opts: ContainerCreateOptions{AllowedLogDrivers: []string{"syslog"}, AllowedLogEndpointOptions: []string{"syslog-address"}},
			body: logConfig(`{"Type":"syslog","Config":{"syslog-address":"unixgram:///dev/log"}}`),
		},
		{
			name: "a listed endpoint option does not list its neighbors",
			opts: ContainerCreateOptions{AllowedLogDrivers: []string{"syslog"}, AllowedLogEndpointOptions: []string{"syslog-address"}},
			body: logConfig(`{"Type":"syslog","Config":{"syslog-address":"unixgram:///dev/log","gelf-address":"udp://evil:1"}}`),
			want: `container create denied: log option "gelf-address" sets a log destination and is not allowed (see allowed_log_endpoint_options)`,
		},
		// allow_log_path is its own gate and answers first, with or without the driver list.
		{
			name: "log path is still refused with a driver list",
			opts: ContainerCreateOptions{AllowedLogDrivers: []string{"k8s-file"}},
			body: logConfig(`{"Type":"k8s-file","Config":{"path":"/host/x.log"}}`),
			want: "container create denied: setting a log path in HostConfig.LogConfig.Config is not allowed (set allow_log_path: true)",
		},
		{
			name: "allow_log_path does not open an unlisted driver",
			opts: ContainerCreateOptions{AllowLogPath: true, AllowedLogDrivers: []string{"json-file"}},
			body: logConfig(`{"Type":"k8s-file","Config":{"path":"/host/x.log"}}`),
			want: `container create denied: log driver "k8s-file" is not allowed (see allowed_log_drivers)`,
		},
		{
			name: "both gates open",
			opts: ContainerCreateOptions{AllowLogPath: true, AllowedLogDrivers: []string{"k8s-file"}},
			body: logConfig(`{"Type":"k8s-file","Config":{"path":"/host/x.log"}}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, err := newContainerCreatePolicy(tt.opts).inspect(nil, makeInspectRequest(t, tt.body), "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.want {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.want)
			}
		})
	}
}

func TestLibpodContainerCreatePolicyLogDrivers(t *testing.T) {
	create := func(fields string) []byte {
		return []byte(`{"systemd":"false","image":"alpine"` + fields + `}`)
	}
	opts := LibpodContainerCreateOptions{AllowedLogDrivers: []string{"journald", "k8s-file"}}
	const (
		driverDenied   = `libpod container create denied: log driver "syslog" is not allowed (see allowed_log_drivers)`
		endpointDenied = `libpod container create denied: log option "gelf-address" sets a log destination and is not allowed (see allowed_log_endpoint_options)`
	)
	tests := []struct {
		name string
		opts LibpodContainerCreateOptions
		body []byte
		want string
	}{
		{name: "off: any driver", body: create(`,"log_configuration":{"driver":"syslog","options":{"gelf-address":"udp://evil:1"}}`)},
		{name: "unlisted driver", opts: opts, body: create(`,"log_configuration":{"driver":"syslog"}`), want: driverDenied},
		{name: "unlisted driver under capitalized keys", opts: opts, body: create(`,"LOG_CONFIGURATION":{"Driver":"syslog"}`), want: driverDenied},
		{name: "driver replaced by an option", opts: opts, body: create(`,"log_configuration":{"driver":"journald","options":{"driver":"syslog"}}`), want: driverDenied},
		{name: "endpoint option", opts: opts, body: create(`,"log_configuration":{"driver":"journald","options":{"gelf-address":"udp://evil:1"}}`), want: endpointDenied},
		{name: "listed driver with tag", opts: opts, body: create(`,"log_configuration":{"driver":"journald","options":{"tag":"web"}}`)},
		{name: "no driver is the daemon default", opts: opts, body: create(`,"log_configuration":{}`)},
		{name: "no log_configuration", opts: opts, body: create(``)},
		{name: "null log_configuration", opts: opts, body: create(`,"log_configuration":null`)},
		{
			name: "listed endpoint option",
			opts: LibpodContainerCreateOptions{AllowedLogDrivers: []string{"journald"}, AllowedLogEndpointOptions: []string{"gelf-address"}},
			body: create(`,"log_configuration":{"driver":"journald","options":{"gelf-address":"udp://collector:1"}}`),
		},
		{
			name: "log path is still refused with a driver list",
			opts: opts,
			body: create(`,"log_configuration":{"driver":"k8s-file","path":"/host/x.log"}`),
			want: "libpod container create denied: setting log_configuration.path is not allowed (set allow_log_path: true)",
		},
		{
			name: "allow_log_path does not open an unlisted driver",
			opts: LibpodContainerCreateOptions{AllowLogPath: true, AllowedLogDrivers: []string{"journald"}},
			body: create(`,"log_configuration":{"driver":"k8s-file","path":"/host/x.log"}`),
			want: `libpod container create denied: log driver "k8s-file" is not allowed (see allowed_log_drivers)`,
		},
		{
			name: "both gates open",
			opts: LibpodContainerCreateOptions{AllowLogPath: true, AllowedLogDrivers: []string{"k8s-file"}},
			body: create(`,"log_configuration":{"driver":"k8s-file","path":"/host/x.log"}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inspectLibpod(t, newLibpodContainerCreatePolicy(tt.opts), tt.body); got != tt.want {
				t.Fatalf("inspect() reason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestServicePolicyLogDrivers(t *testing.T) {
	svc := func(logDriver string) string {
		return `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest"}` + logDriver + `}}`
	}
	opts := ServiceOptions{AllowedLogDrivers: []string{"json-file"}}
	const (
		driverDenied   = `service denied: log driver "gelf" is not allowed (see allowed_log_drivers)`
		endpointDenied = `service denied: log option "loki-url" sets a log destination and is not allowed (see allowed_log_endpoint_options)`
	)
	tests := []struct {
		name string
		opts ServiceOptions
		path string
		body string
		want string
	}{
		{name: "off: any driver", path: "/services/create", body: svc(`,"LogDriver":{"Name":"gelf","Options":{"gelf-address":"udp://evil:1"}}`)},
		{name: "unlisted driver on create", opts: opts, path: "/services/create", body: svc(`,"LogDriver":{"Name":"gelf"}`), want: driverDenied},
		{name: "unlisted driver on update", opts: opts, path: "/v1.53/services/web/update?version=7", body: svc(`,"LogDriver":{"Name":"gelf"}`), want: driverDenied},
		{name: "endpoint option", opts: opts, path: "/services/create", body: svc(`,"LogDriver":{"Name":"json-file","Options":{"loki-url":"https://evil"}}`), want: endpointDenied},
		{name: "listed driver", opts: opts, path: "/services/create", body: svc(`,"LogDriver":{"Name":"json-file","Options":{"max-size":"10m"}}`)},
		{name: "no LogDriver", opts: opts, path: "/services/create", body: svc(``)},
		{name: "null LogDriver", opts: opts, path: "/services/create", body: svc(`,"LogDriver":null`)},
		{name: "empty LogDriver name is the swarm default", opts: opts, path: "/services/create", body: svc(`,"LogDriver":{"Name":""}`)},
		{
			name: "listed endpoint option",
			opts: ServiceOptions{AllowedLogDrivers: []string{"gelf"}, AllowedLogEndpointOptions: []string{"gelf-address"}},
			path: "/services/create",
			body: svc(`,"LogDriver":{"Name":"gelf","Options":{"gelf-address":"udp://collector:1"}}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.AllowAllRegistries = true
			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))
			got, err := newServicePolicy(tt.opts).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("inspect() reason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLibpodPlayKubePolicyLogDrivers(t *testing.T) {
	opts := LibpodPlayKubeOptions{AllowedLogDrivers: []string{"journald"}}
	const (
		driverDenied   = `libpod kube play denied: log driver "k8s-file" is not allowed (see allowed_log_drivers)`
		endpointDenied = `libpod kube play denied: log option "fluentd-address" sets a log destination and is not allowed (see allowed_log_endpoint_options)`
	)
	tests := []struct {
		name   string
		opts   LibpodPlayKubeOptions
		method string
		path   string
		want   string
	}{
		{name: "off: any driver", path: "/v5.8.6/libpod/play/kube?logDriver=k8s-file&logOptions=fluentd-address%3Dtcp%3A%2F%2Fevil%3A1"},
		{name: "unlisted driver", opts: opts, path: "/v5.8.6/libpod/play/kube?logDriver=k8s-file", want: driverDenied},
		{name: "unlisted driver on the kube/play alias", opts: opts, path: "/libpod/kube/play?logDriver=k8s-file", want: driverDenied},
		{name: "driver key in capitals", opts: opts, path: "/libpod/play/kube?LOGDRIVER=k8s-file", want: driverDenied},
		{name: "driver repeated, last one unlisted", opts: opts, path: "/libpod/play/kube?logDriver=journald&logDriver=k8s-file", want: driverDenied},
		{name: "driver repeated, first one unlisted", opts: opts, path: "/libpod/play/kube?logDriver=k8s-file&logDriver=journald", want: driverDenied},
		{name: "driver replaced by a log option", opts: opts, path: "/libpod/play/kube?logDriver=journald&logOptions=driver%3Dk8s-file", want: driverDenied},
		{name: "endpoint log option", opts: opts, path: "/libpod/play/kube?logDriver=journald&logOptions=fluentd-address%3Dtcp%3A%2F%2Fevil%3A1", want: endpointDenied},
		{name: "endpoint log option in capitals key", opts: opts, path: "/libpod/play/kube?LogOptions=FLUENTD-ADDRESS%3Dx", want: endpointDenied},
		{name: "listed driver with tag", opts: opts, path: "/libpod/play/kube?logDriver=journald&logOptions=tag%3Dweb"},
		{name: "no log parameters is the daemon default", opts: opts, path: "/libpod/play/kube?start=true"},
		{
			name: "listed endpoint option",
			opts: LibpodPlayKubeOptions{AllowedLogDrivers: []string{"journald"}, AllowedLogEndpointOptions: []string{"fluentd-address"}},
			path: "/libpod/play/kube?logDriver=journald&logOptions=fluentd-address%3Dunix%3A%2F%2F%2Frun%2Ff.sock",
		},
		{name: "other routes are not touched", opts: opts, path: "/libpod/pods/create?logDriver=k8s-file"},
		{name: "kube down is not touched", opts: opts, method: http.MethodDelete, path: "/libpod/play/kube?logDriver=k8s-file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			req := httptest.NewRequest(method, tt.path, strings.NewReader("apiVersion: v1\n"))
			reason, err := newLibpodPlayKubePolicy(tt.opts).inspect(nil, req, NormalizePath(req.URL.Path))
			if got := inspectorDenyReason(t, reason, err); got != tt.want {
				t.Fatalf("inspect() reason = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestLibpodPlayKubeInspectionIsMatched pins that the middleware table routes
// both kube play spellings to the log driver inspector.
func TestLibpodPlayKubeInspectionIsMatched(t *testing.T) {
	for _, path := range []string{"/libpod/play/kube", "/libpod/kube/play"} {
		if !matchesLibpodPlayKubeInspection(path) {
			t.Errorf("matchesLibpodPlayKubeInspection(%q) = false", path)
		}
	}
	for _, path := range []string{"/libpod/play/kube/extra", "/play/kube", "/libpod/kube/apply"} {
		if matchesLibpodPlayKubeInspection(path) {
			t.Errorf("matchesLibpodPlayKubeInspection(%q) = true", path)
		}
	}
}

func FuzzLogDriverPolicy(f *testing.F) {
	f.Add("json-file", "max-size=10m\nmax-file=3", "")
	f.Add("syslog", "syslog-address=tcp://evil:514", "logDriver=syslog&logOptions=syslog-address%3Dx")
	f.Add("", "driver=gelf\nGELF-ADDRESS=udp://evil:1", "LOGDRIVER=gelf")
	f.Add("json-file ", "driver=json-file", "logOptions=driver%3Djson-file&logOptions=loki-url%3Dx")
	f.Add("local", "=path\n=\nsplunk-url", "logDriver=%zz")

	enabled := newLogDriverPolicy([]string{"json-file", "local"}, []string{"fluentd-address"})
	disabled := newLogDriverPolicy(nil, nil)

	f.Fuzz(func(t *testing.T, driver, options, rawQuery string) {
		args := strings.Split(options, "\n")
		if reason := disabled.denyArgsReason("x", driver, args); reason != "" {
			t.Fatalf("disabled policy denied: %q", reason)
		}
		reason := enabled.denyArgsReason("x", driver, args)
		if driver != "" && driver != "json-file" && driver != "local" && reason == "" {
			t.Fatalf("driver %q admitted", driver)
		}
		for _, arg := range args {
			name, _, _ := strings.Cut(arg, "=")
			if strings.ToLower(strings.TrimSpace(name)) == "syslog-address" && reason == "" {
				t.Fatalf("endpoint option %q admitted", arg)
			}
		}

		req := httptest.NewRequest(http.MethodPost, "/libpod/play/kube", strings.NewReader(""))
		req.URL.RawQuery = rawQuery
		_, _ = newLibpodPlayKubePolicy(LibpodPlayKubeOptions{AllowedLogDrivers: []string{"json-file"}}).inspect(nil, req, "/libpod/play/kube")
	})
}
