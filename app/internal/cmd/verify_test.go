package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// verifyEnv holds the throwaway paths one verify test case runs against.
type verifyEnv struct {
	dir            string
	upstreamSocket string
	listenSocket   string
}

// newVerifyEnv creates a short-lived socket directory. It uses
// os.MkdirTemp("/tmp", ...) rather than t.TempDir() because macOS caps a unix
// socket path at 104 bytes and the per-test TempDir path is long enough to
// blow that cap once a socket name is appended.
func newVerifyEnv(t *testing.T) *verifyEnv {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sg-vfy-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return &verifyEnv{
		dir:            dir,
		upstreamSocket: filepath.Join(dir, "docker.sock"),
		listenSocket:   filepath.Join(dir, "sockguard.sock"),
	}
}

// serveOnUnixSocket runs handler on a unix socket for the life of the test.
func serveOnUnixSocket(t *testing.T, socketPath string, handler http.Handler) {
	t.Helper()
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen(unix, %q): %v", socketPath, err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		<-done
	})
}

// startFakeDockerDaemon answers the two routes verify probes: GET /version
// (the upstream flavor probe) and GET /containers/json (the readiness probe
// internal/health issues).
func startFakeDockerDaemon(t *testing.T, socketPath string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Components":[{"Name":"Engine","Version":"28.6.0"}],"Version":"28.6.0","ApiVersion":"1.52"}`)
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[]`)
	})
	serveOnUnixSocket(t, socketPath, mux)
}

// startFakeSockguardListener answers GET /health with the given status code,
// standing in for a running sockguard.
func startFakeSockguardListener(t *testing.T, socketPath string, status int) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	serveOnUnixSocket(t, socketPath, mux)
}

// clearDockerEnv removes the DOCKER_* variables verify's upstream resolution
// consults, so an ambient DOCKER_HOST on the developer's machine cannot
// repoint a test at a real daemon.
func clearDockerEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"DOCKER_HOST", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"} {
		value, present := os.LookupEnv(key)
		if !present {
			continue
		}
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("Unsetenv(%q): %v", key, err)
		}
		t.Cleanup(func() { _ = os.Setenv(key, value) })
	}
}

// writeVerifyConfig writes yaml to a file and points the package-level
// cfgFile at it for the duration of the test.
func writeVerifyConfig(t *testing.T, dir, yaml string) string {
	t.Helper()
	path := filepath.Join(dir, "sockguard.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	original := cfgFile
	cfgFile = path
	t.Cleanup(func() { cfgFile = original })
	return path
}

// runVerifyForTest runs the command against a bare cobra.Command so the test
// owns stdout/stderr, and returns the decoded JSON report plus the RunE error.
func runVerifyForTest(t *testing.T, deps *serveDeps) (verifyReport, string, error) {
	t.Helper()

	originalJSON := verifyJSONOutput
	verifyJSONOutput = true
	t.Cleanup(func() { verifyJSONOutput = originalJSON })

	var out, errOut bytes.Buffer
	command := &cobra.Command{Use: "verify"}
	command.SetOut(&out)
	command.SetErr(&errOut)
	command.SetContext(t.Context())

	err := runVerifyWithDeps(command, deps)

	var report verifyReport
	if decodeErr := json.Unmarshal(out.Bytes(), &report); decodeErr != nil {
		t.Fatalf("decode --json report: %v\nraw output:\n%s", decodeErr, out.String())
	}
	return report, out.String(), err
}

func verifyStatusByName(t *testing.T, report verifyReport) map[string]string {
	t.Helper()
	byName := make(map[string]string, len(report.Checks))
	for _, check := range report.Checks {
		if _, dup := byName[check.Name]; dup {
			t.Fatalf("check %q reported twice", check.Name)
		}
		if check.Detail == "" {
			t.Errorf("check %q has an empty detail", check.Name)
		}
		byName[check.Name] = check.Status
	}
	return byName
}

// baseVerifyConfig is a minimal config whose rules differ from the built-in
// defaults, so Tecnativa compatibility stays inactive.
func baseVerifyConfig(env *verifyEnv) string {
	return fmt.Sprintf(`
listen:
  socket: %s
upstream:
  socket: %s
log:
  level: info
  format: json
  output: stderr
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
`, env.listenSocket, env.upstreamSocket)
}

// TestRunVerifyChecks is the table over the five checks: a live fake upstream,
// a live and a dead sockguard listener, missing TLS material, and an
// image-trust trust root that will not load.
func TestRunVerifyChecks(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, env *verifyEnv) string
		want        map[string]string
		wantOverall string
		wantErr     bool
	}{
		{
			name: "upstream and listener both answer",
			setup: func(t *testing.T, env *verifyEnv) string {
				startFakeDockerDaemon(t, env.upstreamSocket)
				startFakeSockguardListener(t, env.listenSocket, http.StatusOK)
				return baseVerifyConfig(env)
			},
			want: map[string]string{
				verifyCheckNameConfig:     verifyStatusOK,
				verifyCheckNameUpstream:   verifyStatusOK,
				verifyCheckNameListener:   verifyStatusOK,
				verifyCheckNameTLS:        verifyStatusSkip,
				verifyCheckNameImageTrust: verifyStatusSkip,
			},
			wantOverall: verifyStatusOK,
		},
		{
			name: "listener socket absent is a skip, not a failure",
			setup: func(t *testing.T, env *verifyEnv) string {
				startFakeDockerDaemon(t, env.upstreamSocket)
				return baseVerifyConfig(env)
			},
			want: map[string]string{
				verifyCheckNameConfig:   verifyStatusOK,
				verifyCheckNameUpstream: verifyStatusOK,
				verifyCheckNameListener: verifyStatusSkip,
			},
			wantOverall: verifyStatusOK,
		},
		{
			name: "listener answering 503 is a failure",
			setup: func(t *testing.T, env *verifyEnv) string {
				startFakeDockerDaemon(t, env.upstreamSocket)
				startFakeSockguardListener(t, env.listenSocket, http.StatusServiceUnavailable)
				return baseVerifyConfig(env)
			},
			want: map[string]string{
				verifyCheckNameConfig:   verifyStatusOK,
				verifyCheckNameUpstream: verifyStatusOK,
				verifyCheckNameListener: verifyStatusFail,
			},
			wantOverall: verifyStatusFail,
			wantErr:     true,
		},
		{
			name: "upstream socket missing is a failure",
			setup: func(t *testing.T, env *verifyEnv) string {
				return baseVerifyConfig(env)
			},
			want: map[string]string{
				verifyCheckNameConfig:   verifyStatusOK,
				verifyCheckNameUpstream: verifyStatusFail,
				verifyCheckNameListener: verifyStatusSkip,
			},
			wantOverall: verifyStatusFail,
			wantErr:     true,
		},
		{
			name: "missing TLS material is a failure",
			setup: func(t *testing.T, env *verifyEnv) string {
				startFakeDockerDaemon(t, env.upstreamSocket)
				return fmt.Sprintf(`
listen:
  address: 127.0.0.1:0
  tls:
    cert_file: %s/absent-cert.pem
    key_file: %s/absent-key.pem
    client_ca_file: %s/absent-ca.pem
upstream:
  socket: %s
log:
  level: info
  format: json
  output: stderr
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
`, env.dir, env.dir, env.dir, env.upstreamSocket)
			},
			want: map[string]string{
				verifyCheckNameConfig:   verifyStatusOK,
				verifyCheckNameUpstream: verifyStatusOK,
				verifyCheckNameTLS:      verifyStatusFail,
			},
			wantOverall: verifyStatusFail,
			wantErr:     true,
		},
		{
			name: "keyed-only image trust needs no trust root",
			setup: func(t *testing.T, env *verifyEnv) string {
				startFakeDockerDaemon(t, env.upstreamSocket)
				loadImageTrustRoot = func() (root.TrustedMaterial, error) {
					t.Error("keyed-only image trust must not fetch the Sigstore trust root")
					return nil, errors.New("unexpected trust root fetch")
				}
				return baseVerifyConfig(env) + `
request_body:
  container_create:
    image_trust:
      mode: enforce
      allowed_signing_keys:
        - pem: "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"
`
			},
			want: map[string]string{
				verifyCheckNameConfig:     verifyStatusOK,
				verifyCheckNameImageTrust: verifyStatusOK,
			},
			wantOverall: verifyStatusOK,
		},
		{
			name: "keyless image trust whose trust root will not load is a failure",
			setup: func(t *testing.T, env *verifyEnv) string {
				startFakeDockerDaemon(t, env.upstreamSocket)
				loadImageTrustRoot = func() (root.TrustedMaterial, error) {
					return nil, errors.New("fetch sigstore trust root via TUF: no network")
				}
				return baseVerifyConfig(env) + `
request_body:
  container_create:
    image_trust:
      mode: enforce
      allowed_keyless:
        - issuer: https://accounts.google.com
          subject_pattern: ".*@example.com$"
`
			},
			want: map[string]string{
				verifyCheckNameConfig:     verifyStatusOK,
				verifyCheckNameImageTrust: verifyStatusFail,
			},
			wantOverall: verifyStatusFail,
			wantErr:     true,
		},
		{
			name: "a config that does not validate skips every later check",
			setup: func(t *testing.T, env *verifyEnv) string {
				return fmt.Sprintf(`
listen:
  socket: %s
upstream:
  socket: %s
rules:
  - match: { method: GET, path: "/_ping" }
    action: nope
`, env.listenSocket, env.upstreamSocket)
			},
			want: map[string]string{
				verifyCheckNameConfig:     verifyStatusFail,
				verifyCheckNameUpstream:   verifyStatusSkip,
				verifyCheckNameListener:   verifyStatusSkip,
				verifyCheckNameTLS:        verifyStatusSkip,
				verifyCheckNameImageTrust: verifyStatusSkip,
			},
			wantOverall: verifyStatusFail,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearDockerEnv(t)
			originalTrustRoot := loadImageTrustRoot
			t.Cleanup(func() { loadImageTrustRoot = originalTrustRoot })

			env := newVerifyEnv(t)
			yaml := tt.setup(t, env)
			writeVerifyConfig(t, env.dir, yaml)

			report, raw, err := runVerifyForTest(t, newServeDeps())
			if tt.wantErr && err == nil {
				t.Fatalf("runVerifyWithDeps() = nil, want a non-nil error so the process exits non-zero\nreport:\n%s", raw)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("runVerifyWithDeps() error = %v\nreport:\n%s", err, raw)
			}
			if report.Status != tt.wantOverall {
				t.Fatalf("report status = %q, want %q\nreport:\n%s", report.Status, tt.wantOverall, raw)
			}

			got := verifyStatusByName(t, report)
			for name, want := range tt.want {
				if got[name] != want {
					t.Errorf("check %q status = %q, want %q\nreport:\n%s", name, got[name], want, raw)
				}
			}
		})
	}
}

// TestRunVerifyJSONShape pins the --json document a scripted caller parses:
// the top-level keys, and one entry per check in a fixed order with a status
// drawn from the three-value set.
func TestRunVerifyJSONShape(t *testing.T) {
	clearDockerEnv(t)
	env := newVerifyEnv(t)
	startFakeDockerDaemon(t, env.upstreamSocket)
	startFakeSockguardListener(t, env.listenSocket, http.StatusOK)
	cfgPath := writeVerifyConfig(t, env.dir, baseVerifyConfig(env))

	report, raw, err := runVerifyForTest(t, newServeDeps())
	if err != nil {
		t.Fatalf("runVerifyWithDeps() error = %v\nreport:\n%s", err, raw)
	}

	if report.Config != cfgPath {
		t.Errorf("report config = %q, want %q", report.Config, cfgPath)
	}
	if report.Version == "" {
		t.Error("report version is empty")
	}
	if report.Status != verifyStatusOK {
		t.Errorf("report status = %q, want %q", report.Status, verifyStatusOK)
	}

	wantOrder := []string{
		verifyCheckNameConfig,
		verifyCheckNameUpstream,
		verifyCheckNameListener,
		verifyCheckNameTLS,
		verifyCheckNameImageTrust,
	}
	if len(report.Checks) != len(wantOrder) {
		t.Fatalf("report has %d checks, want %d\nreport:\n%s", len(report.Checks), len(wantOrder), raw)
	}
	allowed := map[string]bool{verifyStatusOK: true, verifyStatusFail: true, verifyStatusSkip: true}
	for i, want := range wantOrder {
		if report.Checks[i].Name != want {
			t.Errorf("check %d name = %q, want %q", i, report.Checks[i].Name, want)
		}
		if !allowed[report.Checks[i].Status] {
			t.Errorf("check %q status = %q, want one of ok/fail/skip", report.Checks[i].Name, report.Checks[i].Status)
		}
	}

	// The raw document must carry the snake_case-free key names verbatim.
	for _, key := range []string{`"config"`, `"version"`, `"status"`, `"checks"`, `"name"`, `"detail"`} {
		if !strings.Contains(raw, key) {
			t.Errorf("--json output is missing the %s key\nreport:\n%s", key, raw)
		}
	}
}

// TestRunVerifyTextOutputListsEveryCheck covers the default (non-JSON) writer:
// one line per check carrying its status word, and a closing verdict.
func TestRunVerifyTextOutputListsEveryCheck(t *testing.T) {
	clearDockerEnv(t)
	env := newVerifyEnv(t)
	startFakeDockerDaemon(t, env.upstreamSocket)
	writeVerifyConfig(t, env.dir, baseVerifyConfig(env))

	originalJSON := verifyJSONOutput
	verifyJSONOutput = false
	t.Cleanup(func() { verifyJSONOutput = originalJSON })

	var out, errOut bytes.Buffer
	command := &cobra.Command{Use: "verify"}
	command.SetOut(&out)
	command.SetErr(&errOut)
	command.SetContext(t.Context())

	if err := runVerifyWithDeps(command, newServeDeps()); err != nil {
		t.Fatalf("runVerifyWithDeps() error = %v\noutput:\n%s", err, out.String())
	}

	stdout := out.String()
	for _, name := range []string{
		verifyCheckNameConfig,
		verifyCheckNameUpstream,
		verifyCheckNameListener,
		verifyCheckNameTLS,
		verifyCheckNameImageTrust,
	} {
		if !strings.Contains(stdout, name) {
			t.Errorf("text output is missing the %q check\noutput:\n%s", name, stdout)
		}
	}
	if !strings.Contains(stdout, "verification passed") {
		t.Errorf("text output is missing the passing verdict\noutput:\n%s", stdout)
	}
	if errOut.Len() != 0 {
		t.Errorf("expected no stderr output, got:\n%s", errOut.String())
	}
}

// TestRootRegistersVerify pins verify onto the root command's subcommand list
// alongside the four that were already there.
func TestRootRegistersVerify(t *testing.T) {
	want := map[string]bool{
		"match":    false,
		"serve":    false,
		"validate": false,
		"verify":   false,
		"version":  false,
	}
	for _, command := range rootCmd.Commands() {
		if _, tracked := want[command.Name()]; tracked {
			want[command.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("root command is missing the %q subcommand", name)
		}
	}

	if flag := verifyCmd.Flags().Lookup("json"); flag == nil {
		t.Error("verify is missing the --json flag")
	}
	for _, name := range []string{"listen-socket", "upstream-socket"} {
		if flag := verifyCmd.Flags().Lookup(name); flag == nil {
			t.Errorf("verify is missing the --%s override", name)
		}
	}
}

// TestVerifyTLSTargetsMirrorTheValidatorGating pins which config blocks verify
// opens: TCP listeners with a complete mutual-TLS block, the admin listener
// only when admin is enabled on a dedicated TCP address, and nothing on a unix
// socket. That is exactly the set the full offline validator dereferences, so
// the tls check plus the structural config check together cover everything
// config.Validate would have opened.
func TestVerifyTLSTargetsMirrorTheValidatorGating(t *testing.T) {
	t.Parallel()

	complete := config.ListenTLSConfig{
		CertFile:     "/tmp/cert.pem",
		KeyFile:      "/tmp/key.pem",
		ClientCAFile: "/tmp/ca.pem",
	}

	tests := []struct {
		name string
		cfg  config.Config
		want []string
	}{
		{
			name: "legacy unix listener has no TLS material",
			cfg:  config.Config{Listen: config.ListenConfig{Socket: "/run/sockguard.sock"}},
			want: nil,
		},
		{
			name: "legacy TCP listener with complete TLS",
			cfg:  config.Config{Listen: config.ListenConfig{Address: "127.0.0.1:2376", TLS: complete}},
			want: []string{"listen.tls"},
		},
		{
			name: "explicit listeners are labeled by name and skip unix entries",
			cfg: config.Config{
				Listeners: []config.ListenerConfig{
					{Name: "ci", ListenConfig: config.ListenConfig{Socket: "/run/ci.sock"}},
					{Name: "ops", ListenConfig: config.ListenConfig{Address: "127.0.0.1:2376", TLS: complete}},
				},
			},
			want: []string{"listeners[ops].tls"},
		},
		{
			name: "an unnamed explicit listener falls back to its index",
			cfg: config.Config{
				Listeners: []config.ListenerConfig{
					{ListenConfig: config.ListenConfig{Address: "127.0.0.1:2376", TLS: complete}},
				},
			},
			want: []string{"listeners[0].tls"},
		},
		{
			name: "a disabled admin listener is not opened",
			cfg: config.Config{
				Listen: config.ListenConfig{Socket: "/run/sockguard.sock"},
				Admin: config.AdminConfig{
					Listen: config.AdminListenConfig{ListenConfig: config.ListenConfig{Address: "127.0.0.1:2377", TLS: complete}},
				},
			},
			want: nil,
		},
		{
			name: "an enabled admin listener on TCP is opened alongside the main one",
			cfg: config.Config{
				Listen: config.ListenConfig{Address: "127.0.0.1:2376", TLS: complete},
				Admin: config.AdminConfig{
					Enabled: true,
					Listen:  config.AdminListenConfig{ListenConfig: config.ListenConfig{Address: "127.0.0.1:2377", TLS: complete}},
				},
			},
			want: []string{"listen.tls", "admin.listen.tls"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := tt.cfg
			targets := verifyTLSTargets(&cfg)
			got := make([]string, len(targets))
			for i, target := range targets {
				got[i] = target.field
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("verifyTLSTargets() fields = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestVerifyImageTrustTargetsCoverProfiles pins that a client profile's own
// image_trust block is collected, not just the top-level one, and that a block
// left at mode off contributes nothing.
func TestVerifyImageTrustTargetsCoverProfiles(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	cfg.RequestBody.ContainerCreate.ImageTrust = config.ImageTrustConfig{Mode: "enforce"}
	cfg.RequestBody.Service.ImageTrust = config.ImageTrustConfig{Mode: "off"}
	cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "ci"}}
	cfg.Clients.Profiles[0].RequestBody.LibpodContainerCreate.ImageTrust = config.ImageTrustConfig{Mode: "warn"}

	targets := verifyImageTrustTargets(&cfg)
	got := imageTrustFields(targets)
	want := []string{
		"request_body.container_create.image_trust",
		"clients.profiles[ci].request_body.libpod_container_create.image_trust",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("verifyImageTrustTargets() fields = %v, want %v", got, want)
	}
}

// TestWriteVerifyTextReportsAFailingVerdict covers the failing arm of the text
// writer: every check line is still printed, and the closing verdict says the
// run failed rather than passed.
func TestWriteVerifyTextReportsAFailingVerdict(t *testing.T) {
	t.Parallel()

	report := verifyReport{
		Config:  "/etc/sockguard/sockguard.yaml",
		Version: "test",
		Status:  verifyStatusFail,
		Checks: []verifyCheck{
			verifyResult(verifyCheckNameConfig, verifyStatusOK, "loaded"),
			verifyResult(verifyCheckNameUpstream, verifyStatusFail, "daemon is dark"),
			verifyResult(verifyCheckNameListener, verifyStatusSkip, "not up"),
		},
	}

	var out bytes.Buffer
	writeVerifyText(&out, report)

	stdout := out.String()
	for _, want := range []string{"/etc/sockguard/sockguard.yaml", "test", "daemon is dark", "fail", "skip", "verification failed"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("text output is missing %q\noutput:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "verification passed") {
		t.Errorf("a failing report must not print the passing verdict\noutput:\n%s", stdout)
	}
}
