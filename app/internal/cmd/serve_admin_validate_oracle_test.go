package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// candidateWithTLSPaths builds a candidate config whose listen.tls block is
// complete and points every file at path. A complete block is what makes the
// validator try to load the material, so this is the shape that reached
// tls.LoadX509KeyPair and os.ReadFile before the structural split.
func candidateWithTLSPaths(path string) []byte {
	return fmt.Appendf(nil, `
listen:
  address: 127.0.0.1:2375
  tls:
    cert_file: %q
    key_file: %q
    client_ca_file: %q
upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
`, path, path, path)
}

// TestAdminValidateIsNotAFilesystemOracle is the end-to-end regression for the
// admin /validate probing oracle.
//
// A caller who cannot read the host filesystem could previously name any
// absolute path in a candidate's listen.tls block and read the wrapped
// os.PathError back out of ValidateResponse.Errors, learning whether the path
// exists, whether sockguard can read it, and whether it parses as PEM.
//
// The property asserted here is indistinguishability, not just "no error":
// every probe below has to produce the identical response, because any
// difference between them is the oracle. Scrubbing the message would not have
// been enough — "loaded" versus "did not load" is itself the answer.
func TestAdminValidateIsNotAFilesystemOracle(t *testing.T) {
	dir := t.TempDir()

	notPEM := filepath.Join(dir, "present.txt")
	if err := os.WriteFile(notPEM, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write decoy: %v", err)
	}
	subdir := filepath.Join(dir, "present-dir")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	probes := []struct {
		name string
		path string
	}{
		{"absent", filepath.Join(dir, "absent.pem")},
		{"present but not PEM", notPEM},
		{"present but a directory", subdir},
		{"unreadable host path", "/etc/shadow"},
		{"host path that exists", "/etc/hosts"},
	}

	validator := buildAdminValidator(newDiscardLogger())

	var baseline string
	for i, probe := range probes {
		t.Run(probe.name, func(t *testing.T) {
			resp := validator(candidateWithTLSPaths(probe.path))
			if !resp.OK {
				t.Fatalf("OK = false for %q, want true; errors=%v", probe.path, resp.Errors)
			}
			if len(resp.Errors) != 0 {
				t.Fatalf("errors = %v for %q, want none", resp.Errors, probe.path)
			}
			// Nothing in the response may vary with the probed path.
			got := fmt.Sprintf("ok=%v rules=%d profiles=%d compat=%v errors=%v",
				resp.OK, resp.Rules, resp.Profiles, resp.CompatActive, resp.Errors)
			if i == 0 {
				baseline = got
				return
			}
			if got != baseline {
				t.Fatalf("response for %q differs from the baseline probe.\ngot:  %s\nwant: %s", probe.path, got, baseline)
			}
		})
	}
}

// TestAdminValidateStillReportsRealPolicyErrors guards the other side: the
// endpoint exists to tell an operator their candidate is wrong, and the
// filesystem split must not have blunted that.
func TestAdminValidateStillReportsRealPolicyErrors(t *testing.T) {
	validator := buildAdminValidator(newDiscardLogger())

	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "malformed tls identity selector",
			yaml: `
listen:
  address: 127.0.0.1:2375
  tls:
    cert_file: /tmp/c.pem
    key_file: /tmp/k.pem
    client_ca_file: /tmp/ca.pem
    ip_addresses: ["not-an-ip"]
upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
`,
			want: "listen.tls.ip_addresses",
		},
		{
			name: "incomplete tls block",
			yaml: `
listen:
  address: 127.0.0.1:2375
  tls:
    cert_file: /tmp/c.pem
upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
`,
			want: "listen.tls",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := validator([]byte(tc.yaml))
			if resp.OK {
				t.Fatalf("OK = true, want false")
			}
			if !strings.Contains(strings.Join(resp.Errors, "\n"), tc.want) {
				t.Fatalf("errors = %v, want one containing %q", resp.Errors, tc.want)
			}
		})
	}
}
