package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/compliance"
)

func TestExecuteReportJSONOnCISPreset(t *testing.T) {
	stdout, stderr, err := executeRootCommand(t, "-c", "../../configs/cis-docker-benchmark.yaml", "report", "-o", "json")
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
	}
	var report compliance.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("report is not valid JSON: %v\n%s", err, stdout)
	}
	if report.Benchmark != compliance.Benchmark || report.Disclaimer != compliance.Disclaimer {
		t.Fatalf("unexpected header: %+v", report)
	}
	for _, c := range report.Controls {
		if c.Category == compliance.CategoryEnforced &&
			c.Status != compliance.StatusConfigured && c.Status != compliance.StatusAlwaysOn {
			t.Errorf("%s = %s on the CIS preset", c.ID, c.Status)
		}
	}
}

func TestExecuteReportFormats(t *testing.T) {
	for output, want := range map[string]string{
		"text":     "Benchmark:",
		"markdown": "# CIS Docker Benchmark v1.6.0 configuration report",
		"MARKDOWN": "| Control | Title | Category | Status |",
	} {
		stdout, stderr, err := executeRootCommand(t, "-c", "../../configs/cis-docker-benchmark.yaml", "report", "-o", output)
		if err != nil {
			t.Fatalf("-o %s: %v\nstderr:\n%s", output, err, stderr)
		}
		if !strings.Contains(stdout, want) || !strings.Contains(stdout, compliance.Disclaimer) {
			t.Errorf("-o %s output missing %q or the disclaimer:\n%s", output, want, stdout)
		}
	}
}

func TestExecuteReportFailures(t *testing.T) {
	dir := t.TempDir()
	invalid := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(invalid, []byte("rules:\n  - match: { method: GET, path: \"/x\" }\n    action: bogus\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	malformed := filepath.Join(dir, "malformed.yaml")
	if err := os.WriteFile(malformed, []byte("rules: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
	}{
		{"invalid rule", []string{"-c", invalid, "report", "-o", "json"}},
		{"malformed yaml", []string{"-c", malformed, "report", "-o", "json"}},
		{"missing config", []string{"-c", filepath.Join(dir, "missing.yaml"), "report", "-o", "json"}},
		{"unknown format", []string{"-c", "../../configs/cis-docker-benchmark.yaml", "report", "-o", "xml"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, err := executeRootCommand(t, tt.args...)
			if err == nil {
				t.Fatalf("expected an error, got stdout:\n%s", stdout)
			}
			if strings.Contains(stdout, compliance.Disclaimer) {
				t.Errorf("a failed report must not emit a report, got:\n%s", stdout)
			}
		})
	}
}
