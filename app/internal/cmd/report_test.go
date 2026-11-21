package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/compliance"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
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
		// 5.7/5.8, 5.13 and 5.29 are opt-in gates the preset leaves off.
		if c.Category == compliance.CategoryEnforced && c.ID != "5.31" && c.ID != "5.7/5.8" && c.ID != "5.13" && c.ID != "5.29" &&
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

func TestExecuteReportRejectsPositionalArguments(t *testing.T) {
	stdout, _, err := executeRootCommand(t, "-c", "../../configs/cis-docker-benchmark.yaml", "report", "candidate.yaml")
	if err == nil {
		t.Fatalf("expected an error for a positional argument, got stdout:\n%s", stdout)
	}
	if strings.Contains(stdout, compliance.Disclaimer) {
		t.Errorf("no report should be emitted, got:\n%s", stdout)
	}
}

// A selected config that vanishes after the preflight stat makes LoadWithData
// fall back to defaults; report must refuse rather than describe defaults.
func TestExecuteReportRejectsSelectedConfigThatVanishes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gone.yaml")
	if err := os.WriteFile(path, []byte("log:\n  level: info\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := reportLoadConfig
	t.Cleanup(func() { reportLoadConfig = orig })
	reportLoadConfig = func(string) (*config.Config, []byte, error) {
		cfg := config.Defaults()
		return &cfg, nil, nil // what LoadWithData returns when the file is missing
	}
	stdout, _, err := executeRootCommand(t, "-c", path, "report", "-o", "json")
	if err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Fatalf("error = %v, want a could-not-be-read error", err)
	}
	if strings.Contains(stdout, compliance.Disclaimer) {
		t.Errorf("no report should be emitted, got:\n%s", stdout)
	}
}

func TestExecuteReportLoadErrorPropagates(t *testing.T) {
	orig := reportLoadConfig
	t.Cleanup(func() { reportLoadConfig = orig })
	reportLoadConfig = func(string) (*config.Config, []byte, error) { return nil, nil, errors.New("boom") }
	if _, _, err := executeRootCommand(t, "-c", "../../configs/cis-docker-benchmark.yaml", "report", "-o", "json"); err == nil {
		t.Fatal("expected the load error")
	}
}

func TestExecuteReportEmptyConfigFileIsStillAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.yaml")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := executeRootCommand(t, "-c", path, "report", "-o", "json"); err != nil {
		t.Fatalf("an existing empty config should report on defaults: %v\n%s", err, stderr)
	}
}

func TestExecuteReportMissingDefaultConfigFallsBackToDefaults(t *testing.T) {
	// Cobra keeps Changed from earlier runs; this run must not select a path.
	flag := rootCmd.PersistentFlags().Lookup("config")
	wasChanged := flag.Changed
	flag.Changed = false
	t.Cleanup(func() { flag.Changed = wasChanged })

	orig := reportLoadConfig
	t.Cleanup(func() { reportLoadConfig = orig })
	reportLoadConfig = func(string) (*config.Config, []byte, error) {
		cfg := config.Defaults()
		return &cfg, nil, nil // what LoadWithData returns for a missing file
	}

	// executeRootCommand restores cfgFile on cleanup, so pointing it at a
	// missing path here simulates an unset --config with an absent default.
	oldCfg := cfgFile
	t.Cleanup(func() { cfgFile = oldCfg })
	cfgFile = filepath.Join(t.TempDir(), "absent.yaml")

	stdout, stderr, err := executeRootCommand(t, "report", "-o", "json")
	if err != nil {
		t.Fatalf("a missing default config must fall back to defaults, got %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(stdout, compliance.Disclaimer) {
		t.Errorf("expected a report, got:\n%s", stdout)
	}
}
