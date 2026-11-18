package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/v3/app/internal/compliance"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

const (
	reportOutputText     = "text"
	reportOutputJSON     = "json"
	reportOutputMarkdown = "markdown"
)

var reportOutput string

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a CIS Docker Benchmark configuration report",
	Long:  "Load the effective configuration and report which CIS Docker Benchmark controls it configures. The report describes configuration only: it is not a CIS certification and does not prove runtime enforcement.",
	RunE:  runReport,
}

func init() {
	rootCmd.AddCommand(reportCmd)

	reportCmd.Flags().StringVarP(&reportOutput, "output", "o", reportOutputText, "output format: text, json, or markdown")
}

func runReport(cmd *cobra.Command, args []string) error {
	output := strings.ToLower(strings.TrimSpace(reportOutput))
	switch output {
	case reportOutputText, reportOutputJSON, reportOutputMarkdown:
	default:
		return fmt.Errorf("unsupported output format %q (must be text, json, or markdown)", reportOutput)
	}

	if err := requireExplicitConfigFile(cmd, cfgFile); err != nil {
		return fmt.Errorf("config preflight: %w", err)
	}

	// Like match, report is a check tool: a config path that does not exist
	// must not silently report on the built-in defaults.
	if cfgFile != "" {
		if _, err := os.Stat(cfgFile); err != nil {
			return fmt.Errorf("config file: %w", err)
		}
	}

	cfg, data, err := config.LoadWithData(cfgFile)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}

	config.ApplyCompat(cfg, discardLogger)

	if _, err := validateAndCompileRules(cfg); err != nil {
		return fmt.Errorf("config validation: %w", err)
	}

	report := compliance.Generate(cfg, data)
	out := cmd.OutOrStdout()
	switch output {
	case reportOutputJSON:
		return compliance.WriteJSON(out, report)
	case reportOutputMarkdown:
		return compliance.WriteMarkdown(out, report)
	default:
		return compliance.WriteText(out, report)
	}
}
