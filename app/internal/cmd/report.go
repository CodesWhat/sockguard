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

// reportLoadConfig is a seam so tests can simulate a config file that vanishes
// between the preflight stat and the read.
var reportLoadConfig = config.LoadWithData

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a CIS Docker Benchmark configuration report",
	Long:  "Load the effective configuration and report which CIS Docker Benchmark controls it configures. The report describes configuration only: it is not a CIS certification and does not prove runtime enforcement.",
	Args:  cobra.NoArgs,
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
	// must not silently report on the built-in defaults. The default path is
	// not selected, so a missing default still falls back to the defaults.
	if cfgFile != "" && configFlagChanged(cmd) {
		if _, err := os.Stat(cfgFile); err != nil {
			return fmt.Errorf("config file: %w", err)
		}
	}

	cfg, data, err := reportLoadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}
	// LoadWithData falls back to defaults when the file is missing. That
	// fallback is only right when no path was selected; a selected path that
	// vanished after the stat must not produce a report on defaults.
	if data == nil && cfgFile != "" && configFlagChanged(cmd) {
		return fmt.Errorf("config load: config file %q could not be read", cfgFile)
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

func configFlagChanged(cmd *cobra.Command) bool {
	flag := cmd.Flag("config")
	if flag == nil && cmd.Root() != nil {
		flag = cmd.Root().Flag("config")
	}
	return flag != nil && flag.Changed
}
