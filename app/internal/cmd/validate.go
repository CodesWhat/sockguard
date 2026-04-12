package cmd

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/config"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration file",
	Long:  "Parse and validate the sockguard configuration file, then print the effective rule set.",
	RunE:  runValidate,
}

func init() {
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	// 1. Load config
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}

	// 2. Tecnativa compat (with discard logger)
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	compatActive := config.ApplyCompat(cfg, discardLogger)

	// 3. Validate and compile rules
	compiled, err := newServeDeps().validateRules(cfg)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Validation FAILED:\n%v\n", err)
		return err
	}

	// 4. Print effective config
	fmt.Fprintf(cmd.OutOrStdout(), "Config:   %s\n", cfgFile)
	fmt.Fprintf(cmd.OutOrStdout(), "Listen:   %s\n", listenerAddr(cfg))
	fmt.Fprintf(cmd.OutOrStdout(), "Upstream: %s\n", cfg.Upstream.Socket)
	if compatActive {
		fmt.Fprintf(cmd.OutOrStdout(), "Mode:     tecnativa compatibility\n")
	}
	fmt.Fprintln(cmd.OutOrStdout())

	// 5. Print rule table
	fmt.Fprintf(cmd.OutOrStdout(), "Rules (%d):\n", len(compiled))
	for _, r := range cfg.Rules {
		action := "ALLOW"
		if r.Action == "deny" {
			action = "DENY "
		}
		fmt.Fprintf(cmd.OutOrStdout(), "  %s  %-20s %s\n", action, r.Match.Method, r.Match.Path)
	}
	fmt.Fprintln(cmd.OutOrStdout())

	// 6. Print result
	fmt.Fprintln(cmd.OutOrStdout(), "Validation: OK")
	return nil
}
