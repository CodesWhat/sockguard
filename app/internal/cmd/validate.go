package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/ui"
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
	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()
	stdoutP := ui.New(out)
	stderrP := ui.New(errOut)

	if err := requireExplicitConfigFile(cmd, cfgFile); err != nil {
		wrapped := fmt.Errorf("config preflight: %w", err)
		printValidationFailure(errOut, stderrP, wrapped)
		return wrapped
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		wrapped := fmt.Errorf("config load: %w", err)
		printValidationFailure(errOut, stderrP, wrapped)
		return wrapped
	}

	compatActive := config.ApplyCompat(cfg, discardLogger)

	compiled, err := newServeDeps().validateRules(cfg)
	if err != nil {
		printValidationFailure(errOut, stderrP, err)
		return err
	}

	printHeader(out, stdoutP, cfg, compatActive)
	printRules(out, stdoutP, cfg, len(compiled))
	printClientProfiles(out, stdoutP, cfg)
	fmt.Fprintf(out, "  %s %s\n", stdoutP.Green(ui.Check), stdoutP.Green("validation passed"))
	return nil
}

func printHeader(out io.Writer, p *ui.Printer, cfg *config.Config, compatActive bool) {
	fmt.Fprintf(out, "  %s  %s\n", p.Dim("Config  "), cfgFile)
	fmt.Fprintf(out, "  %s  %s\n", p.Dim("Listen  "), listenerAddr(cfg))
	fmt.Fprintf(out, "  %s  %s\n", p.Dim("Upstream"), cfg.Upstream.Socket)
	if compatActive {
		fmt.Fprintf(out, "  %s  %s\n", p.Dim("Mode    "), "tecnativa compatibility")
	}
	fmt.Fprintln(out)
}

func printRules(out io.Writer, p *ui.Printer, cfg *config.Config, count int) {
	fmt.Fprintf(out, "  %s\n", p.Bold(fmt.Sprintf("Rules (%d)", count)))
	for _, r := range cfg.Rules {
		glyph := p.Green(ui.Check)
		action := p.Green("allow")
		if r.Action == "deny" {
			glyph = p.Red(ui.Cross)
			action = p.Red("deny ")
		}
		method := r.Match.Method
		if method == "" {
			method = "*"
		}
		fmt.Fprintf(out, "    %s %s  %-6s %s\n", glyph, action, method, r.Match.Path)
	}
	fmt.Fprintln(out)
}

func printClientProfiles(out io.Writer, p *ui.Printer, cfg *config.Config) {
	if len(cfg.Clients.Profiles) == 0 {
		return
	}

	fmt.Fprintf(out, "  %s\n", p.Bold(fmt.Sprintf("Client Profiles (%d)", len(cfg.Clients.Profiles))))
	for _, profile := range cfg.Clients.Profiles {
		name := profile.Name
		if cfg.Clients.DefaultProfile == profile.Name {
			name += " (default)"
		}
		fmt.Fprintf(out, "    %s\n", p.Bold(name))
		for _, r := range profile.Rules {
			glyph := p.Green(ui.Check)
			action := p.Green("allow")
			if r.Action == "deny" {
				glyph = p.Red(ui.Cross)
				action = p.Red("deny ")
			}
			method := r.Match.Method
			if method == "" {
				method = "*"
			}
			fmt.Fprintf(out, "      %s %s  %-6s %s\n", glyph, action, method, r.Match.Path)
		}
	}
	fmt.Fprintln(out)
}

func printValidationFailure(out io.Writer, p *ui.Printer, err error) {
	fmt.Fprintf(out, "  %s %s\n", p.Red(ui.Cross), p.Red("validation failed"))
	fmt.Fprintf(out, "    %s\n", err)
}
