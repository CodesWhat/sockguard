package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/ui"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration file",
	Long:  "Parse and validate the sockguard configuration file, then print the effective rule set. V3 rejects insecure_skip_tls_verify and DOCKER_TLS without DOCKER_TLS_VERIFY.",
	RunE:  runValidate,
}

var validateStrict bool

// validateLoadConfig is a seam so tests can observe the single config read.
var validateLoadConfig = config.LoadWithData

func init() {
	validateCmd.Flags().BoolVar(&validateStrict, "strict", false, "exit non-zero when the configuration file has unrecognized keys")
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

	// validate reads the same SOCKGUARD_* overlay serve does (config.Load
	// below), so it owes the operator the same warning about a variable that
	// overlay ignores — this is the command they run to find out whether
	// their configuration says what they think it says. Warnings go to
	// stderr, leaving the report on stdout intact for anything parsing it.
	warnUnknownEnvVars(slog.New(slog.NewTextHandler(errOut, nil)), cfgFile, os.Environ())

	cfg, loadedBytes, err := validateLoadConfig(cfgFile)
	if err != nil {
		wrapped := fmt.Errorf("config load: %w", err)
		printValidationFailure(errOut, stderrP, wrapped)
		return wrapped
	}

	// Detection runs on the bytes Load parsed (no second read) and is purely
	// advisory: a detection error never turns a passing validation into a
	// failure.
	var unknownKeys []string
	if len(loadedBytes) > 0 {
		if keys, kerr := config.UnknownKeysBytes(loadedBytes); kerr == nil {
			unknownKeys = keys
		}
	}
	logUnknownKeys(slog.New(slog.NewTextHandler(errOut, nil)), cfgFile, unknownKeys)

	compatActive := config.ApplyCompat(cfg, discardLogger)

	compiled, err := newServeDeps().validateRules(cfg)
	if err != nil {
		printValidationFailure(errOut, stderrP, err)
		return err
	}
	if _, _, err := resolveUpstreamSpecs(cfg, os.LookupEnv, discardLogger); err != nil {
		printValidationFailure(errOut, stderrP, err)
		return err
	}
	warnIfRulesMatchNoKnownRoute(cfg, slog.New(slog.NewTextHandler(errOut, nil)))

	printHeader(out, stdoutP, cfg, compatActive)
	printRules(out, stdoutP, cfg, len(compiled))
	printClientProfiles(out, stdoutP, cfg)
	if validateStrict && len(unknownKeys) > 0 {
		err := fmt.Errorf("%d unrecognized configuration key(s) (--strict)", len(unknownKeys))
		printValidationFailure(errOut, stderrP, err)
		return err
	}
	fmt.Fprintf(out, "  %s %s\n", stdoutP.Green(ui.Check), stdoutP.Green("validation passed"))
	return nil
}

func printHeader(out io.Writer, p *ui.Printer, cfg *config.Config, compatActive bool) {
	fmt.Fprintf(out, "  %s  %s\n", p.Dim("Config  "), cfgFile)
	fmt.Fprintf(out, "  %s  %s\n", p.Dim("Listen  "), listenerAddr(cfg))
	fmt.Fprintf(out, "  %s  %s\n", p.Dim("Upstream"), upstreamDisplayFromConfig(cfg))
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
