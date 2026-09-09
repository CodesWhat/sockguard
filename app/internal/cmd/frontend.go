package cmd

import (
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitrunner"
	"github.com/spf13/cobra"
)

func newFrontendCommand() *cobra.Command {
	var opts buildkitrunner.Options
	var reportPath string
	command := &cobra.Command{
		Use:   "frontend IMAGE@sha256:DIGEST",
		Short: "Run a pinned frontend through Sockguard's mediated gateway",
		Long: `Run a pinned external BuildKit frontend in an isolated Docker container.
Every gateway call goes to the selected Sockguard endpoint. JSONL operation
records are written before each Solve; execution still requires server policy.
Use --opt for frontend-specific options. Local file and credential providers
are not attached. The container runtime context must be selected explicitly.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (retErr error) {
			opts.Image = args[0]
			opts.Operations = cmd.OutOrStdout()
			opts.Stderr = cmd.ErrOrStderr()
			if reportPath != "" {
				file, err := os.OpenFile(reportPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- report destination is explicit local CLI input; exclusive creation prevents overwriting existing files.
				if err != nil {
					return err
				}
				defer func() { retErr = errors.Join(retErr, file.Close()) }()
				opts.Operations = file
			}
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			return buildkitrunner.Run(ctx, opts)
		},
	}
	flags := command.Flags()
	flags.StringVar(&opts.Host, "host", "unix:///var/run/sockguard.sock", "Sockguard endpoint (unix://, http://, or https://)")
	flags.StringVar(&opts.RuntimeContext, "runtime-context", "", "Docker context used only to run the isolated frontend")
	flags.StringArrayVar(&opts.FrontendOptions, "opt", nil, "frontend option as key=value (repeatable)")
	flags.StringVar(&opts.ExportName, "output-image", "", "optional image name for the policy-controlled Docker image exporter (moby)")
	flags.StringVar(&reportPath, "operations-file", "", "create a private JSONL operation report (default: stdout)")
	flags.StringVar(&opts.CAFile, "tls-ca", "", "CA certificate for the Sockguard HTTPS endpoint")
	flags.StringVar(&opts.CertFile, "tls-cert", "", "client certificate for Sockguard authentication")
	flags.StringVar(&opts.KeyFile, "tls-key", "", "client certificate private key")
	_ = command.MarkFlagRequired("runtime-context")
	return command
}

func init() { rootCmd.AddCommand(newFrontendCommand()) }
