package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/ui"
	"github.com/codeswhat/sockguard/internal/version"
)

var versionOutput string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	RunE:  runVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
	versionCmd.Flags().StringVarP(&versionOutput, "output", "o", "text", "output format: text or json")
}

func runVersion(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	switch versionOutput {
	case "text":
		p := ui.New(out)
		fmt.Fprintf(out, "  %s %s\n", p.Bold("sockguard"), p.Dim(version.Version))
		fmt.Fprintf(out, "  %s  %s\n", p.Dim("commit"), shortCommit(version.Commit))
		fmt.Fprintf(out, "  %s  %s\n", p.Dim("built "), version.BuildDate)
		fmt.Fprintf(out, "  %s  %s\n", p.Dim("go    "), runtime.Version())
		return nil
	case "json":
		fmt.Fprintf(out, "{\"version\":%q,\"commit\":%q,\"built\":%q,\"go\":%q}\n",
			version.Version, version.Commit, version.BuildDate, runtime.Version())
		return nil
	default:
		return fmt.Errorf("unknown output format %q (want text or json)", versionOutput)
	}
}

func shortCommit(c string) string {
	const n = 7
	if len(c) > n {
		return c[:n]
	}
	return c
}
