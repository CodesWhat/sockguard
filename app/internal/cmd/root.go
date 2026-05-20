package cmd

import (
	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "sockguard",
	Short: "Docker socket proxy — guide what gets through",
	Long: `Sockguard is a Docker socket proxy that filters API requests
by HTTP method, path, and request body content.

Default-deny posture ensures only explicitly allowed operations
reach the Docker daemon.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return serveCmd.RunE(cmd, args)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "/etc/sockguard/sockguard.yaml", "config file path (missing file falls back to built-in defaults + env overrides)")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
