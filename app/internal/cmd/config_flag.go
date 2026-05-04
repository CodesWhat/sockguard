package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func requireExplicitConfigFile(cmd *cobra.Command, configPath string) error {
	flag := cmd.Flag("config")
	if flag == nil || !flag.Changed || configPath == "" {
		return nil
	}

	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("config file: %w", err)
	}
	return nil
}
