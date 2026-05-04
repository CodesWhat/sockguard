package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func requireExplicitConfigFile(cmd *cobra.Command, configPath string) error {
	if !configFlagChanged(cmd) || configPath == "" {
		return nil
	}

	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("config file: %w", err)
	}
	return nil
}

func configFlagChanged(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}

	flag := cmd.Flag("config")
	return flag != nil && flag.Changed
}
