package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func requireExplicitConfigFile(cmd *cobra.Command, configPath string) error {
	flag := cmd.Flag("config")
	if flag == nil && cmd.Root() != nil {
		flag = cmd.Root().Flag("config")
	}
	if flag == nil || !flag.Changed {
		return nil
	}

	if strings.TrimSpace(configPath) == "" {
		return fmt.Errorf("config file path cannot be empty")
	}

	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("config file: %w", err)
	}
	return nil
}
