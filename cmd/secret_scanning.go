package cmd

import (
	"github.com/spf13/cobra"
	secretscanning "github.com/srz-zumix/gh-secure-kit/cmd/secret_scanning"
)

func init() {
	rootCmd.AddCommand(NewSecretScanningCmd())
}

// NewSecretScanningCmd returns the secret-scanning parent command
func NewSecretScanningCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret-scanning",
		Short: "Manage secret scanning configurations",
		Long:  "Manage secret scanning push protection pattern configurations for organizations.",
	}
	cmd.AddCommand(secretscanning.NewPushProtectionCmd())
	return cmd
}
