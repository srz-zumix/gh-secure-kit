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
		Long:  "Manage secret scanning alerts, scan history, and push protection pattern configurations for organizations and repositories.",
	}
	cmd.AddCommand(secretscanning.NewAlertsCmd())
	cmd.AddCommand(secretscanning.NewPushProtectionCmd())
	cmd.AddCommand(secretscanning.NewScanHistoryCmd())
	return cmd
}

