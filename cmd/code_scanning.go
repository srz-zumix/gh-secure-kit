package cmd

import (
	"github.com/spf13/cobra"
	codescanning "github.com/srz-zumix/gh-secure-kit/cmd/code_scanning"
)

func init() {
	rootCmd.AddCommand(NewCodeScanningCmd())
}

// NewCodeScanningCmd returns the code-scanning parent command
func NewCodeScanningCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "code-scanning",
		Short: "Manage code scanning alerts",
	}
	cmd.AddCommand(codescanning.NewAlertsCmd())
	return cmd
}
