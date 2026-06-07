package codescanning

import (
	"github.com/spf13/cobra"
	alerts "github.com/srz-zumix/gh-secure-kit/cmd/code_scanning/alerts"
)

// NewAlertsCmd returns the code-scanning alerts parent command
func NewAlertsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Manage code scanning alerts",
	}
	cmd.AddCommand(alerts.NewAutofixCmd())
	cmd.AddCommand(alerts.NewGetCmd())
	cmd.AddCommand(alerts.NewListCmd())
	cmd.AddCommand(alerts.NewUpdateCmd())
	return cmd
}
