package dependabot

import (
	"github.com/spf13/cobra"
	alerts "github.com/srz-zumix/gh-secure-kit/cmd/dependabot/alerts"
)

// NewAlertsCmd returns the dependabot alerts parent command
func NewAlertsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Manage Dependabot alerts",
	}
	cmd.AddCommand(alerts.NewGetCmd())
	cmd.AddCommand(alerts.NewListCmd())
	cmd.AddCommand(alerts.NewUpdateCmd())
	return cmd
}
