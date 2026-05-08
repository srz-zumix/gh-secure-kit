package secretscanning

import (
	"github.com/spf13/cobra"
	alerts "github.com/srz-zumix/gh-secure-kit/cmd/secret_scanning/alerts"
)

// NewAlertsCmd returns the secret-scanning alerts parent command
func NewAlertsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Manage secret scanning alerts",
	}
	cmd.AddCommand(alerts.NewGetCmd())
	cmd.AddCommand(alerts.NewListCmd())
	cmd.AddCommand(alerts.NewLocationsCmd())
	cmd.AddCommand(alerts.NewUpdateCmd())
	return cmd
}
