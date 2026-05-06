package secretscanning

import (
	"github.com/spf13/cobra"
	pushprotection "github.com/srz-zumix/gh-secure-kit/cmd/secret_scanning/push_protection"
)

// NewPushProtectionCmd returns the secret-scanning push-protection parent command
func NewPushProtectionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push-protection",
		Short: "Manage secret scanning push protection pattern configurations",
	}
	cmd.AddCommand(pushprotection.NewListCmd())
	cmd.AddCommand(pushprotection.NewUpdateCmd())
	return cmd
}
