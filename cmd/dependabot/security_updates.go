package dependabot

import (
	"github.com/spf13/cobra"
	securityupdates "github.com/srz-zumix/gh-secure-kit/cmd/dependabot/security_updates"
)

// NewSecurityUpdatesCmd returns the dependabot security-updates parent command.
func NewSecurityUpdatesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security-updates",
		Short: "Enable or disable Dependabot security updates for an organization",
	}
	cmd.AddCommand(securityupdates.NewEnableCmd())
	cmd.AddCommand(securityupdates.NewDisableCmd())
	return cmd
}
