package cmd

import (
	"github.com/spf13/cobra"
	securityadvisories "github.com/srz-zumix/gh-secure-kit/cmd/security_advisories"
)

func init() {
	rootCmd.AddCommand(NewSecurityAdvisoriesCmd())
}

// NewSecurityAdvisoriesCmd returns the security-advisories parent command.
func NewSecurityAdvisoriesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security-advisories",
		Short: "Manage repository security advisories",
		Long:  "Manage repository security advisories for repositories and organizations.",
	}
	cmd.AddCommand(securityadvisories.NewListCmd())
	cmd.AddCommand(securityadvisories.NewGetCmd())
	cmd.AddCommand(securityadvisories.NewUpdateCmd())
	cmd.AddCommand(securityadvisories.NewRequestCVECmd())
	cmd.AddCommand(securityadvisories.NewCreateForkCmd())
	return cmd
}
