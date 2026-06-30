package repo

import (
	"github.com/spf13/cobra"
	automatedsecurityfixes "github.com/srz-zumix/gh-secure-kit/cmd/repo/automated_security_fixes"
)

// NewAutomatedSecurityFixesCmd returns the automated-security-fixes parent command.
func NewAutomatedSecurityFixesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "automated-security-fixes",
		Aliases: []string{"asf"},
		Short:   "Manage automated security fixes for a repository",
	}
	cmd.AddCommand(automatedsecurityfixes.NewStatusCmd())
	cmd.AddCommand(automatedsecurityfixes.NewEnableCmd())
	cmd.AddCommand(automatedsecurityfixes.NewDisableCmd())
	return cmd
}
