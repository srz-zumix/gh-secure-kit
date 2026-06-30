package cmd

import (
	"github.com/spf13/cobra"
	repocmd "github.com/srz-zumix/gh-secure-kit/cmd/repo"
)

func init() {
	rootCmd.AddCommand(NewRepoCmd())
}

// NewRepoCmd returns the repo parent command.
func NewRepoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repo",
		Short: "Manage repository security feature toggles",
	}
	cmd.AddCommand(repocmd.NewAutomatedSecurityFixesCmd())
	cmd.AddCommand(repocmd.NewVulnerabilityAlertsCmd())
	cmd.AddCommand(repocmd.NewPrivateVulnerabilityReportingCmd())
	return cmd
}
