package cmd

import (
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/cmd/dependabot"
)

func init() {
	rootCmd.AddCommand(NewDependabotCmd())
}

// NewDependabotCmd returns the dependabot parent command
func NewDependabotCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dependabot",
		Short: "Manage Dependabot alerts and repository access",
	}
	cmd.AddCommand(dependabot.NewAlertsCmd())
	cmd.AddCommand(dependabot.NewRepositoryAccessCmd())
	return cmd
}
