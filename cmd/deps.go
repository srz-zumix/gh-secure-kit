package cmd

import (
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/cmd/deps"
)

func init() {
	rootCmd.AddCommand(NewDepsCmd())
}

// NewDepsCmd returns the deps parent command
func NewDepsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deps",
		Short: "Manage GitHub dependency graph",
	}
	cmd.AddCommand(deps.NewListCmd())
	cmd.AddCommand(deps.NewActionsCmd())
	cmd.AddCommand(deps.NewSubmoduleCmd())
	cmd.AddCommand(deps.NewUnityCmd())
	return cmd
}
