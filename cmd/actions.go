package cmd

import (
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/cmd/actions"
)

func init() {
	rootCmd.AddCommand(NewActionsCmd())
}

// NewActionsCmd returns the actions parent command
func NewActionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "actions",
		Short: "Manage GitHub Actions workflow security",
	}
	cmd.AddCommand(actions.NewLintCmd())
	cmd.AddCommand(actions.NewWorkflowCmd())
	return cmd
}
