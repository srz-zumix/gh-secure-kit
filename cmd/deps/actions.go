package deps

import (
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/cmd/deps/actions"
)

// NewActionsCmd returns the deps actions parent command
func NewActionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "actions",
		Short: "Manage GitHub Actions-related dependencies",
	}
	cmd.AddCommand(actions.NewListCmd())
	cmd.AddCommand(actions.NewGraphCmd())
	return cmd
}
