package codequality

import (
	"github.com/spf13/cobra"
	setup "github.com/srz-zumix/gh-secure-kit/cmd/code_quality/setup"
)

// NewSetupCmd returns the code-quality setup parent command
func NewSetupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Manage code quality setup configuration",
	}
	cmd.AddCommand(setup.NewGetCmd())
	cmd.AddCommand(setup.NewUpdateCmd())
	return cmd
}
