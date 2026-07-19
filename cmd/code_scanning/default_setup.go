package codescanning

import (
	"github.com/spf13/cobra"
	defaultsetup "github.com/srz-zumix/gh-secure-kit/cmd/code_scanning/default_setup"
)

// NewDefaultSetupCmd returns the code-scanning default-setup parent command.
func NewDefaultSetupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "default-setup",
		Short: "Enable or disable code scanning default setup for an organization",
	}
	cmd.AddCommand(defaultsetup.NewEnableCmd())
	cmd.AddCommand(defaultsetup.NewDisableCmd())
	cmd.AddCommand(defaultsetup.NewGetCmd())
	cmd.AddCommand(defaultsetup.NewUpdateCmd())
	return cmd
}
