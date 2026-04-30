package codesecurity

import (
	"github.com/spf13/cobra"
	configurations "github.com/srz-zumix/gh-secure-kit/cmd/code_security/configurations"
)

// NewConfigurationsCmd returns the code-security configurations parent command
func NewConfigurationsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configurations",
		Short: "Manage code security configurations",
	}
	cmd.AddCommand(configurations.NewListCmd())
	cmd.AddCommand(configurations.NewGetCmd())
	cmd.AddCommand(configurations.NewCreateCmd())
	cmd.AddCommand(configurations.NewUpdateCmd())
	cmd.AddCommand(configurations.NewDeleteCmd())
	cmd.AddCommand(configurations.NewAttachCmd())
	cmd.AddCommand(configurations.NewDetachCmd())
	cmd.AddCommand(configurations.NewDefaultsCmd())
	cmd.AddCommand(configurations.NewSetDefaultCmd())
	cmd.AddCommand(configurations.NewRepositoriesCmd())
	cmd.AddCommand(configurations.NewRepoConfigCmd())
	return cmd
}
