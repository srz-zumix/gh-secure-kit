package cmd

import (
	"github.com/spf13/cobra"
	advancedsecurity "github.com/srz-zumix/gh-secure-kit/cmd/advanced_security"
)

func init() {
	rootCmd.AddCommand(NewAdvancedSecurityCmd())
}

// NewAdvancedSecurityCmd returns the advanced-security parent command.
func NewAdvancedSecurityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "advanced-security",
		Short: "Enable or disable GitHub Advanced Security for an organization",
	}
	cmd.AddCommand(advancedsecurity.NewEnableCmd())
	cmd.AddCommand(advancedsecurity.NewDisableCmd())
	return cmd
}
