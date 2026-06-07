package alerts

import (
	"github.com/spf13/cobra"
)

// NewAutofixCmd returns the code-scanning alerts autofix parent command.
func NewAutofixCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "autofix",
		Short: "Manage autofixes for code scanning alerts",
	}
	cmd.AddCommand(NewAutofixGetCmd())
	cmd.AddCommand(NewAutofixCreateCmd())
	cmd.AddCommand(NewAutofixCommitCmd())
	return cmd
}
