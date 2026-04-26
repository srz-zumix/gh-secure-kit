package codescanning

import (
	"github.com/spf13/cobra"
	codeql "github.com/srz-zumix/gh-secure-kit/cmd/code_scanning/codeql"
)

// NewCodeqlCmd returns the code-scanning codeql parent command
func NewCodeqlCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "codeql",
		Short: "Manage CodeQL databases",
	}
	cmd.AddCommand(codeql.NewListCmd())
	cmd.AddCommand(codeql.NewGetCmd())
	return cmd
}
