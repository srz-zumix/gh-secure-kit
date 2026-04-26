package codescanning

import (
	"github.com/spf13/cobra"
	analyses "github.com/srz-zumix/gh-secure-kit/cmd/code_scanning/analyses"
)

// NewAnalysesCmd returns the code-scanning analyses parent command
func NewAnalysesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyses",
		Short: "Manage code scanning analyses",
	}
	cmd.AddCommand(analyses.NewListCmd())
	cmd.AddCommand(analyses.NewGetCmd())
	return cmd
}
