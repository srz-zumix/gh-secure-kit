package codeql

import (
	"github.com/spf13/cobra"
	variantanalyses "github.com/srz-zumix/gh-secure-kit/cmd/code_scanning/codeql/variant_analyses"
)

// NewVariantAnalysesCmd returns the code-scanning codeql variant-analyses parent command
func NewVariantAnalysesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "variant-analyses",
		Short: "Manage CodeQL variant analyses",
	}
	cmd.AddCommand(variantanalyses.NewCreateCmd())
	cmd.AddCommand(variantanalyses.NewGetCmd())
	cmd.AddCommand(variantanalyses.NewRepoStatusCmd())
	return cmd
}
