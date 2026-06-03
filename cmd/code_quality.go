package cmd

import (
	"github.com/spf13/cobra"
	codequality "github.com/srz-zumix/gh-secure-kit/cmd/code_quality"
)

func init() {
	rootCmd.AddCommand(NewCodeQualityCmd())
}

// NewCodeQualityCmd returns the code-quality parent command
func NewCodeQualityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "code-quality",
		Short: "Manage code quality setup configuration",
		Long:  "Manage code quality setup configuration for a repository.",
	}
	cmd.AddCommand(codequality.NewSetupCmd())
	return cmd
}
