package cmd

import (
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/cmd/recommended"
)

func init() {
	rootCmd.AddCommand(NewRecommendedCmd())
}

// NewRecommendedCmd returns the recommended parent command
func NewRecommendedCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recommended",
		Short: "Check and apply GitHub security best-practice recommendations",
	}
	cmd.AddCommand(recommended.NewCheckCmd())
	cmd.AddCommand(recommended.NewApplyCmd())
	cmd.AddCommand(recommended.NewListCmd())
	cmd.AddCommand(recommended.NewExplainCmd())
	return cmd
}
