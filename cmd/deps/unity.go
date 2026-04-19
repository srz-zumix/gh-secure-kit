package deps

import (
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/cmd/deps/unity"
)

// NewUnityCmd returns the deps unity parent command
func NewUnityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unity",
		Short: "Manage Unity package dependencies",
	}
	cmd.AddCommand(unity.NewListCmd())
	return cmd
}
