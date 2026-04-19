package deps

import (
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/cmd/deps/submodule"
)

// NewSubmoduleCmd returns the deps submodule parent command
func NewSubmoduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "submodule",
		Short: "Manage repository submodules",
	}
	cmd.AddCommand(submodule.NewListCmd())
	return cmd
}
