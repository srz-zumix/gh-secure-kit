package secretscanning

import (
	"github.com/spf13/cobra"
	localscancmd "github.com/srz-zumix/gh-secure-kit/cmd/secret_scanning/local"
)

// NewLocalCmd returns the secret-scanning local parent command
func NewLocalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "local",
		Short: "Scan local git content for secrets, similar to push protection",
		Long:  "Scan local, not-yet-pushed git content for secrets using built-in and user-defined patterns, without requiring GitHub push protection to run.",
	}
	cmd.AddCommand(localscancmd.NewCheckCmd())
	cmd.AddCommand(localscancmd.NewPatternsCmd())
	return cmd
}
