package securityadvisories

import (
	"github.com/spf13/cobra"
	globaladvisories "github.com/srz-zumix/gh-secure-kit/cmd/security_advisories/global"
)

// NewGlobalCmd returns the security-advisories global parent command.
func NewGlobalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "global",
		Short: "Manage global security advisories",
		Long:  "Manage global security advisories from the GitHub Advisory Database.",
	}
	cmd.AddCommand(globaladvisories.NewListCmd())
	cmd.AddCommand(globaladvisories.NewGetCmd())
	return cmd
}
