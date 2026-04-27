package codescanning

import (
	"github.com/spf13/cobra"
	sarif "github.com/srz-zumix/gh-secure-kit/cmd/code_scanning/sarif"
)

// NewSarifCmd returns the code-scanning sarif parent command
func NewSarifCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sarif",
		Short: "Manage SARIF uploads",
	}
	cmd.AddCommand(sarif.NewGetCmd())
	cmd.AddCommand(sarif.NewUploadCmd())
	return cmd
}
