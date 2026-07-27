package deps

import (
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/cmd/deps/sbom"
)

// NewSBOMCmd returns the deps sbom parent command
func NewSBOMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Manage SBOM reports",
	}
	cmd.AddCommand(sbom.NewGenerateReportCmd())
	cmd.AddCommand(sbom.NewFetchReportCmd())
	return cmd
}
