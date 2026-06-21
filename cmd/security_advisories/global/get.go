package globaladvisories

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// GetOptions holds the format exporter for global get command output.
type GetOptions struct {
	Exporter cmdutil.Exporter
}

// NewGetCmd returns the security-advisories global get command.
func NewGetCmd() *cobra.Command {
	opts := &GetOptions{}

	cmd := &cobra.Command{
		Use:   "get <ghsa-id>",
		Short: "Get a global security advisory",
		Long:  "Get a global security advisory from the GitHub Advisory Database by its GHSA identifier.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ghsaID := args[0]

			client, err := gh.NewGitHubClient()
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			advisory, err := gh.GetGlobalSecurityAdvisory(ctx, client, ghsaID)
			if err != nil {
				return fmt.Errorf("failed to get global security advisory: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderGlobalSecurityAdvisory(advisory)
		},
	}
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
