package pushprotection

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// ListOptions holds the format exporter for list command output.
type ListOptions struct {
	Exporter cmdutil.Exporter
}

// NewListCmd returns the secret-scanning push-protection list command
func NewListCmd() *cobra.Command {
	var owner string
	opts := &ListOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secret scanning push protection pattern configurations",
		Long:  "List secret scanning push protection pattern configurations for an organization, including provider and custom pattern overrides.",
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, err := parser.Repository(parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			configs, err := gh.ListSecretScanningPatternConfigs(ctx, client, repository)
			if err != nil {
				return fmt.Errorf("failed to list secret scanning pattern configurations: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderSecretScanningPatternConfigs(configs)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
