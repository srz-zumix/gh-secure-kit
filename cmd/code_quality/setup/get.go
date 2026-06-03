package setup

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// GetOptions holds the format exporter for get command output.
type GetOptions struct {
	Exporter cmdutil.Exporter
}

// NewGetCmd returns the code-quality setup get command
func NewGetCmd() *cobra.Command {
	var repo string
	opts := &GetOptions{}

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get a code quality setup configuration",
		Long:  "Gets the code quality setup configuration for a repository.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			setup, err := gh.GetCodeQualitySetup(ctx, client, repository)
			if err != nil {
				return fmt.Errorf("failed to get code quality setup: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeQualitySetup(setup)
		},
	}
	cmd.Flags().StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
