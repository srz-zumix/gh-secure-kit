package configurations

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// RepoConfigOptions holds the format exporter for repo-config command output.
type RepoConfigOptions struct {
	Exporter cmdutil.Exporter
}

// NewRepoConfigCmd returns the code-security configurations repo-config command
func NewRepoConfigCmd() *cobra.Command {
	var repo string
	opts := &RepoConfigOptions{}

	cmd := &cobra.Command{
		Use:   "repo-config",
		Short: "Get the code security configuration attached to a repository",
		Long:  "Get the code security configuration that manages a repository's code security settings.",
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
			c, err := gh.GetRepoCodeSecurityConfiguration(ctx, client, repository)
			if err != nil {
				return fmt.Errorf("failed to get repository code security configuration: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderRepositoryCodeSecurityConfiguration(c)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
