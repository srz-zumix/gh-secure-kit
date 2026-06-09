package deps

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

type DiffOptions struct {
	Exporter cmdutil.Exporter
}

// NewDiffCmd returns the deps diff command
func NewDiffCmd() *cobra.Command {
	var repo string
	opts := &DiffOptions{}

	cmd := &cobra.Command{
		Use:   "diff <basehead>",
		Short: "Show dependency diff between two commits or branches",
		Long:  "Show dependency changes between two commits, tags, or branches using the GitHub dependency-graph compare API.\nThe basehead argument must be in the format <base>...<head> (e.g. main...feature/branch).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			basehead := args[0]
			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			changes, err := gh.GetRepositoryDependencyGraphDiff(ctx, client, repository, basehead)
			if err != nil {
				return fmt.Errorf("failed to get dependency diff: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderDependencyChanges(changes, nil)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
