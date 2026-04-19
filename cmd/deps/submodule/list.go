package submodule

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// ListOptions holds options for the submodule list command
type ListOptions struct {
	Exporter cmdutil.Exporter
}

// NewListCmd returns the submodule list command
func NewListCmd() *cobra.Command {
	var repo string
	var recursive bool
	var nameOnly bool
	opts := &ListOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List repository submodules",
		Long:  `List submodules of the specified repository. Use --recursive to include nested submodules.`,
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
			submodules, err := gh.GetRepositorySubmodules(ctx, client, repository, recursive)
			if err != nil {
				return fmt.Errorf("failed to get submodules: %w", err)
			}

			if recursive {
				submodules = gh.FlattenRepositorySubmodules(submodules)
			}

			renderer := render.NewRenderer(opts.Exporter)
			if nameOnly {
				return renderer.RenderNames(submodules)
			} else {
				return renderer.RenderSubmodules(submodules, nil)
			}
		},
	}
	f := cmd.Flags()
	f.BoolVar(&nameOnly, "name-only", false, "Output only submodule names")
	f.BoolVarP(&recursive, "recursive", "r", false, "Recursively list nested submodules")
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
