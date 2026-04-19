package actions

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

type ListOptions struct {
	Exporter cmdutil.Exporter
}

// NewListCmd returns the deps actions list command
func NewListCmd() *cobra.Command {
	var repo string
	var nameOnly bool
	var recursive bool
	opts := &ListOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List actions-related dependency packages",
		Long:  "List dependency packages related to GitHub Actions in the repository's SBOM. Use --recursive to traverse referenced action repositories.",
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
			sboms, _, err := gh.GetActionsDependencyGraph(ctx, client, repository, recursive)
			if err != nil {
				return fmt.Errorf("failed to get actions dependencies recursively: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			if nameOnly {
				packages := gh.FlattenSBOMPackages(sboms)
				return renderer.RenderNames(packages)
			} else {
				return renderer.RenderMultipleSBOMPackages(sboms, []string{"Name", "Version"})
			}
		},
	}
	f := cmd.Flags()
	f.BoolVar(&nameOnly, "name-only", false, "Output only package names")
	f.BoolVarP(&recursive, "recursive", "r", false, "Recursively traverse referenced action repositories")
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
