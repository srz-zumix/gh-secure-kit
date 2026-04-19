package deps

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

// NewListCmd returns the deps list command
func NewListCmd() *cobra.Command {
	var repo string
	var includeEcosystems []string
	var excludeEcosystems []string
	var nameOnly bool
	opts := &ListOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List dependency packages",
		Long:  "List dependency packages in the repository's SBOM.",
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
			sbom, err := gh.GetRepositoryDependencyGraphSBOM(ctx, client, repository)
			if err != nil {
				return fmt.Errorf("failed to get SBOM: %w", err)
			}

			if len(includeEcosystems) > 0 {
				sbom = gh.FilterSBOMPackages(sbom, includeEcosystems)
			}

			if len(excludeEcosystems) > 0 {
				sbom = gh.ExcludeSBOMPackages(sbom, excludeEcosystems)
			}

			renderer := render.NewRenderer(opts.Exporter)
			if nameOnly {
				return renderer.RenderNames(sbom.SBOM.Packages)
			} else {
				if len(includeEcosystems) > 0 {
					return renderer.RenderSBOMPackages(sbom, []string{"Name", "Version"})
				} else {
					return renderer.RenderSBOMPackages(sbom, nil)
				}
			}
		},
	}
	f := cmd.Flags()
	f.BoolVar(&nameOnly, "name-only", false, "Output only package names")
	f.StringArrayVarP(&includeEcosystems, "include", "i", nil, "Filter by ecosystem (can be specified multiple times)")
	f.StringArrayVarP(&excludeEcosystems, "exclude", "e", nil, "Exclude packages by ecosystem (can be specified multiple times)")
	_ = cmd.RegisterFlagCompletionFunc("include", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return gh.SBOMEcosystems, cobra.ShellCompDirectiveNoFileComp
	})
	_ = cmd.RegisterFlagCompletionFunc("exclude", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return gh.SBOMEcosystems, cobra.ShellCompDirectiveNoFileComp
	})
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
