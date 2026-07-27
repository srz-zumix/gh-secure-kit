package sbom

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

type FetchReportOptions struct {
	Exporter cmdutil.Exporter
}

// NewFetchReportCmd returns the deps sbom fetch-report command
func NewFetchReportCmd() *cobra.Command {
	var repo string
	opts := &FetchReportOptions{}

	cmd := &cobra.Command{
		Use:   "fetch-report <sbom-uuid>",
		Short: "Fetch a previously generated SBOM report",
		Long:  "Fetch a software bill of materials (SBOM) report previously requested via \"deps sbom generate-report\". If the report is not ready yet, a pending message is shown; retry later.",
		Args:  cobra.ExactArgs(1),
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
			result, err := gh.FetchRepositoryDependencyGraphSBOMReport(ctx, client, repository, args[0])
			if err != nil {
				return fmt.Errorf("failed to fetch SBOM report: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderSBOMReport(result)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
