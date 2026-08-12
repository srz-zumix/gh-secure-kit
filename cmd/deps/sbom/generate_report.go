package sbom

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

type GenerateReportOptions struct {
	Exporter cmdutil.Exporter
}

// NewGenerateReportCmd returns the deps sbom generate-report command
func NewGenerateReportCmd() *cobra.Command {
	var repo string
	opts := &GenerateReportOptions{}

	cmd := &cobra.Command{
		Use:   "generate-report",
		Short: "Request generation of an SBOM report",
		Long:  "Trigger a job to generate a software bill of materials (SBOM) report for a repository in SPDX JSON format. Use \"deps sbom fetch-report\" to retrieve the result once ready.",
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
			result, err := gh.GenerateRepositoryDependencyGraphSBOMReport(ctx, client, repository)
			if err != nil {
				return fmt.Errorf("failed to request SBOM report generation: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderSBOMReportGeneration(result)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
