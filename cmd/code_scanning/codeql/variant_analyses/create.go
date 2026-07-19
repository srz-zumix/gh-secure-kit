package variantanalyses

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// CreateOptions holds the format exporter for create command output.
type CreateOptions struct {
	Exporter cmdutil.Exporter
}

// NewCreateCmd returns the code-scanning codeql variant-analyses create command
func NewCreateCmd() *cobra.Command {
	var repo string
	var language string
	var queryPackFile string
	var repositories []string
	var repositoryOwners []string
	var repositoryLists []string
	opts := &CreateOptions{}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a CodeQL variant analysis",
		Long: `Creates a new CodeQL variant analysis, which runs a CodeQL query against one or more repositories.

The --repo flag specifies the controller repository that runs the GitHub Actions workflow
and stores the results. Exactly one of --repositories, --repository-owners or --repository-lists
must be specified to select the target repositories.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			queryPackData, err := os.ReadFile(queryPackFile)
			if err != nil {
				return fmt.Errorf("failed to read query pack file %q: %w", queryPackFile, err)
			}
			queryPack := base64.StdEncoding.EncodeToString(queryPackData)

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			createOpts := &gh.CreateCodeQLVariantAnalysisOptions{
				Language:         language,
				QueryPack:        queryPack,
				Repositories:     repositories,
				RepositoryOwners: repositoryOwners,
				RepositoryLists:  repositoryLists,
			}

			ctx := cmd.Context()
			analysis, err := gh.CreateCodeQLVariantAnalysis(ctx, client, repository, createOpts)
			if err != nil {
				return fmt.Errorf("failed to create CodeQL variant analysis: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeQLVariantAnalysis(analysis)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The controller repository in the format 'owner/repo'")
	f.StringVar(&language, "language", "", "The CodeQL query language (required)")
	f.StringVar(&queryPackFile, "query-pack", "", "Path to a zipped CodeQL query pack file to upload (required)")
	f.StringSliceVar(&repositories, "repositories", nil, "Repositories to analyze, in 'owner/repo' format (comma-separated, no default)")
	f.StringSliceVar(&repositoryOwners, "repository-owners", nil, "Organizations or users whose repositories to analyze (comma-separated, no default)")
	f.StringSliceVar(&repositoryLists, "repository-lists", nil, "Names of repository lists to analyze (comma-separated, no default)")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	_ = cmd.MarkFlagRequired("language")
	_ = cmd.MarkFlagRequired("query-pack")
	cmd.MarkFlagsMutuallyExclusive("repositories", "repository-owners", "repository-lists")
	cmd.MarkFlagsOneRequired("repositories", "repository-owners", "repository-lists")
	return cmd
}
