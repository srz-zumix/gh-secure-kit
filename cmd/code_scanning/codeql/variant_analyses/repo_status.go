package variantanalyses

import (
	"fmt"
	"strconv"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// RepoStatusOptions holds the format exporter for repo-status command output.
type RepoStatusOptions struct {
	Exporter cmdutil.Exporter
}

// NewRepoStatusCmd returns the code-scanning codeql variant-analyses repo-status command
func NewRepoStatusCmd() *cobra.Command {
	var repo string
	var targetRepo string
	opts := &RepoStatusOptions{}

	cmd := &cobra.Command{
		Use:   "repo-status <variant-analysis-id>",
		Short: "Get the analysis status of a repository in a CodeQL variant analysis",
		Long:  "Gets the analysis status of a specific repository that was scanned as part of a CodeQL variant analysis.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid variant analysis ID %q: %w", args[0], err)
			}

			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			target, err := parser.Repository(parser.RepositoryInput(targetRepo))
			if err != nil {
				return fmt.Errorf("failed to parse target repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			status, err := gh.GetCodeQLVariantAnalysisRepoStatus(ctx, client, repository, id, target)
			if err != nil {
				return fmt.Errorf("failed to get CodeQL variant analysis repository status: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeQLVariantAnalysisRepoStatus(status)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The controller repository in the format 'owner/repo'")
	f.StringVar(&targetRepo, "target-repo", "", "The scanned repository in the format 'owner/repo' (required)")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	_ = cmd.MarkFlagRequired("target-repo")
	return cmd
}
