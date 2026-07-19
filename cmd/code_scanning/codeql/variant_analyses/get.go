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

// GetOptions holds the format exporter for get command output.
type GetOptions struct {
	Exporter cmdutil.Exporter
}

// NewGetCmd returns the code-scanning codeql variant-analyses get command
func NewGetCmd() *cobra.Command {
	var repo string
	opts := &GetOptions{}

	cmd := &cobra.Command{
		Use:   "get <variant-analysis-id>",
		Short: "Get the summary of a CodeQL variant analysis",
		Long:  "Gets the summary of a CodeQL variant analysis for the controller repository.",
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

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			analysis, err := gh.GetCodeQLVariantAnalysis(ctx, client, repository, id)
			if err != nil {
				return fmt.Errorf("failed to get CodeQL variant analysis: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeQLVariantAnalysis(analysis)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The controller repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
