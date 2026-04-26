package analyses

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// ListOptions holds the format exporter for list command output.
type ListOptions struct {
	Exporter cmdutil.Exporter
}

// NewListCmd returns the code-scanning analyses list command
func NewListCmd() *cobra.Command {
	var repo string
	var sarifID string
	var ref string
	opts := &ListOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List code scanning analyses",
		Long:  "Lists the details of all code scanning analyses for a repository, starting with the most recent.",
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			listOpts := &gh.ListCodeScanningAnalysesOptions{
				SARIFID: sarifID,
				Ref:     ref,
			}

			ctx := cmd.Context()
			analyses, err := gh.ListCodeScanningAnalyses(ctx, client, repository, listOpts)
			if err != nil {
				return fmt.Errorf("failed to list code scanning analyses: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeScanningAnalyses(analyses)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	f.StringVar(&sarifID, "sarif-id", "", "Filter analyses belonging to the same SARIF upload")
	f.StringVar(&ref, "ref", "", "Filter by Git ref (branch or tag)")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
