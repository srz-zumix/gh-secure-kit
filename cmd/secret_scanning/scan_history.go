package secretscanning

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// ScanHistoryOptions holds the format exporter for scan-history command output.
type ScanHistoryOptions struct {
	Exporter cmdutil.Exporter
}

// NewScanHistoryCmd returns the secret-scanning scan-history command
func NewScanHistoryCmd() *cobra.Command {
	var repo string
	opts := &ScanHistoryOptions{}

	cmd := &cobra.Command{
		Use:   "scan-history",
		Short: "Get secret scanning scan history for a repository",
		Long:  "Get the latest default incremental and backfill secret scanning scan history for a repository.",
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
			history, err := gh.GetSecretScanningScanHistory(ctx, client, repository)
			if err != nil {
				return fmt.Errorf("failed to get secret scanning scan history: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderSecretScanningScanHistory(history)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
