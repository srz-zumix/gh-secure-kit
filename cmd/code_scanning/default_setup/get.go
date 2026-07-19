package defaultsetup

import (
	"fmt"

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

// NewGetCmd returns the code-scanning default-setup get command.
func NewGetCmd() *cobra.Command {
	var repo string
	opts := &GetOptions{}

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get a code scanning default setup configuration for a repository",
		Long:  "Gets the code scanning default setup configuration for a repository.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}
			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}
			config, err := gh.GetCodeScanningDefaultSetupConfiguration(cmd.Context(), client, repository)
			if err != nil {
				return fmt.Errorf("failed to get code scanning default setup configuration: %w", err)
			}
			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeScanningDefaultSetupConfiguration(config)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
