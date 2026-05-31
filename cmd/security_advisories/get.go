package securityadvisories

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

// NewGetCmd returns the security-advisories get command.
func NewGetCmd() *cobra.Command {
	var repo string
	opts := &GetOptions{}

	cmd := &cobra.Command{
		Use:   "get <ghsa-id>",
		Short: "Get a repository security advisory",
		Long:  "Get a repository security advisory by its GHSA identifier.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ghsaID := args[0]

			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			advisory, err := gh.GetRepositorySecurityAdvisory(ctx, client, repository, ghsaID)
			if err != nil {
				return fmt.Errorf("failed to get repository security advisory: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderRepositorySecurityAdvisory(advisory)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
