package automatedsecurityfixes

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// StatusOptions holds the format exporter for status command output.
type StatusOptions struct {
	Exporter cmdutil.Exporter
}

// NewStatusCmd returns the automated-security-fixes status command.
func NewStatusCmd() *cobra.Command {
	var owner string
	var repo string
	opts := &StatusOptions{}

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Get the status of automated security fixes for a repository",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			repository, err := parser.Repository(parser.RepositoryInput(repo), parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}
			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}
			status, err := gh.GetAutomatedSecurityFixes(cmd.Context(), client, repository)
			if err != nil {
				return fmt.Errorf("failed to get automated security fixes status: %w", err)
			}
			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderRepositorySecurityFeatureStatus(status)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
