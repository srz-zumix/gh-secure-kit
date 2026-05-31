package securityadvisories

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

// NewListCmd returns the security-advisories list command.
func NewListCmd() *cobra.Command {
	var owner string
	var repo string
	var state string
	var sort string
	var direction string
	opts := &ListOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List repository security advisories",
		Long: `List repository security advisories for a repository or organization.

Use --repo to list advisories for a specific repository.
Use --owner to list advisories across all repositories in an organization.
--repo and --owner are mutually exclusive.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, err := parser.Repository(parser.RepositoryInput(repo), parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			listOpts := &gh.ListRepositorySecurityAdvisoriesOptions{
				State:     state,
				Sort:      sort,
				Direction: direction,
			}

			ctx := cmd.Context()
			advisories, err := gh.ListRepositorySecurityAdvisories(ctx, client, repository, listOpts)
			if err != nil {
				return fmt.Errorf("failed to list repository security advisories: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderRepositorySecurityAdvisories(advisories)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name (lists advisories for all repositories in the org)")
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.StringEnumFlag(cmd, &state, "state", "", "", gh.RepositorySecurityAdvisoryStates, "Filter by state")
	cmdutil.StringEnumFlag(cmd, &sort, "sort", "", "", gh.RepositorySecurityAdvisorySortOptions, "Sort by field")
	cmdutil.StringEnumFlag(cmd, &direction, "direction", "", "", gh.RepositorySecurityAdvisoryDirections, "Sort direction")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	cmd.MarkFlagsMutuallyExclusive("owner", "repo")
	return cmd
}
