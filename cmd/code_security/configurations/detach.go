package configurations

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewDetachCmd returns the code-security configurations detach command
func NewDetachCmd() *cobra.Command {
	var owner string
	var repoIDs []int64

	cmd := &cobra.Command{
		Use:   "detach",
		Short: "Detach code security configurations from repositories",
		Long:  "Detach code security configurations from a set of repositories. Repositories retain their settings but are no longer associated with any configuration.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(repoIDs) == 0 {
				return fmt.Errorf("--repo-id is required (at least one)")
			}
			repository, err := parser.Repository(parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			if err := gh.DetachCodeSecurityConfigurations(ctx, client, repository, repoIDs); err != nil {
				return fmt.Errorf("failed to detach code security configurations: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Detached code security configurations from %d repositories in %s\n", len(repoIDs), repository.Owner)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	f.Int64SliceVar(&repoIDs, "repo-id", nil, "Repository IDs to detach (repeatable, up to 250)")
	_ = cmd.MarkFlagRequired("repo-id")
	return cmd
}
