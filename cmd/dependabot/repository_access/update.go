package repositoryaccess

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewUpdateCmd returns the dependabot repository-access update command
func NewUpdateCmd() *cobra.Command {
	var owner string
	var addIDs []int64
	var removeIDs []int64

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update Dependabot repository access list",
		Long:  "Updates repositories according to the list of repositories that organization admins have given Dependabot access to when they've updated dependencies. Use --add to add repository IDs and --remove to remove repository IDs.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(addIDs) == 0 && len(removeIDs) == 0 {
				return fmt.Errorf("at least one of --add or --remove must be specified")
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
			err = gh.UpdateOrgDependabotRepositoryAccess(ctx, client, repository.Owner, addIDs, removeIDs)
			if err != nil {
				return fmt.Errorf("failed to update Dependabot repository access: %w", err)
			}

			fmt.Println("Dependabot repository access updated successfully.")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	f.Int64SliceVar(&addIDs, "add", nil, "Repository IDs to add (can be specified multiple times)")
	f.Int64SliceVar(&removeIDs, "remove", nil, "Repository IDs to remove (can be specified multiple times)")
	return cmd
}
