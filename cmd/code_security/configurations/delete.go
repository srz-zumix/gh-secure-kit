package configurations

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewDeleteCmd returns the code-security configurations delete command
func NewDeleteCmd() *cobra.Command {
	var owner string

	cmd := &cobra.Command{
		Use:   "delete <configuration-id>",
		Short: "Delete a code security configuration",
		Long:  "Delete a code security configuration in an organization. Repositories attached to the configuration retain their settings but are no longer associated with it.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid configuration id %q: %w", args[0], err)
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
			if err := gh.DeleteCodeSecurityConfiguration(ctx, client, repository, id); err != nil {
				return fmt.Errorf("failed to delete code security configuration: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted code security configuration #%d in %s\n", id, repository.Owner)
			return nil
		},
	}
	cmd.Flags().StringVarP(&owner, "owner", "o", "", "The organization name")
	return cmd
}
