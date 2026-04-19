package repositoryaccess

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewSetDefaultLevelCmd returns the dependabot repository-access set-default-level command
func NewSetDefaultLevelCmd() *cobra.Command {
	var owner string
	var level string

	cmd := &cobra.Command{
		Use:   "set-default-level",
		Short: "Set the default repository access level for Dependabot",
		Long:  "Sets the default level of repository access Dependabot will have while performing an update. Available values are 'public' (only public repositories) and 'internal' (public and internal repositories).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, err := parser.Repository(parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			err = gh.SetOrgDependabotDefaultLevel(ctx, client, repository.Owner, level)
			if err != nil {
				return err
			}

			fmt.Printf("Dependabot default repository access level set to %q for org %q.\n", level, repository.Owner)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	cmdutil.StringEnumFlag(cmd, &level, "level", "", "", gh.DependabotDefaultLevels, "The default access level")
	_ = cmd.MarkFlagRequired("level")
	return cmd
}
