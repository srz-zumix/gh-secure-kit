package securityupdates

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/logger"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewEnableCmd returns the dependabot security-updates enable command.
func NewEnableCmd() *cobra.Command {
	var owner string

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable Dependabot security updates for all repositories in the organization",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			repository, err := parser.Repository(parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}
			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}
			if err := gh.EnableDependabotSecurityUpdates(cmd.Context(), client, repository); err != nil {
				return fmt.Errorf("failed to enable Dependabot security updates: %w", err)
			}
			logger.Info("Enabled Dependabot security updates for organization", "owner", repository.Owner)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	_ = cmd.MarkFlagRequired("owner")
	return cmd
}
