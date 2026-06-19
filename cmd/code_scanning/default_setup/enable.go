package defaultsetup

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/logger"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewEnableCmd returns the code-scanning default-setup enable command.
func NewEnableCmd() *cobra.Command {
	var owner string
	var querySuite string

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable code scanning default setup for all repositories in the organization",
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
			if err := gh.EnableCodeScanningDefaultSetup(cmd.Context(), client, repository, querySuite); err != nil {
				return fmt.Errorf("failed to enable code scanning default setup: %w", err)
			}
			logger.Info("Enabled code scanning default setup for organization", "owner", repository.Owner)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	f.StringVar(&querySuite, "query-suite", "", "CodeQL query suite {default|extended}")
	_ = cmd.RegisterFlagCompletionFunc("query-suite", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return gh.CodeScanningQuerySuites, cobra.ShellCompDirectiveNoFileComp
	})
	return cmd
}
