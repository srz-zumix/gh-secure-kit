package securityadvisories

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewCreateForkCmd returns the security-advisories create-fork command.
func NewCreateForkCmd() *cobra.Command {
	var repo string

	cmd := &cobra.Command{
		Use:   "create-fork <ghsa-id>",
		Short: "Create a temporary private fork for a repository security advisory",
		Long:  "Create a temporary private fork of the repository to collaborate on fixing a security vulnerability.",
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
			fork, err := gh.CreateRepositorySecurityAdvisoryFork(ctx, client, repository, ghsaID)
			if err != nil {
				return fmt.Errorf("failed to create temporary private fork: %w", err)
			}

			if fork != nil && fork.HTMLURL != nil {
				fmt.Printf("Temporary private fork created: %s\n", *fork.HTMLURL)
			} else {
				fmt.Printf("Temporary private fork created for advisory %s\n", ghsaID)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	return cmd
}
