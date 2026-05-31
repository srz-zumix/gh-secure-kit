package securityadvisories

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewRequestCVECmd returns the security-advisories request-cve command.
func NewRequestCVECmd() *cobra.Command {
	var repo string

	cmd := &cobra.Command{
		Use:   "request-cve <ghsa-id>",
		Short: "Request a CVE for a repository security advisory",
		Long:  "Request a CVE (Common Vulnerabilities and Exposures) identifier for a repository security advisory.",
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
			if err := gh.RequestRepositorySecurityAdvisoryCVE(ctx, client, repository, ghsaID); err != nil {
				return fmt.Errorf("failed to request CVE for repository security advisory: %w", err)
			}

			fmt.Printf("CVE requested for advisory %s\n", ghsaID)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	return cmd
}
