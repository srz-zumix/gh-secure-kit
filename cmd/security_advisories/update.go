package securityadvisories

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// UpdateOptions holds the format exporter for update command output.
type UpdateOptions struct {
	Exporter cmdutil.Exporter
}

// NewUpdateCmd returns the security-advisories update command.
func NewUpdateCmd() *cobra.Command {
	var repo string
	var state string
	var severity string
	opts := &UpdateOptions{}

	cmd := &cobra.Command{
		Use:   "update <ghsa-id>",
		Short: "Update a repository security advisory",
		Long: `Update a repository security advisory by its GHSA identifier.

Use --state to change the advisory state (published, closed, draft).
Use --severity to change the advisory severity (critical, high, medium, low).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ghsaID := args[0]

			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			ghClient, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			updateOpts := &gh.RepositorySecurityAdvisoryUpdateOptions{}
			if state != "" {
				updateOpts.State = state
			}
			if severity != "" {
				updateOpts.Severity = severity
			}

			ctx := cmd.Context()
			advisory, err := gh.UpdateRepositorySecurityAdvisory(ctx, ghClient, repository, ghsaID, updateOpts)
			if err != nil {
				return fmt.Errorf("failed to update repository security advisory: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderRepositorySecurityAdvisory(advisory)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.StringEnumFlag(cmd, &state, "state", "", "", gh.RepositorySecurityAdvisoryUpdateStates, "The new state of the advisory")
	cmdutil.StringEnumFlag(cmd, &severity, "severity", "", "", gh.RepositorySecurityAdvisorySeverities, "The severity of the advisory")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
