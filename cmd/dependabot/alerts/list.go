package alerts

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

// NewListCmd returns the dependabot alerts list command
func NewListCmd() *cobra.Command {
	var repo string
	var state string
	var severity string
	var ecosystem string
	var scope string
	var sort string
	var direction string
	opts := &ListOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Dependabot alerts",
		Long:  "List Dependabot alerts for a repository. Supports filtering by state, severity, ecosystem, and scope.",
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			alertOpts := &gh.ListDependabotAlertsOptions{
				State:     state,
				Severity:  severity,
				Ecosystem: ecosystem,
				Scope:     scope,
				Sort:      sort,
				Direction: direction,
			}

			ctx := cmd.Context()
			alerts, err := gh.ListDependabotAlerts(ctx, client, repository, alertOpts)
			if err != nil {
				return fmt.Errorf("failed to list Dependabot alerts: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderDependabotAlerts(alerts, nil)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.StringEnumFlag(cmd, &state, "state", "", "", gh.DependabotAlertStates, "Filter by state")
	cmdutil.StringEnumFlag(cmd, &severity, "severity", "", "", gh.DependabotAlertSeverities, "Filter by severity")
	cmdutil.StringEnumFlag(cmd, &ecosystem, "ecosystem", "", "", gh.DependabotAlertEcosystems, "Filter by ecosystem")
	cmdutil.StringEnumFlag(cmd, &scope, "scope", "", "", gh.DependabotAlertScopes, "Filter by scope")
	cmdutil.StringEnumFlag(cmd, &sort, "sort", "", "", gh.DependabotAlertSortOptions, "Sort by field")
	cmdutil.StringEnumFlag(cmd, &direction, "direction", "", "", []string{"asc", "desc"}, "Sort direction")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
