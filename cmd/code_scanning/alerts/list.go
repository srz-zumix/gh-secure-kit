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

// NewListCmd returns the code-scanning alerts list command
func NewListCmd() *cobra.Command {
	var repo string
	var state string
	var severity string
	var toolName string
	var toolGUID string
	var ref string
	var sort string
	var direction string
	opts := &ListOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List code scanning alerts",
		Long:  "List code scanning alerts for a repository. Supports filtering by state, severity, tool, and ref.",
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			alertOpts := &gh.ListCodeScanningAlertsOptions{
				State:     state,
				Severity:  severity,
				ToolName:  toolName,
				ToolGUID:  toolGUID,
				Ref:       ref,
				Sort:      sort,
				Direction: direction,
			}

			ctx := cmd.Context()
			alerts, err := gh.ListCodeScanningAlerts(ctx, client, repository, alertOpts)
			if err != nil {
				return fmt.Errorf("failed to list code scanning alerts: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeScanningAlerts(alerts, nil)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.StringEnumFlag(cmd, &state, "state", "", "", gh.CodeScanningAlertStates, "Filter by state")
	cmdutil.StringEnumFlag(cmd, &severity, "severity", "", "", gh.CodeScanningAlertSeverities, "Filter by severity")
	f.StringVar(&toolName, "tool-name", "", "Filter by tool name")
	f.StringVar(&toolGUID, "tool-guid", "", "Filter by tool GUID")
	f.StringVar(&ref, "ref", "", "Filter by Git ref (branch, tag, or pull request)")
	cmdutil.StringEnumFlag(cmd, &sort, "sort", "", "", gh.CodeScanningAlertSortOptions, "Sort by field")
	cmdutil.StringEnumFlag(cmd, &direction, "direction", "", "", []string{"asc", "desc"}, "Sort direction")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
