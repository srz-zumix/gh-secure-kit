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

// NewListCmd returns the secret-scanning alerts list command
func NewListCmd() *cobra.Command {
	var owner string
	var repo string
	var state string
	var secretType string
	var resolution string
	var validity string
	var sort string
	var direction string
	opts := &ListOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secret scanning alerts",
		Long: `List secret scanning alerts for a repository or organization.

Use --repo to list alerts for a specific repository.
Use --owner to list alerts across all repositories in an organization.
--repo and --owner are mutually exclusive.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// RepositoryInput(repo) takes priority; RepositoryOwner(owner) is applied only when repo is empty.
			repository, err := parser.Repository(parser.RepositoryInput(repo), parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			alertOpts := &gh.ListSecretScanningAlertsOptions{
				State:      state,
				SecretType: secretType,
				Resolution: resolution,
				Validity:   validity,
				Sort:       sort,
				Direction:  direction,
			}

			ctx := cmd.Context()
			alerts, err := gh.ListSecretScanningAlerts(ctx, client, repository, alertOpts)
			if err != nil {
				return fmt.Errorf("failed to list secret scanning alerts: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderSecretScanningAlerts(alerts)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name (lists alerts for all repositories in the org)")
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.StringEnumFlag(cmd, &state, "state", "", "", gh.SecretScanningAlertStates, "Filter by state")
	f.StringVar(&secretType, "secret-type", "", "Filter by secret type (comma-separated)")
	cmdutil.StringEnumFlag(cmd, &resolution, "resolution", "", "", gh.SecretScanningAlertResolutions, "Filter by resolution")
	cmdutil.StringEnumFlag(cmd, &validity, "validity", "", "", gh.SecretScanningAlertValidities, "Filter by validity")
	cmdutil.StringEnumFlag(cmd, &sort, "sort", "", "", gh.SecretScanningAlertSortOptions, "Sort by field")
	cmdutil.StringEnumFlag(cmd, &direction, "direction", "", "", []string{"asc", "desc"}, "Sort direction")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	cmd.MarkFlagsMutuallyExclusive("owner", "repo")
	return cmd
}
