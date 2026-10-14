package auditlog

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/internal/auditlog"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// CredentialsOptions holds the format exporter for command output.
type CredentialsOptions struct {
	Exporter cmdutil.Exporter
}

// NewCredentialsCmd returns the audit-log credentials command.
func NewCredentialsCmd() *cobra.Command {
	var owner string
	var categories []string
	var since string
	var until string
	opts := &CredentialsOptions{}

	cmd := &cobra.Command{
		Use:   "credentials",
		Args:  cobra.NoArgs,
		Short: "Detect credential-related operations in the organization audit log",
		Long: `Detect operations on credentials in the organization audit log:
SSH keys and deploy keys, personal access tokens, SSO credential authorizations,
OAuth apps, and GitHub Apps.

Use --category to limit the detected categories (default: all).
Use --since and --until to limit the period. Both accept RFC3339 timestamps,
dates (2006-01-02), or relative periods such as 7d, 2w, 24h (default: no limit).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, err := parser.Repository(parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			sinceTime, untilTime, err := auditlog.ParseTimeRange(since, until)
			if err != nil {
				return fmt.Errorf("failed to parse time range: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			detections, err := auditlog.Detect(cmd.Context(), client, repository, auditlog.Options{
				Categories: auditlog.NormalizeCategories(categories),
				Since:      sinceTime,
				Until:      untilTime,
			})
			if err != nil {
				return fmt.Errorf("failed to detect credential-related audit log entries: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return auditlog.RenderDetections(renderer, detections)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	cmdutil.StringSliceEnumFlag(cmd, &categories, "category", "c", nil, auditlog.Categories, "Categories to detect (default: all)")
	f.StringVar(&since, "since", "", "Only include entries at or after this time (RFC3339, YYYY-MM-DD, or period like 7d)")
	f.StringVar(&until, "until", "", "Only include entries at or before this time (RFC3339, YYYY-MM-DD, or period like 7d)")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
