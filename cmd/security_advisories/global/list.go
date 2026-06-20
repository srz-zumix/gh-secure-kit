package globaladvisories

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// ListOptions holds the format exporter for global list command output.
type ListOptions struct {
	Exporter cmdutil.Exporter
}

// NewListCmd returns the security-advisories global list command.
func NewListCmd() *cobra.Command {
	var advisoryType string
	var severity string
	var ecosystem string
	var ghsaID string
	var cveID string
	opts := &ListOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List global security advisories",
		Long: `List global security advisories from the GitHub Advisory Database.

Use --type to filter by advisory type (reviewed, malware, unreviewed).
Use --severity to filter by severity (unknown, low, medium, high, critical).
Use --ecosystem to filter by package ecosystem.
Use --ghsa-id to filter by GHSA identifier.
Use --cve-id to filter by CVE identifier.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := gh.NewGitHubClient()
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			listOpts := &gh.ListGlobalSecurityAdvisoriesOptions{
				Type:      advisoryType,
				Severity:  severity,
				Ecosystem: ecosystem,
				GHSAID:    ghsaID,
				CVEID:     cveID,
			}

			ctx := cmd.Context()
			advisories, err := gh.ListGlobalSecurityAdvisories(ctx, client, listOpts)
			if err != nil {
				return fmt.Errorf("failed to list global security advisories: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderGlobalSecurityAdvisories(advisories)
		},
	}
	f := cmd.Flags()
	cmdutil.StringEnumFlag(cmd, &advisoryType, "type", "", "", gh.GlobalSecurityAdvisoryTypes, "Filter by advisory type")
	cmdutil.StringEnumFlag(cmd, &severity, "severity", "", "", gh.RepositorySecurityAdvisorySeverities, "Filter by severity")
	cmdutil.StringEnumFlag(cmd, &ecosystem, "ecosystem", "", "", gh.GlobalSecurityAdvisoryEcosystems, "Filter by package ecosystem")
	f.StringVar(&ghsaID, "ghsa-id", "", "Filter by GHSA identifier")
	f.StringVar(&cveID, "cve-id", "", "Filter by CVE identifier")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
