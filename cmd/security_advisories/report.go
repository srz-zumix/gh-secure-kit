package securityadvisories

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// ReportOptions holds the format exporter for report command output.
type ReportOptions struct {
	Exporter cmdutil.Exporter
}

// NewReportCmd returns the security-advisories report command.
func NewReportCmd() *cobra.Command {
	var repo string
	var ecosystem string
	var packageName string
	var summary string
	var description string
	var severity string
	var cvssVector string
	var cweIDs string
	var startPrivateFork bool
	opts := &ReportOptions{}

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Report a vulnerability in a repository",
		Long: `Report a vulnerability in an open source repository to the maintainers privately.

Requires --summary, --description, and --ecosystem.
Use --package-name to specify the affected package name.
Use --severity to set the severity level (critical, high, medium, low).
Use --cvss-vector-string to provide the CVSS vector string.
Use --cwe-ids to specify comma-separated CWE identifiers (e.g. CWE-79,CWE-284).
Use --start-private-fork to request creation of a temporary private fork.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if summary == "" {
				return fmt.Errorf("--summary is required")
			}
			if description == "" {
				return fmt.Errorf("--description is required")
			}
			if ecosystem == "" {
				return fmt.Errorf("--ecosystem is required")
			}

			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			reportOpts := &gh.ReportRepositorySecurityAdvisoryOptions{
				Ecosystem:        ecosystem,
				PackageName:      packageName,
				Summary:          summary,
				Description:      description,
				StartPrivateFork: startPrivateFork,
			}
			if severity != "" {
				reportOpts.Severity = severity
			}
			if cvssVector != "" {
				reportOpts.CVSSVectorString = cvssVector
			}
			if cweIDs != "" {
				reportOpts.CWEIDs = splitComma(cweIDs)
			}

			ctx := cmd.Context()
			advisory, err := gh.ReportRepositorySecurityAdvisory(ctx, client, repository, reportOpts)
			if err != nil {
				return fmt.Errorf("failed to report repository security advisory: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderRepositorySecurityAdvisory(advisory)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.StringEnumFlag(cmd, &ecosystem, "ecosystem", "", "", gh.GlobalSecurityAdvisoryEcosystems, "The package ecosystem of the vulnerability (required)")
	f.StringVar(&packageName, "package-name", "", "The name of the affected package")
	f.StringVar(&summary, "summary", "", "A short description of the vulnerability, max 180 characters (required)")
	f.StringVar(&description, "description", "", "A detailed description of the vulnerability, max 10000 characters (required)")
	cmdutil.StringEnumFlag(cmd, &severity, "severity", "", "", gh.RepositorySecurityAdvisorySeverities, "The severity of the vulnerability")
	f.StringVar(&cvssVector, "cvss-vector-string", "", "The CVSS vector string for the vulnerability")
	f.StringVar(&cweIDs, "cwe-ids", "", "Comma-separated list of CWE identifiers (e.g. CWE-79,CWE-284)")
	f.BoolVar(&startPrivateFork, "start-private-fork", false, "Request creation of a temporary private fork")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
