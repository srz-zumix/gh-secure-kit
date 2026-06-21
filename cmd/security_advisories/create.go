package securityadvisories

import (
	"fmt"
	"strings"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// CreateOptions holds the format exporter for create command output.
type CreateOptions struct {
	Exporter cmdutil.Exporter
}

// NewCreateCmd returns the security-advisories create command.
func NewCreateCmd() *cobra.Command {
	var repo string
	var summary string
	var description string
	var cveID string
	var severity string
	var cvssVector string
	var ecosystem string
	var packageName string
	var vulnVersionRange string
	var patchedVersions string
	var cweIDs string
	var startPrivateFork bool
	opts := &CreateOptions{}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a repository security advisory",
		Long: `Create a new repository security advisory.

Requires --summary, --description, and --ecosystem (for the vulnerability package ecosystem).
Use --severity to set the severity level (critical, high, medium, low).
Use --cve-id to associate a CVE identifier.
Use --package-name to specify the affected package name.
Use --vulnerable-version-range to specify the vulnerable version range.
Use --patched-versions to specify the patched version.
Use --cwe-ids to specify comma-separated CWE identifiers (e.g. CWE-79,CWE-284).
Use --start-private-fork to create a temporary private fork.`,
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

			createOpts := &gh.CreateRepositorySecurityAdvisoryOptions{
				Summary:                summary,
				Description:            description,
				Ecosystem:              ecosystem,
				PackageName:            packageName,
				VulnerableVersionRange: vulnVersionRange,
				PatchedVersions:        patchedVersions,
				StartPrivateFork:       startPrivateFork,
			}
			if cveID != "" {
				createOpts.CVEID = cveID
			}
			if severity != "" {
				createOpts.Severity = severity
			}
			if cvssVector != "" {
				createOpts.CVSSVectorString = cvssVector
			}
			if cweIDs != "" {
				createOpts.CWEIDs = splitComma(cweIDs)
			}

			ctx := cmd.Context()
			advisory, err := gh.CreateRepositorySecurityAdvisory(ctx, client, repository, createOpts)
			if err != nil {
				return fmt.Errorf("failed to create repository security advisory: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderRepositorySecurityAdvisory(advisory)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	f.StringVar(&summary, "summary", "", "A short description of the advisory (required)")
	f.StringVar(&description, "description", "", "A detailed description of the advisory (required)")
	f.StringVar(&cveID, "cve-id", "", "The CVE identifier to associate with the advisory")
	cmdutil.StringEnumFlag(cmd, &severity, "severity", "", "", gh.RepositorySecurityAdvisorySeverities, "The severity of the advisory")
	f.StringVar(&cvssVector, "cvss-vector-string", "", "The CVSS vector string for the advisory")
	cmdutil.StringEnumFlag(cmd, &ecosystem, "ecosystem", "", "", gh.GlobalSecurityAdvisoryEcosystems, "The package ecosystem of the vulnerability (required)")
	f.StringVar(&packageName, "package-name", "", "The name of the affected package")
	f.StringVar(&vulnVersionRange, "vulnerable-version-range", "", "The version range of the vulnerable package")
	f.StringVar(&patchedVersions, "patched-versions", "", "The version(s) that fix the vulnerability")
	f.StringVar(&cweIDs, "cwe-ids", "", "Comma-separated list of CWE identifiers (e.g. CWE-79,CWE-284)")
	f.BoolVar(&startPrivateFork, "start-private-fork", false, "Create a temporary private fork to collaborate on a fix")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}

// splitComma splits a comma-separated string into a slice of trimmed non-empty strings.
func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
