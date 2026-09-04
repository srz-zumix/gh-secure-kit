package recommended

import (
	"context"
	"fmt"
	"time"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

func init() {
	registerRepositorySecurityRules()
	registerRepositoryAccessRules()
	registerRepositoryMetadataRules()
}

func registerRepositorySecurityRules() {
	register(Rule{
		ID: "GSK101", GHQRID: "repo-sec-001", Scope: ScopeRepository,
		Category: "security", Severity: SeverityHigh, Title: "Dependabot alerts not enabled", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.VulnerabilityAlerts == nil {
				return Skip("could not read Dependabot alerts status")
			}
			if f.VulnerabilityAlerts.Enabled {
				return Pass("Dependabot alerts are enabled")
			}
			return Fail("Dependabot alerts are disabled")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			return gh.EnableVulnerabilityAlerts(ctx, g, repo)
		},
	})

	register(Rule{
		ID: "GSK102", GHQRID: "repo-sec-006", Scope: ScopeRepository,
		Category: "security", Severity: SeverityMedium, Title: "Dependabot enabled but no dependabot.yml found",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.VulnerabilityAlerts == nil {
				return Skip("could not read Dependabot alerts status")
			}
			if !f.VulnerabilityAlerts.Enabled {
				return Skip("Dependabot alerts are disabled; dependabot.yml check not applicable")
			}
			if f.HasDependabotYML == nil {
				return Skip("could not determine whether a dependabot.yml file exists")
			}
			if !*f.HasDependabotYML {
				return Fail("no .github/dependabot.yml found; automated version update PRs are not configured")
			}
			return Pass(".github/dependabot.yml found")
		},
	})

	register(Rule{
		ID: "GSK103", GHQRID: "repo-sec-004", Scope: ScopeRepository,
		Category: "security", Severity: SeverityLow, Title: "No SECURITY.md file found", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.HasSecurityMD == nil {
				return Skip("could not determine whether a SECURITY.md file exists")
			}
			if *f.HasSecurityMD {
				return Pass("SECURITY.md found")
			}
			return Fail("no SECURITY.md found")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			return applyFileViaPullRequest(ctx, g, repo, f,
				"gh-secure-kit/add-security-md", "SECURITY.md",
				"docs: add SECURITY.md",
				"docs: add SECURITY.md",
				"Adds a starter SECURITY.md so researchers know how to report vulnerabilities. Recommended by `gh secure-kit recommended` (GSK103).",
				[]byte(defaultSecurityMD))
		},
	})

	register(Rule{
		ID: "GSK105", GHQRID: "repo-sec-008", Scope: ScopeRepository,
		Category: "security", Severity: SeverityHigh, Title: "Code scanning (CodeQL) not configured", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.CodeScanningSetup == nil {
				return Skip("could not read code scanning default setup status")
			}
			if f.CodeScanningSetup.GetState() == "configured" {
				return Pass("code scanning default setup is configured")
			}
			return Fail("code scanning default setup is not configured")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			return gh.EnableCodeScanningDefaultSetup(ctx, g, repo, "default")
		},
	})

	register(Rule{
		ID: "GSK106", GHQRID: "org-def-004", Scope: ScopeRepository,
		Category: "security", Severity: SeverityHigh, Title: "Secret scanning not enabled", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			status := f.Repo.GetSecurityAndAnalysis().GetSecretScanning().GetStatus()
			if status == "" {
				return Skip("secret scanning requires GitHub Advanced Security or a public repository")
			}
			if status == "enabled" {
				return Pass("secret scanning is enabled")
			}
			return Fail("secret scanning is disabled")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			return gh.EnableSecretScanning(ctx, g, repo)
		},
	})

	register(Rule{
		ID: "GSK107", GHQRID: "org-def-005", Scope: ScopeRepository,
		Category: "security", Severity: SeverityHigh, Title: "Secret scanning push protection not enabled", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			status := f.Repo.GetSecurityAndAnalysis().GetSecretScanningPushProtection().GetStatus()
			if status == "" {
				return Skip("secret scanning push protection requires GitHub Advanced Security or a public repository")
			}
			if status == "enabled" {
				return Pass("secret scanning push protection is enabled")
			}
			return Fail("secret scanning push protection is disabled")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			return gh.EnableSecretScanningPushProtection(ctx, g, repo)
		},
	})

	register(Rule{
		ID: "GSK108", GHQRID: "org-def-007", Scope: ScopeRepository,
		Category: "security", Severity: SeverityMedium, Title: "Private vulnerability reporting not enabled", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.PrivateVulnerabilityReporting == nil {
				return Skip("could not read private vulnerability reporting status")
			}
			if f.PrivateVulnerabilityReporting.Enabled {
				return Pass("private vulnerability reporting is enabled")
			}
			return Fail("private vulnerability reporting is disabled")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			return gh.EnablePrivateVulnerabilityReporting(ctx, g, repo)
		},
	})

	register(Rule{
		ID: "GSK109", GHQRID: "org-def-002", Scope: ScopeRepository,
		Category: "security", Severity: SeverityMedium, Title: "Dependabot security updates not enabled", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.AutomatedSecurityFixes == nil {
				return Skip("could not read Dependabot security updates status")
			}
			if f.AutomatedSecurityFixes.Enabled {
				return Pass("Dependabot security updates are enabled")
			}
			return Fail("Dependabot security updates are disabled")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			return gh.EnableAutomatedSecurityFixes(ctx, g, repo)
		},
	})
}

func registerRepositoryAccessRules() {
	register(Rule{
		ID: "GSK104", GHQRID: "repo-sec-005", Scope: ScopeRepository,
		Category: "access_control", Severity: SeverityMedium, Title: "No CODEOWNERS file found", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.HasCodeowners == nil {
				return Skip("could not determine whether a CODEOWNERS file exists")
			}
			if *f.HasCodeowners {
				return Pass("CODEOWNERS found")
			}
			return Fail("no CODEOWNERS found")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			return applyFileViaPullRequest(ctx, g, repo, f,
				"gh-secure-kit/add-codeowners", ".github/CODEOWNERS",
				"docs: add CODEOWNERS",
				"docs: add CODEOWNERS",
				"Adds a starter CODEOWNERS file. Recommended by `gh secure-kit recommended` (GSK104).",
				[]byte(codeownersFor(f.Repo.GetOwner().GetLogin())))
		},
	})

	register(Rule{
		ID: "GSK119", GHQRID: "repo-acc-001", Scope: ScopeRepository,
		Category: "access_control", Severity: SeverityHigh, Title: "Excessive admin collaborators",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if !f.CollaboratorsKnown {
				return Skip("could not read direct collaborators")
			}
			admins := 0
			for _, c := range f.Collaborators {
				if c.GetPermissions().GetAdmin() {
					admins++
				}
			}
			const maxAdmins = 3
			if admins > maxAdmins {
				return Fail(fmt.Sprintf("%d direct collaborators have admin access (threshold: %d)", admins, maxAdmins))
			}
			return Pass(fmt.Sprintf("%d direct collaborators have admin access", admins))
		},
	})

	register(Rule{
		ID: "GSK120", GHQRID: "repo-acc-002", Scope: ScopeRepository,
		Category: "access_control", Severity: SeverityMedium, Title: "Direct collaborators instead of teams",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if !f.CollaboratorsKnown {
				return Skip("could not read direct collaborators")
			}
			if len(f.Collaborators) > 0 {
				return Fail(fmt.Sprintf("%d direct collaborators found; prefer granting access via teams", len(f.Collaborators)))
			}
			return Pass("no direct collaborators found")
		},
	})

	register(Rule{
		ID: "GSK121", GHQRID: "repo-acc-003", Scope: ScopeRepository,
		Category: "security", Severity: SeverityHigh, Title: "Deploy keys with write access",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if !f.DeployKeysKnown {
				return Skip("could not read deploy keys")
			}
			for _, k := range f.DeployKeys {
				if !k.GetReadOnly() {
					return Fail("one or more deploy keys have write access")
				}
			}
			return Pass("no deploy keys have write access")
		},
	})

	register(Rule{
		ID: "GSK122", GHQRID: "repo-acc-004", Scope: ScopeRepository,
		Category: "security", Severity: SeverityMedium, Title: "Unverified deploy keys",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if !f.DeployKeysKnown {
				return Skip("could not read deploy keys")
			}
			for _, k := range f.DeployKeys {
				if !k.GetVerified() {
					return Fail("one or more deploy keys are unverified")
				}
			}
			return Pass("all deploy keys are verified")
		},
	})
}

func registerRepositoryMetadataRules() {
	register(Rule{
		ID: "GSK123", GHQRID: "repo-meta-001", Scope: ScopeRepository,
		Category: "community", Severity: SeverityMedium, Title: "Repository has no description",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.Repo.GetDescription() != "" {
				return Pass("repository has a description")
			}
			return Fail("repository has no description")
		},
	})

	register(Rule{
		ID: "GSK124", GHQRID: "repo-meta-002", Scope: ScopeRepository,
		Category: "community", Severity: SeverityLow, Title: "Repository has no topics",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if len(f.Repo.Topics) > 0 {
				return Pass(fmt.Sprintf("repository has %d topics", len(f.Repo.Topics)))
			}
			return Fail("repository has no topics")
		},
	})

	register(Rule{
		ID: "GSK125", GHQRID: "repo-feat-002", Scope: ScopeRepository,
		Category: "maintenance", Severity: SeverityLow, Title: "Auto-delete branches on merge not enabled", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.Repo.GetDeleteBranchOnMerge() {
				return Pass("auto-delete branches on merge is enabled")
			}
			return Fail("auto-delete branches on merge is disabled")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			_, err := gh.SetDeleteBranchOnMerge(ctx, g, repo, true)
			return err
		},
	})

	register(Rule{
		ID: "GSK126", GHQRID: "repo-feat-001", Scope: ScopeRepository,
		Category: "features", Severity: SeverityLow, Title: "Issues and Discussions both disabled", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.Repo.GetHasIssues() || f.Repo.GetHasDiscussions() {
				return Pass("Issues or Discussions is enabled")
			}
			return Fail("both Issues and Discussions are disabled")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			_, err := gh.EnableIssues(ctx, g, repo)
			return err
		},
	})

	register(Rule{
		ID: "GSK127", GHQRID: "repo-meta-003", Scope: ScopeRepository,
		Category: "maintenance", Severity: SeverityLow, Title: "Repository appears dormant but is not archived",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.Repo.GetArchived() {
				return Pass("repository is archived")
			}
			pushedAt := f.Repo.GetPushedAt().Time
			const dormantThreshold = 2 * 365 * 24 * time.Hour
			if pushedAt.IsZero() {
				return Skip("could not read last push time")
			}
			if time.Since(pushedAt) > dormantThreshold {
				return Fail(fmt.Sprintf("last pushed on %s and not archived", pushedAt.Format("2006-01-02")))
			}
			return Pass("repository has recent activity")
		},
	})
}

const defaultSecurityMD = `# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately using GitHub's private
vulnerability reporting feature (Security tab -> Report a vulnerability),
or contact the maintainers directly. Do not open a public issue.
`

// codeownersFor returns a starter CODEOWNERS file assigning the repository
// owner (user or organization login) as the default owner of all files.
func codeownersFor(owner string) string {
	return fmt.Sprintf(`# See https://docs.github.com/articles/about-codeowners for syntax.
# Each line is a file pattern followed by one or more owners.
*       @%s
`, owner)
}
