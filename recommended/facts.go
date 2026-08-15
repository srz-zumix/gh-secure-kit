package recommended

import (
	"context"
	"errors"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

// RepositoryFacts holds the raw data collected from GitHub for a single
// repository, used as input to every repository-scoped Rule.Check function.
type RepositoryFacts struct {
	Repo *github.Repository

	// Protection is nil when the default branch has no legacy branch protection rule.
	Protection *github.Protection
	Rulesets   []*github.RepositoryRuleset

	// Collaborators are direct (non-team, non-outside) collaborators.
	Collaborators []*github.User
	DeployKeys    []*github.Key

	HasSecurityMD    bool
	HasCodeowners    bool
	HasDependabotYML bool
	HasCodeQLConfig  bool

	CodeScanningSetup             *github.DefaultSetupConfiguration
	VulnerabilityAlerts           *gh.RepositorySecurityFeatureStatus
	AutomatedSecurityFixes        *gh.RepositorySecurityFeatureStatus
	PrivateVulnerabilityReporting *gh.RepositorySecurityFeatureStatus
}

// isNotFound reports whether err represents a GitHub 404 response.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.StatusCode == 404
	}
	return false
}

// fileExists reports whether the given path exists in the repository's default branch.
func fileExists(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, path string) bool {
	_, err := gh.GetRepositoryFileContent(ctx, g, repo, path, nil)
	return err == nil
}

// CollectRepositoryFacts gathers the data required to evaluate all repository-scoped rules.
// Individual collectors are best-effort: a permission error or 404 degrades the related
// facts to their zero value instead of aborting the whole collection.
func CollectRepositoryFacts(ctx context.Context, g *gh.GitHubClient, repo repository.Repository) (*RepositoryFacts, error) {
	repoInfo, err := gh.GetRepository(ctx, g, repo)
	if err != nil {
		return nil, err
	}

	f := &RepositoryFacts{Repo: repoInfo}

	if protection, err := gh.GetBranchProtection(ctx, g, repo, repoInfo.GetDefaultBranch()); err == nil {
		f.Protection = protection
	} else if !isNotFound(err) {
		// Legacy protection API returns 404 both for "no protection" and for
		// "branch not found"; treat any other error as a soft failure (skip).
		f.Protection = nil
	}

	if rulesets, err := gh.ListRepositoryRulesets(ctx, g, repo, true); err == nil {
		f.Rulesets = rulesets
	}

	if collaborators, err := gh.ListRepositoryCollaborators(ctx, g, repo, []string{"direct"}, nil); err == nil {
		f.Collaborators = collaborators
	}

	if keys, err := gh.ListDeployKeys(ctx, g, repo); err == nil {
		f.DeployKeys = keys
	}

	f.HasSecurityMD = fileExists(ctx, g, repo, "SECURITY.md")
	f.HasCodeowners = fileExists(ctx, g, repo, "CODEOWNERS") ||
		fileExists(ctx, g, repo, ".github/CODEOWNERS") ||
		fileExists(ctx, g, repo, "docs/CODEOWNERS")
	f.HasDependabotYML = fileExists(ctx, g, repo, ".github/dependabot.yml") ||
		fileExists(ctx, g, repo, ".github/dependabot.yaml")
	f.HasCodeQLConfig = fileExists(ctx, g, repo, ".github/codeql/codeql-config.yml") ||
		fileExists(ctx, g, repo, ".github/codeql/codeql-config.yaml")

	if setup, err := gh.GetCodeScanningDefaultSetupConfiguration(ctx, g, repo); err == nil {
		f.CodeScanningSetup = setup
	}
	if status, err := gh.GetVulnerabilityAlerts(ctx, g, repo); err == nil {
		f.VulnerabilityAlerts = status
	}
	if status, err := gh.GetAutomatedSecurityFixes(ctx, g, repo); err == nil {
		f.AutomatedSecurityFixes = status
	}
	if status, err := gh.GetPrivateVulnerabilityReporting(ctx, g, repo); err == nil {
		f.PrivateVulnerabilityReporting = status
	}

	return f, nil
}

// OrganizationFacts holds the raw data collected from GitHub for a single
// organization, used as input to every organization-scoped Rule.Check function.
type OrganizationFacts struct {
	Org                    *github.Organization
	SecurityManagerTeams   []*github.Team
	ActionsPermissions     *github.ActionsPermissions
	DefaultSecurityConfigs []*github.CodeSecurityConfigurationWithDefaultForNewRepos
}

// CollectOrganizationFacts gathers the data required to evaluate all organization-scoped rules.
func CollectOrganizationFacts(ctx context.Context, g *gh.GitHubClient, repo repository.Repository) (*OrganizationFacts, error) {
	org, err := gh.GetOrg(ctx, g, repo)
	if err != nil {
		return nil, err
	}

	f := &OrganizationFacts{Org: org}

	if teams, err := gh.ListTeamsAssignedToRole(ctx, g, repo, "security_manager"); err == nil {
		f.SecurityManagerTeams = teams
	}
	if permissions, err := gh.GetOrgActionsPermissions(ctx, g, repo); err == nil {
		f.ActionsPermissions = permissions
	}
	if configs, err := gh.ListDefaultCodeSecurityConfigurations(ctx, g, repo); err == nil {
		f.DefaultSecurityConfigs = configs
	}

	return f, nil
}
