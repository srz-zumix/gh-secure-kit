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
	// ProtectionKnown is false when the legacy branch-protection status could not
	// be determined (a non-404 error), so rules can skip instead of reporting a
	// false negative.
	ProtectionKnown bool
	Rulesets        []*github.RepositoryRuleset
	// RulesetsKnown is false when the ruleset state could not be fully determined
	// (the list call failed, or an active ruleset's details could not be fetched),
	// so branch-protection rules can skip instead of reporting a false negative.
	RulesetsKnown bool

	// Collaborators are direct (non-team, non-outside) collaborators.
	Collaborators []*github.User
	// CollaboratorsKnown is false when the direct-collaborator list could not be
	// fetched, so access-control rules skip instead of treating the repository as
	// having no collaborators (a false negative).
	CollaboratorsKnown bool
	DeployKeys         []*github.Key
	// DeployKeysKnown is false when the deploy-key list could not be fetched, so
	// deploy-key rules skip instead of treating the repository as having no keys.
	DeployKeysKnown bool

	// File-existence facts are tri-state: nil means the existence could not be
	// determined (a non-404 error), so rules skip instead of reporting a file as
	// missing.
	HasSecurityMD    *bool
	HasCodeowners    *bool
	HasDependabotYML *bool
	HasCodeQLConfig  *bool

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

// fileExists reports whether the given path exists in the repository's default
// branch. The second return is false when the answer is unknown (a non-404
// error such as a permission or transient API failure), so callers can skip a
// rule instead of recording a false "missing file".
func fileExists(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, path string) (exists bool, known bool) {
	_, err := gh.GetRepositoryFileContent(ctx, g, repo, path, nil)
	if err == nil {
		return true, true
	}
	if isNotFound(err) {
		return false, true
	}
	return false, false
}

// anyFileExists reports whether any of the candidate paths exists, as a
// tri-state: a non-nil true when at least one path is present, a non-nil false
// when every path was definitively absent (404), and nil when the result is
// unknown (no path was found but at least one lookup failed for a non-404
// reason).
func anyFileExists(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, paths ...string) *bool {
	known := true
	for _, path := range paths {
		exists, ok := fileExists(ctx, g, repo, path)
		if exists {
			return github.Ptr(true)
		}
		if !ok {
			known = false
		}
	}
	if !known {
		return nil
	}
	return github.Ptr(false)
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
		f.ProtectionKnown = true
	} else if isNotFound(err) {
		// The legacy protection API returns 404 both for "no protection" and for
		// "branch not found"; either way the branch has no legacy protection.
		f.ProtectionKnown = true
	}
	// A non-404 error leaves ProtectionKnown false so rules skip rather than
	// report a false negative.

	if rulesets, err := gh.ListRepositoryRulesets(ctx, g, repo, true); err == nil {
		f.RulesetsKnown = true
		for _, rs := range rulesets {
			// The list endpoint omits conditions/rules; fetch the details of
			// active rulesets so branch-protection rules can tell whether the
			// default branch is actually targeted. If a detail fetch fails the
			// state is indeterminate, so mark rulesets unknown.
			if rs.GetEnforcement() == "active" && rs.Conditions == nil && rs.GetID() != 0 {
				if detailed, derr := gh.GetRepositoryRuleset(ctx, g, repo, rs.GetID(), true); derr == nil && detailed != nil {
					rs = detailed
				} else {
					f.RulesetsKnown = false
				}
			}
			f.Rulesets = append(f.Rulesets, rs)
		}
	}

	if collaborators, err := gh.ListRepositoryCollaborators(ctx, g, repo, []string{"direct"}, nil); err == nil {
		f.Collaborators = collaborators
		f.CollaboratorsKnown = true
	}

	if keys, err := gh.ListDeployKeys(ctx, g, repo); err == nil {
		f.DeployKeys = keys
		f.DeployKeysKnown = true
	}

	f.HasSecurityMD = anyFileExists(ctx, g, repo, "SECURITY.md")
	f.HasCodeowners = anyFileExists(ctx, g, repo, "CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")
	f.HasDependabotYML = anyFileExists(ctx, g, repo, ".github/dependabot.yml", ".github/dependabot.yaml")
	f.HasCodeQLConfig = anyFileExists(ctx, g, repo, ".github/codeql/codeql-config.yml", ".github/codeql/codeql-config.yaml")

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
