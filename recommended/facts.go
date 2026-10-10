package recommended

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/cli/go-gh/v2/pkg/auth"
	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

// branchErrorHTTPStatus captures the HTTP status code from a "(HTTP <code>)"
// marker that some client transports append to a stringified error message.
var branchErrorHTTPStatus = regexp.MustCompile(`\(HTTP (\d{3})\)`)

// RepositoryFacts holds the raw data collected from GitHub for a single
// repository, used as input to every repository-scoped Rule.Check function.
type RepositoryFacts struct {
	Repo       *github.Repository
	Hooks      []*github.Hook
	HooksKnown bool

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

	CodeScanningSetup             *github.DefaultSetupConfiguration
	VulnerabilityAlerts           *gh.RepositorySecurityFeatureStatus
	AutomatedSecurityFixes        *gh.RepositorySecurityFeatureStatus
	PrivateVulnerabilityReporting *gh.RepositorySecurityFeatureStatus

	// DefaultWorkflowPermissions is nil when the GITHUB_TOKEN default workflow
	// permissions for the repository could not be fetched.
	DefaultWorkflowPermissions *github.DefaultWorkflowPermissionRepository
	// ForkPRContributorApproval is nil when the fork PR contributor approval
	// policy for the repository could not be fetched.
	ForkPRContributorApproval *github.ContributorApprovalPermissions

	// ActionsPermissions is nil when the Actions permissions policy for the
	// repository could not be fetched.
	ActionsPermissions *github.ActionsPermissionsRepository
	// PrivateForkPRWorkflows is nil for public repositories and when the fork
	// pull request workflow settings could not be fetched.
	PrivateForkPRWorkflows *github.WorkflowsPermissions
	// HasTags is tri-state: nil means the existence of tags could not be
	// determined, so tag-related rules skip instead of reporting a false result.
	HasTags *bool
	// ImmutableReleases is nil when the repository has no tags or the status
	// could not be fetched.
	ImmutableReleases *github.RepoImmutableReleasesStatus

	Environments []*github.Environment
	// EnvironmentsKnown is false when the environment list could not be
	// fetched, so environment rules skip instead of treating the repository
	// as having no environments.
	EnvironmentsKnown bool
	// EnvironmentSecrets maps environment name to its secrets, for
	// environments that have at least one secret configured.
	EnvironmentSecrets map[string][]*github.Secret
	// EnvironmentSecretsKnown maps environment name to whether that
	// environment's secrets could be listed. Environments whose secrets could
	// not be read are absent, so a failure for one environment does not discard
	// the confirmed results of the others: rules can report violations for the
	// environments that were read and skip only the ones that remain unknown.
	EnvironmentSecretsKnown map[string]bool
	// EnvironmentBranchPolicies maps environment name to its custom deployment
	// branch policies, for environments that enable custom branch policies. It
	// is only populated when a selected rule needs to inspect the actual
	// branch-name patterns (rather than the deployment-branch-policy booleans).
	EnvironmentBranchPolicies map[string][]*github.DeploymentBranchPolicy
	// EnvironmentBranchPoliciesKnown maps environment name to whether that
	// environment's custom branch policies could be listed. Environments whose
	// policies could not be read are absent, so a failure for one environment
	// does not discard the confirmed results of the others.
	EnvironmentBranchPoliciesKnown map[string]bool
}

// isPrivateOrInternal reports whether the repository is not public. The
// visibility field is preferred; Private is the fallback for hosts that omit it.
func isPrivateOrInternal(r *github.Repository) bool {
	if v := r.GetVisibility(); v != "" {
		return v == "private" || v == "internal"
	}
	return r.GetPrivate()
}

// isNotFound reports whether err represents a GitHub 404 response. It relies on
// the HTTP status code only, so it is safe to use for any endpoint. Callers that
// need the branch-protection-specific "Branch not protected" fallback must use
// isBranchNotProtected instead.
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

// isBranchNotProtected reports whether err means the default branch has no legacy
// branch protection. GitHub answers the branch-protection endpoint with a 404 for
// an unprotected branch, but some client transports drop the HTTP response while
// preserving the standard "Branch not protected" message, so this
// branch-protection-specific check also accepts that message. An authoritative
// non-404 HTTP status always takes precedence over the message text: a typed
// response, or a "(HTTP <code>)" marker in the message, is only treated as
// no-protection when the status is 404, so a server or transport failure is not
// misreported as an unprotected branch.
func isBranchNotProtected(err error) bool {
	if err == nil {
		return false
	}
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.StatusCode == 404
	}
	if errors.As(err, &ghErr) && ghErr.Message == "Branch not protected" {
		return true
	}
	msg := err.Error()
	switch msg {
	case "Branch not protected", "branch is not protected":
		return true
	}
	if strings.Contains(msg, "branch is not protected") || strings.Contains(msg, "Branch not protected") {
		if m := branchErrorHTTPStatus.FindStringSubmatch(msg); m != nil {
			return m[1] == "404"
		}
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

// CollectRepositoryFacts gathers the data required to evaluate the given repository-scoped
// rules. Facts whose collection scales with the number of environments (environment secrets
// and custom branch policies) are only collected when a selected rule actually needs them,
// so unrelated checks do not pay their per-environment API cost.
// Individual collectors are best-effort: a permission error or 404 degrades the related
// facts to their zero value instead of aborting the whole collection.
func CollectRepositoryFacts(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, rules []Rule) (*RepositoryFacts, error) {
	repoInfo, err := gh.GetRepository(ctx, g, repo)
	if err != nil {
		return nil, err
	}

	f := &RepositoryFacts{Repo: repoInfo}

	if protection, err := gh.GetBranchProtection(ctx, g, repo, repoInfo.GetDefaultBranch()); err == nil {
		f.Protection = protection
		f.ProtectionKnown = true
	} else if isBranchNotProtected(err) {
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

	f.HasSecurityMD = anyFileExists(ctx, g, repo, "SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
	f.HasCodeowners = anyFileExists(ctx, g, repo, "CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")
	f.HasDependabotYML = anyFileExists(ctx, g, repo, ".github/dependabot.yml", ".github/dependabot.yaml")

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
	if permissions, err := gh.GetRepoDefaultWorkflowPermissions(ctx, g, repo); err == nil {
		f.DefaultWorkflowPermissions = permissions
	}
	if permissions, err := gh.GetRepoForkPRContributorApprovalPermissions(ctx, g, repo); err == nil {
		f.ForkPRContributorApproval = permissions
	}
	if permissions, err := gh.GetRepoActionsPermissions(ctx, g, repo); err == nil {
		f.ActionsPermissions = permissions
	}
	if isPrivateOrInternal(repoInfo) {
		if settings, err := gh.GetRepoPrivateRepoForkPRWorkflowSettings(ctx, g, repo); err == nil {
			f.PrivateForkPRWorkflows = settings
		}
	}
	if hasTags, err := gh.HasTags(ctx, g, repo); err == nil {
		f.HasTags = github.Ptr(hasTags)
		if hasTags {
			if status, err := gh.GetRepoImmutableReleases(ctx, g, repo); err == nil {
				f.ImmutableReleases = status
			}
		}
	}
	needSecrets, needBranchPolicies := environmentFactNeeds(rules)
	if needSecrets || needBranchPolicies {
		if environments, err := gh.ListEnvironments(ctx, g, repo); err == nil {
			f.Environments = environments
			f.EnvironmentsKnown = true

			if needSecrets {
				// Reuse the environments already listed above instead of calling
				// gh.CollectEnvSecrets, which would list them a second time. Only
				// secret-bearing environments are recorded, matching the map contract
				// documented on EnvironmentSecrets. A failure for one environment is
				// isolated to that environment (left out of EnvironmentSecretsKnown)
				// so the confirmed results of the others are preserved.
				envSecrets := make(map[string][]*github.Secret)
				secretsKnown := make(map[string]bool)
				for _, env := range environments {
					secrets, err := gh.ListEnvSecrets(ctx, g, repo, env.GetName())
					if err != nil {
						continue
					}
					secretsKnown[env.GetName()] = true
					if len(secrets) > 0 {
						envSecrets[env.GetName()] = secrets
					}
				}
				f.EnvironmentSecrets = envSecrets
				f.EnvironmentSecretsKnown = secretsKnown
			}

			if needBranchPolicies {
				// Only environments that enable custom branch policies have patterns
				// to inspect; the rest are classified from the deployment-branch-policy
				// booleans alone, so no extra request is made for them. A failure for
				// one environment is isolated to that environment (left out of
				// EnvironmentBranchPoliciesKnown) so the confirmed results of the
				// others are preserved.
				branchPolicies := make(map[string][]*github.DeploymentBranchPolicy)
				policiesKnown := make(map[string]bool)
				for _, env := range environments {
					policy := env.GetDeploymentBranchPolicy()
					if policy == nil || !policy.GetCustomBranchPolicies() {
						continue
					}
					policies, err := gh.ListDeploymentCustomBranchPolicies(ctx, g, repo, env)
					if err != nil {
						continue
					}
					branchPolicies[env.GetName()] = policies
					policiesKnown[env.GetName()] = true
				}
				f.EnvironmentBranchPolicies = branchPolicies
				f.EnvironmentBranchPoliciesKnown = policiesKnown
			}
		}
	}

	if selectedRule(rules, "GSK144", "GSK145") {
		if hooks, err := gh.ListRepoHooks(ctx, g, repo); err == nil {
			f.Hooks, f.HooksKnown = hooks, true
		}
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
	// DefaultSecurityConfigsKnown reports whether the default code security
	// configurations were successfully fetched. It stays false when the API
	// call fails so rules can distinguish "unknown" from "empty".
	DefaultSecurityConfigsKnown bool
	// DefaultWorkflowPermissions is nil when the GITHUB_TOKEN default workflow
	// permissions for the organization could not be fetched.
	DefaultWorkflowPermissions *github.DefaultWorkflowPermissionOrganization
	// ForkPRContributorApproval is nil when the fork PR contributor approval
	// policy for the organization could not be fetched.
	ForkPRContributorApproval *github.ContributorApprovalPermissions
	// ImmutableReleases is nil when the organization immutable releases
	// enforcement settings could not be fetched.
	ImmutableReleases *github.ImmutableReleaseSettings
	// PrivateForkPRWorkflows is nil when the fork pull request workflow
	// settings for private repositories could not be fetched.
	PrivateForkPRWorkflows *github.WorkflowsPermissions
	// Owners are the organization members with the owner (admin) role.
	Owners []*github.User
	// OwnersKnown is false when the owner list could not be fetched, so the
	// owner-count rule skips instead of treating the organization as having none.
	OwnersKnown           bool
	SuspendedOwners       []*github.User
	SuspendedOwnersKnown  bool
	SuspendedMembers      []*github.User
	SuspendedMembersKnown bool
	RunnerGroups          []*github.RunnerGroup
	RunnerGroupsKnown     bool
	Hooks                 []*github.Hook
	HooksKnown            bool
}

// CollectOrganizationFacts gathers the data required to evaluate all organization-scoped rules.
func CollectOrganizationFacts(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, rules []Rule) (*OrganizationFacts, error) {
	org, err := gh.GetOrg(ctx, g, repo)
	if err != nil {
		return nil, err
	}

	f := &OrganizationFacts{Org: org}
	if len(rules) == 0 {
		rules = AllRules()
	}

	if teams, err := gh.ListTeamsAssignedToRole(ctx, g, repo, "security_manager"); err == nil {
		f.SecurityManagerTeams = teams
	}
	if permissions, err := gh.GetOrgActionsPermissions(ctx, g, repo); err == nil {
		f.ActionsPermissions = permissions
	}
	if configs, err := gh.ListDefaultCodeSecurityConfigurations(ctx, g, repo); err == nil {
		f.DefaultSecurityConfigs = configs
		f.DefaultSecurityConfigsKnown = true
	}
	if permissions, err := gh.GetOrgDefaultWorkflowPermissions(ctx, g, repo); err == nil {
		f.DefaultWorkflowPermissions = permissions
	}
	if permissions, err := gh.GetOrgForkPRContributorApprovalPermissions(ctx, g, repo); err == nil {
		f.ForkPRContributorApproval = permissions
	}
	if settings, err := gh.GetOrgImmutableReleasesSettings(ctx, g, repo); err == nil {
		f.ImmutableReleases = settings
	}
	if settings, err := gh.GetOrgPrivateRepoForkPRWorkflowSettings(ctx, g, repo); err == nil {
		f.PrivateForkPRWorkflows = settings
	}
	if owners, err := gh.ListOrgMembers(ctx, g, repo, []string{"admin"}, false); err == nil {
		f.Owners = owners
		f.OwnersKnown = true
	}
	if selectedRule(rules, "GSK521") && f.OwnersKnown {
		f.SuspendedOwners, f.SuspendedOwnersKnown = collectSuspendedUsers(ctx, g, repo.Host, f.Owners)
	}
	if selectedRule(rules, "GSK522") {
		if members, err := gh.ListOrgMembers(ctx, g, repo, []string{"member"}, false); err == nil {
			f.SuspendedMembers, f.SuspendedMembersKnown = collectSuspendedUsers(ctx, g, repo.Host, members)
		}
	}
	if selectedRule(rules, "GSK523") {
		if groups, err := gh.ListOrgRunnerGroups(ctx, g, repo); err == nil {
			f.RunnerGroups, f.RunnerGroupsKnown = groups, true
		}
	}
	if selectedRule(rules, "GSK524", "GSK525") {
		if hooks, err := gh.ListOrgHooks(ctx, g, repo); err == nil {
			f.Hooks, f.HooksKnown = hooks, true
		}
	}

	return f, nil
}

func selectedRule(rules []Rule, ids ...string) bool {
	for _, rule := range rules {
		for _, id := range ids {
			if rule.ID == id {
				return true
			}
		}
	}
	return false
}

func collectSuspendedUsers(ctx context.Context, g *gh.GitHubClient, host string, users []*github.User) ([]*github.User, bool) {
	var suspended []*github.User
	known := true
	for _, user := range users {
		if user.GetLogin() == "" {
			known = false
			continue
		}
		if gh.IsSuspendedUser(user) {
			suspended = append(suspended, user)
			continue
		}
		if !auth.IsEnterprise(host) {
			continue
		}
		details, err := gh.FindUser(ctx, g, user.GetLogin())
		if err != nil || details == nil {
			known = false
			continue
		}
		if gh.IsSuspendedUser(details) {
			suspended = append(suspended, details)
		}
	}
	return suspended, known
}
