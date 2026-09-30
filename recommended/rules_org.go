package recommended

import (
	"context"
	"fmt"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

func init() {
	registerOrganizationRules()
}

func registerOrganizationRules() {
	register(Rule{
		ID: "GSK501", GHQRID: "org-sec-001", Scope: ScopeOrganization,
		Category: "security", Severity: SeverityCritical, Title: "Two-factor authentication not required for members",
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.Org.GetTwoFactorRequirementEnabled() {
				return Pass("two-factor authentication is required for all members")
			}
			return Fail("two-factor authentication is not required for all members")
		},
	})

	register(Rule{
		ID: "GSK502", GHQRID: "org-sec-002", Scope: ScopeOrganization,
		Category: "security", Severity: SeverityMedium, Title: "Web commit signoff not required", Fixable: true,
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.Org.GetWebCommitSignoffRequired() {
				return Pass("web-based commit signoff is required")
			}
			return Fail("web-based commit signoff is not required")
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			_, err := gh.SetOrgWebCommitSignoffRequired(ctx, g, repo, true)
			return err
		},
	})

	register(Rule{
		ID: "GSK503", GHQRID: "org-sec-003", Scope: ScopeOrganization,
		Category: "access_control", Severity: SeverityHigh, Title: "Default repository permission is admin or write", Fixable: true,
		CheckOrg: func(f *OrganizationFacts) Outcome {
			perm := f.Org.GetDefaultRepoPermission()
			if perm == "admin" || perm == "write" {
				return Fail(fmt.Sprintf("default repository permission for members is %q", perm))
			}
			return Pass(fmt.Sprintf("default repository permission for members is %q", perm))
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			_, err := gh.SetOrgBasePermission(ctx, g, repo, "read")
			return err
		},
	})

	register(Rule{
		ID: "GSK504", GHQRID: "org-sec-004", Scope: ScopeOrganization,
		Category: "access_control", Severity: SeverityMedium, Title: "Members can create public repositories", Fixable: true,
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.Org.GetMembersCanCreatePublicRepos() {
				return Fail("members are allowed to create public repositories")
			}
			return Pass("members are not allowed to create public repositories")
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			_, err := gh.SetOrgMembersCanCreatePublicRepos(ctx, g, repo, false)
			return err
		},
	})

	register(Rule{
		ID: "GSK505", GHQRID: "org-sec-005", Scope: ScopeOrganization,
		Category: "security", Severity: SeverityMedium, Title: "No security manager team assigned",
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if len(f.SecurityManagerTeams) > 0 {
				return Pass(fmt.Sprintf("%d team(s) assigned the security manager role", len(f.SecurityManagerTeams)))
			}
			return Fail("no team is assigned the security manager role")
		},
	})

	register(Rule{
		ID: "GSK506", GHQRID: "org-act-002", Scope: ScopeOrganization,
		Category: "actions", Severity: SeverityHigh, Title: "Actions allows all third-party actions and reusable workflows", Fixable: true,
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.ActionsPermissions == nil {
				return Skip("could not retrieve Actions permissions for the organization")
			}
			if f.ActionsPermissions.GetAllowedActions() == gh.OrgAllowedActionsAll {
				return Fail("all GitHub Actions, including third-party actions, are allowed to run")
			}
			return Pass(fmt.Sprintf("allowed actions are restricted (%q)", f.ActionsPermissions.GetAllowedActions()))
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			_, err := gh.SetOrgAllowedActions(ctx, g, repo, gh.OrgAllowedActionsSelected)
			return err
		},
	})

	register(Rule{
		ID: "GSK507", GHQRID: "", Scope: ScopeOrganization,
		Category: "security", Severity: SeverityHigh, Title: "No default code security configuration for new repositories",
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if !f.DefaultSecurityConfigsKnown {
				return Skip("could not retrieve default code security configurations for the organization")
			}
			for _, c := range f.DefaultSecurityConfigs {
				if d := c.GetDefaultForNewRepos(); d != "" && d != "none" {
					return Pass(fmt.Sprintf("a code security configuration is the default for new repositories (%q)", d))
				}
			}
			return Fail("no code security configuration is set as the default for new repositories; new repositories start with no baseline security settings")
		},
	})

	register(Rule{
		ID: "GSK508", GHQRID: "", Scope: ScopeOrganization,
		Category: "actions", Severity: SeverityMedium, Title: "Actions enabled for all repositories",
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.ActionsPermissions == nil {
				return Skip("could not retrieve Actions permissions for the organization")
			}
			enabled := f.ActionsPermissions.GetEnabledRepositories()
			if enabled == "all" {
				return Fail("GitHub Actions is enabled for all repositories in the organization")
			}
			return Pass(fmt.Sprintf("GitHub Actions is restricted to a subset of repositories (%q)", enabled))
		},
	})

	register(Rule{
		ID: "GSK509", GHQRID: "", Scope: ScopeOrganization,
		Category: "access_control", Severity: SeverityHigh, Title: "Members can fork private repositories", Fixable: true,
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.Org.GetMembersCanForkPrivateRepos() {
				return Fail("members are allowed to fork private repositories")
			}
			return Pass("members are not allowed to fork private repositories")
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			_, err := gh.SetOrgMembersCanForkPrivateRepos(ctx, g, repo, false)
			return err
		},
	})

	register(Rule{
		ID: "GSK510", GHQRID: "", Scope: ScopeOrganization,
		Category: "access_control", Severity: SeverityHigh, Title: "Members can delete repositories", Fixable: true,
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.Org.GetMembersCanDeleteRepositories() {
				return Fail("members with admin permissions are allowed to delete repositories")
			}
			return Pass("members with admin permissions are not allowed to delete repositories")
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			_, err := gh.SetOrgMembersCanDeleteRepositories(ctx, g, repo, false)
			return err
		},
	})

	register(Rule{
		ID: "GSK511", GHQRID: "", Scope: ScopeOrganization,
		Category: "access_control", Severity: SeverityHigh, Title: "Members can change repository visibility", Fixable: true,
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.Org.GetMembersCanChangeRepoVisibility() {
				return Fail("members with admin permissions are allowed to change a repository's visibility")
			}
			return Pass("members with admin permissions are not allowed to change a repository's visibility")
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			_, err := gh.SetOrgMembersCanChangeRepoVisibility(ctx, g, repo, false)
			return err
		},
	})

	register(Rule{
		ID: "GSK512", GHQRID: "", Scope: ScopeOrganization,
		Category: "actions", Severity: SeverityHigh, Title: "GITHUB_TOKEN default permissions are read-write", Fixable: true,
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.DefaultWorkflowPermissions == nil {
				return Skip("could not retrieve default workflow permissions for the organization")
			}
			if f.DefaultWorkflowPermissions.GetDefaultWorkflowPermissions() == gh.DefaultWorkflowPermissionsWrite {
				return Fail("the GITHUB_TOKEN default permissions are read-write for all workflows")
			}
			return Pass("the GITHUB_TOKEN default permissions are read-only")
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			_, err := gh.SetOrgDefaultWorkflowPermissions(ctx, g, repo, gh.DefaultWorkflowPermissionsRead)
			return err
		},
	})

	register(Rule{
		ID: "GSK513", GHQRID: "", Scope: ScopeOrganization,
		Category: "actions", Severity: SeverityHigh, Title: "Actions can approve pull requests", Fixable: true,
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.DefaultWorkflowPermissions == nil {
				return Skip("could not retrieve default workflow permissions for the organization")
			}
			if f.DefaultWorkflowPermissions.GetCanApprovePullRequestReviews() {
				return Fail("GitHub Actions is allowed to approve pull requests, which can bypass required reviews")
			}
			return Pass("GitHub Actions is not allowed to approve pull requests")
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			_, err := gh.SetOrgActionsCanApprovePullRequestReviews(ctx, g, repo, false)
			return err
		},
	})

	register(Rule{
		ID: "GSK514", GHQRID: "", Scope: ScopeOrganization,
		Category: "actions", Severity: SeverityHigh, Title: "Fork pull request workflows run without maintainer approval", Fixable: true,
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.ForkPRContributorApproval == nil {
				return Skip("could not retrieve the fork pull request contributor approval policy for the organization")
			}
			policy := f.ForkPRContributorApproval.GetApprovalPolicy()
			if policy == gh.ForkPRApprovalAllExternalContributors {
				return Pass("all external contributors require maintainer approval to run fork pull request workflows")
			}
			return Fail(fmt.Sprintf("fork pull request workflows only require maintainer approval for %q, allowing some external contributors to run workflows without review", policy))
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			return gh.SetOrgForkPRContributorApprovalPolicy(ctx, g, repo, gh.ForkPRApprovalAllExternalContributors)
		},
	})

	register(Rule{
		ID: "GSK515", GHQRID: "", Scope: ScopeOrganization,
		Category: "access_control", Severity: SeverityMedium, Title: "Members can create private repositories", Fixable: true,
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.Org.GetMembersCanCreatePrivateRepos() {
				return Fail("members are allowed to create private repositories")
			}
			return Pass("members are not allowed to create private repositories")
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			_, err := gh.SetOrgMembersCanCreatePrivateRepos(ctx, g, repo, false)
			return err
		},
	})

	register(Rule{
		ID: "GSK516", GHQRID: "", Scope: ScopeOrganization,
		Category: "access_control", Severity: SeverityMedium, Title: "Members can create internal repositories", Fixable: true,
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.Org.GetMembersCanCreateInternalRepos() {
				return Fail("members are allowed to create internal repositories")
			}
			return Pass("members are not allowed to create internal repositories")
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			_, err := gh.SetOrgMembersCanCreateInternalRepos(ctx, g, repo, false)
			return err
		},
	})
}
