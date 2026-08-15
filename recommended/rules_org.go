package recommended

import (
	"context"
	"fmt"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v90/github"
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
			_, err := gh.EditOrg(ctx, g, repo, &github.Organization{WebCommitSignoffRequired: github.Ptr(true)})
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
			_, err := gh.EditOrg(ctx, g, repo, &github.Organization{MembersCanCreatePublicRepos: github.Ptr(false)})
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
			if f.ActionsPermissions.GetAllowedActions() == "all" {
				return Fail("all GitHub Actions, including third-party actions, are allowed to run")
			}
			return Pass(fmt.Sprintf("allowed actions are restricted (%q)", f.ActionsPermissions.GetAllowedActions()))
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			_, err := gh.UpdateOrgActionsPermissions(ctx, g, repo, github.ActionsPermissions{
				AllowedActions: github.Ptr("selected"),
			})
			return err
		},
	})
}
