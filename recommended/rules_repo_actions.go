package recommended

import (
	"context"
	"fmt"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

func init() {
	registerRepositoryActionsRules()
}

func registerRepositoryActionsRules() {
	register(Rule{
		ID: "GSK132", GHQRID: "", Scope: ScopeRepository,
		Category: "actions", Severity: SeverityHigh, Title: "GITHUB_TOKEN default permissions are read-write", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.DefaultWorkflowPermissions == nil {
				return Skip("could not retrieve default workflow permissions for the repository")
			}
			if f.DefaultWorkflowPermissions.GetDefaultWorkflowPermissions() == gh.DefaultWorkflowPermissionsWrite {
				return Fail("the GITHUB_TOKEN default permissions are read-write for all workflows")
			}
			return Pass("the GITHUB_TOKEN default permissions are read-only")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			_, err := gh.SetRepoDefaultWorkflowPermissions(ctx, g, repo, gh.DefaultWorkflowPermissionsRead)
			return err
		},
	})

	register(Rule{
		ID: "GSK133", GHQRID: "", Scope: ScopeRepository,
		Category: "actions", Severity: SeverityHigh, Title: "Actions can approve pull requests", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.DefaultWorkflowPermissions == nil {
				return Skip("could not retrieve default workflow permissions for the repository")
			}
			if f.DefaultWorkflowPermissions.GetCanApprovePullRequestReviews() {
				return Fail("GitHub Actions is allowed to approve pull requests, which can bypass required reviews")
			}
			return Pass("GitHub Actions is not allowed to approve pull requests")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			_, err := gh.SetRepoActionsCanApprovePullRequestReviews(ctx, g, repo, false)
			return err
		},
	})

	register(Rule{
		ID: "GSK134", GHQRID: "", Scope: ScopeRepository,
		Category: "actions", Severity: SeverityHigh, Title: "Fork pull request workflows run without maintainer approval", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.ForkPRContributorApproval == nil {
				return Skip("could not retrieve the fork pull request contributor approval policy for the repository")
			}
			policy := f.ForkPRContributorApproval.GetApprovalPolicy()
			if policy == gh.ForkPRApprovalAllExternalContributors {
				return Pass("all external contributors require maintainer approval to run fork pull request workflows")
			}
			return Fail(fmt.Sprintf("fork pull request workflows only require maintainer approval for %q, allowing some external contributors to run workflows without review", policy))
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			return gh.SetRepoForkPRContributorApprovalPolicy(ctx, g, repo, gh.ForkPRApprovalAllExternalContributors)
		},
	})
}
