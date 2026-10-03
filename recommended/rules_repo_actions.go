package recommended

import (
	"context"
	"fmt"
	"strings"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

func init() {
	registerRepositoryActionsRules()
}

// forkPRWorkflowRisks lists the sensitive resources that workflows triggered by
// fork pull requests receive. It is empty when such workflows are disabled.
func forkPRWorkflowRisks(s *github.WorkflowsPermissions) []string {
	if !s.GetRunWorkflowsFromForkPullRequests() {
		return nil
	}
	var risks []string
	if s.GetSendWriteTokensToWorkflows() {
		risks = append(risks, "write tokens")
	}
	if s.GetSendSecretsAndVariables() {
		risks = append(risks, "secrets and variables")
	}
	return risks
}

// checkForkPRWorkflowSettings evaluates the fork pull request workflow settings
// shared by the repository and organization rules.
func checkForkPRWorkflowSettings(s *github.WorkflowsPermissions, scope string) Outcome {
	if s == nil {
		return Skip("could not retrieve the fork pull request workflow settings for private repositories of the " + scope)
	}
	if !s.GetRunWorkflowsFromForkPullRequests() {
		return Pass("workflows are not run for fork pull requests of private repositories")
	}
	if risks := forkPRWorkflowRisks(s); len(risks) > 0 {
		return Fail(fmt.Sprintf("fork pull request workflows of private repositories receive %s", strings.Join(risks, " and ")))
	}
	return Pass("fork pull request workflows of private repositories receive neither write tokens nor secrets")
}

// restrictedForkPRWorkflowSettings returns the current settings with write
// tokens and secrets withheld from fork pull request workflows.
func restrictedForkPRWorkflowSettings(s *github.WorkflowsPermissions) github.WorkflowsPermissionsOpt {
	return github.WorkflowsPermissionsOpt{
		RunWorkflowsFromForkPullRequests:  s.GetRunWorkflowsFromForkPullRequests(),
		SendWriteTokensToWorkflows:        github.Ptr(false),
		SendSecretsAndVariables:           github.Ptr(false),
		RequireApprovalForForkPRWorkflows: s.RequireApprovalForForkPRWorkflows,
	}
}

func registerRepositoryActionsRules() {
	register(Rule{
		ID: "GSK138", GHQRID: "", Scope: ScopeRepository,
		Category: "actions", Severity: SeverityHigh, Title: "Actions SHA pinning not required", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.ActionsPermissions == nil {
				return Skip("could not retrieve Actions permissions for the repository")
			}
			if f.ActionsPermissions.Enabled != nil && !f.ActionsPermissions.GetEnabled() {
				return Skip("GitHub Actions is disabled for the repository")
			}
			if f.ActionsPermissions.GetSHAPinningRequired() {
				return Pass("actions must be pinned to a full-length commit SHA")
			}
			return Fail("actions are not required to be pinned to a full-length commit SHA; a moved tag can run attacker-controlled code")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			_, err := gh.SetRepoSHAPinningRequired(ctx, g, repo, true)
			return err
		},
	})

	register(Rule{
		ID: "GSK141", GHQRID: "", Scope: ScopeRepository,
		Category: "actions", Severity: SeverityHigh, Title: "Private fork pull request workflows receive write tokens or secrets", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if !isPrivateOrInternal(f.Repo) {
				return Skip("fork pull request workflow settings only apply to private and internal repositories")
			}
			return checkForkPRWorkflowSettings(f.PrivateForkPRWorkflows, "repository")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			return gh.UpdateRepoPrivateRepoForkPRWorkflowSettings(ctx, g, repo, restrictedForkPRWorkflowSettings(f.PrivateForkPRWorkflows))
		},
	})

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
