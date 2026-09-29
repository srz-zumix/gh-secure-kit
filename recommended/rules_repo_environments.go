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
	registerRepositoryEnvironmentRules()
}

// environmentFactNeeds reports which per-environment facts the selected rules
// require, so CollectRepositoryFacts can skip the requests that scale with the
// number of environments when no selected rule consumes them.
func environmentFactNeeds(rules []Rule) (needSecrets, needBranchPolicies bool) {
	for _, r := range rules {
		if r.Scope != ScopeRepository {
			continue
		}
		switch r.ID {
		case "GSK135", "GSK136":
			needSecrets = true
		case "GSK137":
			needBranchPolicies = true
		}
	}
	return needSecrets, needBranchPolicies
}

// environmentHasCatchAllBranchPolicy reports whether any custom deployment
// branch policy uses a catch-all pattern that admits every branch, leaving the
// environment effectively unrestricted despite enabling custom policies. Tag
// policies are ignored because they do not gate which branches can deploy.
// GitHub wildcards do not cross "/", so only "*" (all top-level branches) and
// "**" (all branches) are treated as catch-all.
func environmentHasCatchAllBranchPolicy(policies []*github.DeploymentBranchPolicy) bool {
	for _, p := range policies {
		if t := p.GetType(); t != "" && t != "branch" {
			continue
		}
		switch p.GetName() {
		case "*", "**":
			return true
		}
	}
	return false
}

// environmentProtectionRule returns the environment's protection rule of the
// given type, or nil if none is configured.
func environmentProtectionRule(env *github.Environment, ruleType string) *github.ProtectionRule {
	for _, rule := range env.GetProtectionRules() {
		if rule.GetType() == ruleType {
			return rule
		}
	}
	return nil
}

func registerRepositoryEnvironmentRules() {
	register(Rule{
		ID: "GSK135", GHQRID: "", Scope: ScopeRepository,
		Category: "environments", Severity: SeverityMedium, Title: "Environment with secrets has no required reviewers configured",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if !f.EnvironmentsKnown || !f.EnvironmentSecretsKnown {
				return Skip("could not read environments or environment secrets")
			}
			var missing []string
			for _, env := range f.Environments {
				if len(f.EnvironmentSecrets[env.GetName()]) == 0 {
					// Environments without secrets have nothing sensitive for a
					// reviewer to gate, so a missing reviewer isn't reported here.
					continue
				}
				rule := environmentProtectionRule(env, "required_reviewers")
				if rule == nil || len(rule.GetReviewers()) == 0 {
					missing = append(missing, env.GetName())
				}
			}
			if len(missing) > 0 {
				return Fail(fmt.Sprintf("environments with secrets but no required reviewers: %s", strings.Join(missing, ", ")))
			}
			return Pass("all environments with secrets require reviewers before deployment")
		},
	})

	register(Rule{
		ID: "GSK136", GHQRID: "", Scope: ScopeRepository,
		Category: "environments", Severity: SeverityHigh, Title: "Environment with secrets allows self-review", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if !f.EnvironmentsKnown || !f.EnvironmentSecretsKnown {
				return Skip("could not read environments or environment secrets")
			}
			var selfReview []string
			for _, env := range f.Environments {
				if len(f.EnvironmentSecrets[env.GetName()]) == 0 {
					continue
				}
				rule := environmentProtectionRule(env, "required_reviewers")
				if rule != nil && len(rule.GetReviewers()) > 0 && !rule.GetPreventSelfReview() {
					selfReview = append(selfReview, env.GetName())
				}
			}
			if len(selfReview) > 0 {
				return Fail(fmt.Sprintf("environments with secrets allowing self-review: %s", strings.Join(selfReview, ", ")))
			}
			return Pass("no environment with secrets allows self-review")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			for _, env := range f.Environments {
				// Only secret-bearing environments are flagged by the check, so
				// remediation must not touch environments without secrets even if
				// they happen to allow self-review.
				if len(f.EnvironmentSecrets[env.GetName()]) == 0 {
					continue
				}
				rule := environmentProtectionRule(env, "required_reviewers")
				if rule == nil || len(rule.GetReviewers()) == 0 || rule.GetPreventSelfReview() {
					continue
				}
				req := gh.EnvironmentToCreateUpdateRequest(env)
				req.PreventSelfReview = github.Ptr(true)
				if _, err := gh.CreateUpdateEnvironment(ctx, g, repo, env.GetName(), req); err != nil {
					return fmt.Errorf("failed to enable prevent-self-review for environment %q: %w", env.GetName(), err)
				}
			}
			return nil
		},
	})

	register(Rule{
		ID: "GSK137", GHQRID: "", Scope: ScopeRepository,
		Category: "environments", Severity: SeverityMedium, Title: "Environment deployment branch policy allows all branches",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if !f.EnvironmentsKnown {
				return Skip("could not read environments")
			}
			var unrestricted, indeterminate []string
			for _, env := range f.Environments {
				policy := env.GetDeploymentBranchPolicy()
				if policy == nil {
					unrestricted = append(unrestricted, env.GetName())
					continue
				}
				if policy.GetCustomBranchPolicies() {
					// An allow-list of branch name patterns only restricts
					// deployments if the patterns themselves are not catch-all.
					// The deployment-branch-policy booleans alone cannot prove
					// this, so inspect the fetched patterns; when they could not
					// be read, treat the environment as indeterminate instead of
					// passing a possibly-unrestricted configuration.
					if !f.EnvironmentBranchPoliciesKnown {
						indeterminate = append(indeterminate, env.GetName())
						continue
					}
					if environmentHasCatchAllBranchPolicy(f.EnvironmentBranchPolicies[env.GetName()]) {
						unrestricted = append(unrestricted, env.GetName())
						continue
					}
					continue
				}
				if policy.GetProtectedBranches() {
					// "Protected branches only" restricts deployments only when the
					// repository actually has at least one protected branch. With no
					// branch protection anywhere, GitHub allows every branch to
					// deploy. Facts only reveal the default branch's protection, so
					// treat confirmed default-branch protection as sufficient
					// evidence and otherwise skip as indeterminate instead of
					// passing a possibly-unrestricted configuration.
					if f.Protection != nil || activeRulesetProtectsDefaultBranch(f) {
						continue
					}
					indeterminate = append(indeterminate, env.GetName())
					continue
				}
				// Neither protected branches nor custom policies effectively
				// restricts which branches can deploy.
				unrestricted = append(unrestricted, env.GetName())
			}
			if len(unrestricted) > 0 {
				return Fail(fmt.Sprintf("environments deployable from any branch: %s", strings.Join(unrestricted, ", ")))
			}
			if len(indeterminate) > 0 {
				return Skip(fmt.Sprintf("environments restrict deployments but the restriction could not be confirmed: %s", strings.Join(indeterminate, ", ")))
			}
			return Pass("all environments restrict which branches can deploy")
		},
	})
}
