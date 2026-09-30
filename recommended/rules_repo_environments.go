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

// activeRulesetProtectsAllBranches reports whether an active branch ruleset with
// at least one rule applies to every branch of the repository (a "~ALL" target
// with no exclusions). When every branch is protected, an environment limited to
// "protected branches only" can still deploy from any branch, so the setting
// does not actually restrict deployments.
func activeRulesetProtectsAllBranches(f *RepositoryFacts) bool {
	if f == nil || !f.RulesetsKnown {
		return false
	}
	for _, rs := range f.Rulesets {
		if rs.GetEnforcement() != "active" {
			continue
		}
		if t := rs.Target; t != nil && *t != github.RulesetTargetBranch {
			continue
		}
		if !gh.HasAnyRulesetRule(rs.Rules) {
			continue
		}
		cond := rs.Conditions
		if cond == nil || cond.RefName == nil || len(cond.RefName.Exclude) > 0 {
			continue
		}
		for _, pattern := range cond.RefName.Include {
			if pattern == "~ALL" {
				return true
			}
		}
	}
	return false
}

func registerRepositoryEnvironmentRules() {
	register(Rule{
		ID: "GSK135", GHQRID: "", Scope: ScopeRepository,
		Category: "environments", Severity: SeverityMedium, Title: "Environment with secrets has no required reviewers configured",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if !f.EnvironmentsKnown {
				return Skip("could not read environments")
			}
			var missing, unknown []string
			for _, env := range f.Environments {
				name := env.GetName()
				if !f.EnvironmentSecretsKnown[name] {
					// The secrets of this environment could not be read, so a
					// missing reviewer here can neither be confirmed nor ruled
					// out; it is reported as indeterminate below.
					unknown = append(unknown, name)
					continue
				}
				if len(f.EnvironmentSecrets[name]) == 0 {
					// Environments without secrets have nothing sensitive for a
					// reviewer to gate, so a missing reviewer isn't reported here.
					continue
				}
				rule := environmentProtectionRule(env, "required_reviewers")
				if rule == nil || len(rule.GetReviewers()) == 0 {
					missing = append(missing, name)
				}
			}
			// Report confirmed violations before skipping, so a single
			// unreadable environment does not mask an environment already
			// known to lack required reviewers.
			if len(missing) > 0 {
				return Fail(fmt.Sprintf("environments with secrets but no required reviewers: %s", strings.Join(missing, ", ")))
			}
			if len(unknown) > 0 {
				return Skip(fmt.Sprintf("could not read secrets for environments: %s", strings.Join(unknown, ", ")))
			}
			return Pass("all environments with secrets require reviewers before deployment")
		},
	})

	register(Rule{
		ID: "GSK136", GHQRID: "", Scope: ScopeRepository,
		Category: "environments", Severity: SeverityHigh, Title: "Environment with secrets allows self-review", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if !f.EnvironmentsKnown {
				return Skip("could not read environments")
			}
			var selfReview, unknown []string
			for _, env := range f.Environments {
				name := env.GetName()
				if !f.EnvironmentSecretsKnown[name] {
					unknown = append(unknown, name)
					continue
				}
				if len(f.EnvironmentSecrets[name]) == 0 {
					continue
				}
				rule := environmentProtectionRule(env, "required_reviewers")
				if rule != nil && len(rule.GetReviewers()) > 0 && !rule.GetPreventSelfReview() {
					selfReview = append(selfReview, name)
				}
			}
			// Report confirmed violations before skipping, so a single
			// unreadable environment does not mask an environment already
			// known to allow self-review.
			if len(selfReview) > 0 {
				return Fail(fmt.Sprintf("environments with secrets allowing self-review: %s", strings.Join(selfReview, ", ")))
			}
			if len(unknown) > 0 {
				return Skip(fmt.Sprintf("could not read secrets for environments: %s", strings.Join(unknown, ", ")))
			}
			return Pass("no environment with secrets allows self-review")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			for _, env := range f.Environments {
				name := env.GetName()
				// Only secret-bearing environments are flagged by the check, so
				// remediation must not touch environments without secrets even if
				// they happen to allow self-review. Environments whose secrets
				// could not be read are left untouched for the same reason.
				if !f.EnvironmentSecretsKnown[name] || len(f.EnvironmentSecrets[name]) == 0 {
					continue
				}
				rule := environmentProtectionRule(env, "required_reviewers")
				if rule == nil || len(rule.GetReviewers()) == 0 || rule.GetPreventSelfReview() {
					continue
				}
				req := gh.EnvironmentToCreateUpdateRequest(env)
				req.PreventSelfReview = github.Ptr(true)
				if _, err := gh.CreateUpdateEnvironment(ctx, g, repo, name, req); err != nil {
					return fmt.Errorf("failed to enable prevent-self-review for environment %q: %w", name, err)
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
				name := env.GetName()
				policy := env.GetDeploymentBranchPolicy()
				if policy == nil {
					unrestricted = append(unrestricted, name)
					continue
				}
				if policy.GetCustomBranchPolicies() {
					// An allow-list of branch name patterns only restricts
					// deployments if the patterns themselves are not catch-all.
					// The deployment-branch-policy booleans alone cannot prove
					// this, so inspect the fetched patterns; when they could not
					// be read, treat the environment as indeterminate instead of
					// passing a possibly-unrestricted configuration.
					if !f.EnvironmentBranchPoliciesKnown[name] {
						indeterminate = append(indeterminate, name)
						continue
					}
					if environmentHasCatchAllBranchPolicy(f.EnvironmentBranchPolicies[name]) {
						unrestricted = append(unrestricted, name)
						continue
					}
					continue
				}
				if policy.GetProtectedBranches() {
					// "Protected branches only" restricts deployments only when
					// some branches are protected and others are not. If a
					// ruleset protects every branch, every branch is deployable,
					// so the environment is unrestricted despite the setting.
					if activeRulesetProtectsAllBranches(f) {
						unrestricted = append(unrestricted, name)
						continue
					}
					// With no branch protection anywhere, GitHub allows every
					// branch to deploy. Facts only reveal the default branch's
					// protection, so treat confirmed default-branch protection as
					// sufficient evidence of a restriction and otherwise skip as
					// indeterminate instead of passing a possibly-unrestricted
					// configuration.
					if f.Protection != nil || activeRulesetProtectsDefaultBranch(f) {
						continue
					}
					indeterminate = append(indeterminate, name)
					continue
				}
				// Neither protected branches nor custom policies effectively
				// restricts which branches can deploy.
				unrestricted = append(unrestricted, name)
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
