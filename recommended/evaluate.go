package recommended

import (
	"context"
	"fmt"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

// EvaluateRepository collects facts for a single repository and evaluates the
// given rules against it. Only rules with Scope == ScopeRepository are evaluated.
func EvaluateRepository(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, rules []Rule) ([]Result, *RepositoryFacts, error) {
	facts, err := CollectRepositoryFacts(ctx, g, repo)
	if err != nil {
		return nil, nil, err
	}

	target := fmt.Sprintf("%s/%s", repo.Owner, repo.Name)
	var results []Result
	for _, rule := range rules {
		if rule.Scope != ScopeRepository || rule.CheckRepo == nil {
			continue
		}
		outcome := rule.CheckRepo(facts)
		results = append(results, Result{Rule: rule, Target: target, Status: outcome.Status, Detail: outcome.Detail})
	}
	return results, facts, nil
}

// EvaluateOrganization collects facts for a single organization and evaluates
// the given rules against it. Only rules with Scope == ScopeOrganization are evaluated.
func EvaluateOrganization(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, rules []Rule) ([]Result, *OrganizationFacts, error) {
	facts, err := CollectOrganizationFacts(ctx, g, repo)
	if err != nil {
		return nil, nil, err
	}

	var results []Result
	for _, rule := range rules {
		if rule.Scope != ScopeOrganization || rule.CheckOrg == nil {
			continue
		}
		outcome := rule.CheckOrg(facts)
		results = append(results, Result{Rule: rule, Target: repo.Owner, Status: outcome.Status, Detail: outcome.Detail})
	}
	return results, facts, nil
}
