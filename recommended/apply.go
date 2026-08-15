package recommended

import (
	"context"
	"fmt"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

// ApplyResult is the outcome of attempting to apply a fix for a single rule.
type ApplyResult struct {
	Result
	Applied bool
	Error   error
}

// ApplyRepository evaluates the given rules against a repository and applies
// the fix for every failing, fixable rule. Rules that already pass, are not
// fixable, or were skipped during evaluation are reported but not touched.
func ApplyRepository(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, rules []Rule) ([]ApplyResult, error) {
	results, facts, err := EvaluateRepository(ctx, g, repo, rules)
	if err != nil {
		return nil, err
	}

	byID := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
	}

	out := make([]ApplyResult, 0, len(results))
	for _, res := range results {
		ar := ApplyResult{Result: res}
		if res.Status == StatusFail {
			rule := byID[res.Rule.ID]
			if rule.Fixable && rule.ApplyRepo != nil {
				if err := rule.ApplyRepo(ctx, g, repo, facts); err != nil {
					ar.Error = fmt.Errorf("failed to apply fix for rule %s: %w", rule.ID, err)
				} else {
					ar.Applied = true
				}
			}
		}
		out = append(out, ar)
	}
	return out, nil
}

// ApplyOrganization evaluates the given rules against an organization and
// applies the fix for every failing, fixable rule.
func ApplyOrganization(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, rules []Rule) ([]ApplyResult, error) {
	results, facts, err := EvaluateOrganization(ctx, g, repo, rules)
	if err != nil {
		return nil, err
	}

	byID := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
	}

	out := make([]ApplyResult, 0, len(results))
	for _, res := range results {
		ar := ApplyResult{Result: res}
		if res.Status == StatusFail {
			rule := byID[res.Rule.ID]
			if rule.Fixable && rule.ApplyOrg != nil {
				if err := rule.ApplyOrg(ctx, g, repo, facts); err != nil {
					ar.Error = fmt.Errorf("failed to apply fix for rule %s: %w", rule.ID, err)
				} else {
					ar.Applied = true
				}
			}
		}
		out = append(out, ar)
	}
	return out, nil
}
