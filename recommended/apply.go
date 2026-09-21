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
	// DryRun reports that Applied reflects what would happen, not an actual change.
	DryRun bool
	Error  error
}

// ApplyRepository evaluates the given rules against a repository and applies
// the fix for every failing, fixable rule. Rules that already pass, are not
// fixable, or were skipped during evaluation are reported but not touched.
// When dryRun is true, no changes are made; Applied instead reports whether a
// fix would have been applied.
func ApplyRepository(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, rules []Rule, dryRun bool) ([]ApplyResult, error) {
	results, facts, err := EvaluateRepository(ctx, g, repo, rules)
	if err != nil {
		return nil, err
	}

	byID := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
	}

	out := make([]ApplyResult, 0, len(results))
	var rulesetResultIndexes []int
	var rulesetRuleIDs []string
	var reviewRulesetResultIndexes []int
	var reviewRulesetRuleIDs []string
	for _, res := range results {
		ar := ApplyResult{Result: res, DryRun: dryRun}
		if res.Status == StatusFail {
			rule := byID[res.Rule.ID]
			if rule.Fixable && isRulesetRemediationRule(rule.ID) && canRemediateRulesetRule(rule.ID, facts) {
				if dryRun {
					ar.Applied = true
				} else if rule.ID == "GSK111" && oneMemberRepository(facts) {
					reviewRulesetResultIndexes = append(reviewRulesetResultIndexes, len(out))
					reviewRulesetRuleIDs = append(reviewRulesetRuleIDs, rule.ID)
				} else {
					rulesetResultIndexes = append(rulesetResultIndexes, len(out))
					rulesetRuleIDs = append(rulesetRuleIDs, rule.ID)
				}
			} else if rule.Fixable && rule.ApplyRepo != nil {
				if dryRun {
					ar.Applied = true
				} else if err := rule.ApplyRepo(ctx, g, repo, facts); err != nil {
					ar.Error = fmt.Errorf("failed to apply fix for rule %s: %w", rule.ID, err)
				} else {
					ar.Applied = true
				}
			}
		}
		out = append(out, ar)
	}
	if len(rulesetRuleIDs) > 0 {
		if err := applyBranchProtectionRuleset(ctx, g, repo, facts, rulesetRuleIDs); err != nil {
			for _, index := range rulesetResultIndexes {
				out[index].Error = fmt.Errorf("failed to apply branch protection ruleset: %w", err)
			}
		} else {
			for _, index := range rulesetResultIndexes {
				out[index].Applied = true
			}
		}
	}
	if len(reviewRulesetRuleIDs) > 0 {
		if err := applyNamedBranchProtectionRuleset(ctx, g, repo, facts, branchProtectionReviewRulesetName, reviewRulesetRuleIDs, true); err != nil {
			for _, index := range reviewRulesetResultIndexes {
				out[index].Error = fmt.Errorf("failed to apply branch protection review ruleset: %w", err)
			}
		} else {
			for _, index := range reviewRulesetResultIndexes {
				out[index].Applied = true
			}
		}
	}
	return out, nil
}

// ApplyOrganization evaluates the given rules against an organization and
// applies the fix for every failing, fixable rule. When dryRun is true, no
// changes are made; Applied instead reports whether a fix would have been
// applied.
func ApplyOrganization(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, rules []Rule, dryRun bool) ([]ApplyResult, error) {
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
		ar := ApplyResult{Result: res, DryRun: dryRun}
		if res.Status == StatusFail {
			rule := byID[res.Rule.ID]
			if rule.Fixable && rule.ApplyOrg != nil {
				if dryRun {
					ar.Applied = true
				} else if err := rule.ApplyOrg(ctx, g, repo, facts); err != nil {
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
