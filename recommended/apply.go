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
	// The owner-exempt review ruleset for a single-member repository's GSK111 is
	// only safe when the default branch already has a pull request requirement the
	// owner cannot bypass, or when GSK110 is being applied in this same run to
	// establish that protection. Without it, exempting the sole owner would leave
	// the branch unprotected.
	gsk110WillApply := false
	for _, res := range results {
		if res.Status != StatusFail {
			continue
		}
		rule := byID[res.Rule.ID]
		if rule.ID == "GSK110" && rule.Fixable && isRulesetRemediationRule(rule.ID) && canRemediateRulesetRule(rule.ID, facts) {
			gsk110WillApply = true
		}
	}
	hasEnforcedPR := defaultBranchHasEnforcedPullRequest(facts)
	reviewPrereqMet := hasEnforcedPR || gsk110WillApply
	// When the prerequisite is only met because GSK110 is applied in this run, the
	// review ruleset must not be created unless that main ruleset succeeds.
	reviewDependsOnMain := !hasEnforcedPR
	for _, res := range results {
		ar := ApplyResult{Result: res, DryRun: dryRun}
		if res.Status == StatusFail {
			rule := byID[res.Rule.ID]
			if rule.Fixable && isRulesetRemediationRule(rule.ID) && canRemediateRulesetRule(rule.ID, facts) {
				if rule.ID == "GSK111" && oneMemberRepository(facts) {
					if !reviewPrereqMet {
						ar.Error = fmt.Errorf("cannot safely apply %s on a single-member repository without owner-enforced pull request protection: include GSK110 in this run or configure branch protection that requires pull requests", rule.ID)
					} else if dryRun {
						ar.Applied = true
					} else {
						reviewRulesetResultIndexes = append(reviewRulesetResultIndexes, len(out))
						reviewRulesetRuleIDs = append(reviewRulesetRuleIDs, rule.ID)
					}
				} else if dryRun {
					ar.Applied = true
				} else {
					rulesetResultIndexes = append(rulesetResultIndexes, len(out))
					rulesetRuleIDs = append(rulesetRuleIDs, rule.ID)
				}
			} else if rule.Fixable && isRulesetRemediationRule(rule.ID) && !canRemediateRulesetRule(rule.ID, facts) {
				ar.Error = fmt.Errorf("cannot safely apply %s: the number of members who can approve pull requests is unknown, so requiring approvals could leave pull requests unmergeable", rule.ID)
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
	var mainErr error
	if len(rulesetRuleIDs) > 0 {
		mainErr = applyBranchProtectionRuleset(ctx, g, repo, facts, rulesetRuleIDs)
		if mainErr != nil {
			for _, index := range rulesetResultIndexes {
				out[index].Error = fmt.Errorf("failed to apply branch protection ruleset: %w", mainErr)
			}
		} else {
			for _, index := range rulesetResultIndexes {
				out[index].Applied = true
			}
		}
	}
	if len(reviewRulesetRuleIDs) > 0 {
		if reviewDependsOnMain && mainErr != nil {
			for _, index := range reviewRulesetResultIndexes {
				out[index].Error = fmt.Errorf("skipped branch protection review ruleset because the branch protection ruleset failed: %w", mainErr)
			}
		} else if err := applyNamedBranchProtectionRuleset(ctx, g, repo, facts, branchProtectionReviewRulesetName, reviewRulesetRuleIDs, true); err != nil {
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
