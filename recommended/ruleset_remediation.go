package recommended

import (
	"context"
	"fmt"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

const branchProtectionRulesetName = "gh-secure-kit/branch-protection"

// branchProtectionRulesetRemediation builds the repository-owned ruleset used
// by recommended apply. It only changes rules explicitly requested by failed
// recommendations and preserves every other rule from an existing ruleset.
type branchProtectionRulesetRemediation struct {
	ruleset *github.RepositoryRuleset
}

func newBranchProtectionRulesetRemediation(facts *RepositoryFacts, existing *github.RepositoryRuleset) (*branchProtectionRulesetRemediation, error) {
	if facts == nil || facts.Repo == nil || facts.Repo.GetDefaultBranch() == "" {
		return nil, fmt.Errorf("default branch is required to create a branch protection ruleset")
	}
	if existing != nil {
		if existing.Name != branchProtectionRulesetName {
			return nil, fmt.Errorf("refusing to modify ruleset %q", existing.Name)
		}
		if existing.Target == nil || *existing.Target != github.RulesetTargetBranch {
			return nil, fmt.Errorf("ruleset %q does not target branches", branchProtectionRulesetName)
		}
		if !rulesetTargetsBranch(existing.Conditions, facts.Repo.GetDefaultBranch()) {
			return nil, fmt.Errorf("ruleset %q does not target the default branch", branchProtectionRulesetName)
		}
		if existing.Rules == nil {
			existing.Rules = &github.RepositoryRulesetRules{}
		}
		// Ensure the managed ruleset is active so the applied rules actually
		// enforce protection; an evaluate/disabled ruleset would leave the
		// branch-protection checks failing after remediation.
		existing.Enforcement = github.RulesetEnforcementActive
		return &branchProtectionRulesetRemediation{ruleset: existing}, nil
	}

	target := github.RulesetTargetBranch
	enforcement := github.RulesetEnforcementActive
	return &branchProtectionRulesetRemediation{ruleset: &github.RepositoryRuleset{
		Name:        branchProtectionRulesetName,
		Target:      &target,
		Enforcement: enforcement,
		Conditions: &github.RepositoryRulesetConditions{
			RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"~DEFAULT_BRANCH"}},
		},
		Rules: &github.RepositoryRulesetRules{},
	}}, nil
}

// Apply adds the minimum rule changes required to remediate ruleID. GSK110 is
// deliberately limited to non-fast-forward protection; the remaining settings
// require their own failing recommendation before they are added.
func (r *branchProtectionRulesetRemediation) Apply(ruleID string, facts *RepositoryFacts) error {
	switch ruleID {
	case "GSK110", "GSK117":
		r.ruleset.Rules.NonFastForward = &github.EmptyRuleParameters{}
	case "GSK111", "GSK112":
		pullRequestRule(r.ruleset).RequiredApprovingReviewCount = 2
	case "GSK113":
		pullRequestRule(r.ruleset).DismissStaleReviewsOnPush = true
	case "GSK114":
		pullRequestRule(r.ruleset).RequireCodeOwnerReview = true
	case "GSK115":
		checks := branchProtectionStatusChecks(facts)
		if len(checks) == 0 && r.ruleset.Rules.RequiredStatusChecks != nil {
			checks = append(checks, r.ruleset.Rules.RequiredStatusChecks.RequiredStatusChecks...)
		}
		if len(checks) == 0 {
			return fmt.Errorf("cannot make status checks strict without configured checks")
		}
		if r.ruleset.Rules.RequiredStatusChecks == nil {
			r.ruleset.Rules.RequiredStatusChecks = &github.RequiredStatusChecksRuleParameters{RequiredStatusChecks: checks}
		}
		r.ruleset.Rules.RequiredStatusChecks.StrictRequiredStatusChecksPolicy = true
	case "GSK118":
		r.ruleset.Rules.RequiredSignatures = &github.EmptyRuleParameters{}
	default:
		return fmt.Errorf("rule %s cannot be remediated with a ruleset", ruleID)
	}
	return nil
}

func (r *branchProtectionRulesetRemediation) Ruleset() *github.RepositoryRuleset {
	return r.ruleset
}

// UpdatePayload removes server-managed fields before sending an existing
// ruleset back to GitHub while retaining user-configurable fields and rules.
func (r *branchProtectionRulesetRemediation) UpdatePayload() *github.RepositoryRuleset {
	payload := *r.ruleset
	payload.ID = nil
	payload.Source = ""
	payload.SourceType = nil
	payload.CurrentUserCanBypass = nil
	payload.NodeID = nil
	payload.Links = nil
	payload.UpdatedAt = nil
	payload.CreatedAt = nil
	return &payload
}

func isRulesetRemediationRule(id string) bool {
	switch id {
	case "GSK110", "GSK111", "GSK112", "GSK113", "GSK114", "GSK115", "GSK117", "GSK118":
		return true
	default:
		return false
	}
}

func canRemediateRulesetRule(id string, facts *RepositoryFacts) bool {
	return id != "GSK115" || len(branchProtectionStatusChecks(facts)) > 0
}

// applyBranchProtectionRuleset persists all requested branch-protection fixes
// as a single create or update operation.
func applyBranchProtectionRuleset(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, facts *RepositoryFacts, ruleIDs []string) error {
	if len(ruleIDs) == 0 {
		return nil
	}
	existing, err := gh.FindRepositoryRulesetByName(ctx, g, repo, branchProtectionRulesetName, false)
	if err != nil {
		return fmt.Errorf("failed to find ruleset %q: %w", branchProtectionRulesetName, err)
	}
	if existing != nil {
		if existing.GetID() == 0 {
			return fmt.Errorf("ruleset %q has no ID", branchProtectionRulesetName)
		}
		existing, err = gh.GetRepositoryRuleset(ctx, g, repo, existing.GetID(), false)
		if err != nil {
			return fmt.Errorf("failed to get ruleset %q: %w", branchProtectionRulesetName, err)
		}
	}
	remediation, err := newBranchProtectionRulesetRemediation(facts, existing)
	if err != nil {
		return err
	}
	for _, id := range ruleIDs {
		if err := remediation.Apply(id, facts); err != nil {
			return err
		}
	}
	if existing == nil {
		if _, err := gh.CreateRepositoryRuleset(ctx, g, repo, remediation.Ruleset()); err != nil {
			return fmt.Errorf("failed to create ruleset %q: %w", branchProtectionRulesetName, err)
		}
		return nil
	}
	if _, err := gh.UpdateRepositoryRuleset(ctx, g, repo, existing.GetID(), remediation.UpdatePayload()); err != nil {
		return fmt.Errorf("failed to update ruleset %q: %w", branchProtectionRulesetName, err)
	}
	return nil
}

func branchProtectionStatusChecks(facts *RepositoryFacts) []*github.RuleStatusCheck {
	seen := make(map[string]struct{})
	var checks []*github.RuleStatusCheck
	add := func(context string, integrationID int64) {
		if context == "" {
			return
		}
		key := fmt.Sprintf("%s\x00%d", context, integrationID)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		check := &github.RuleStatusCheck{Context: context}
		if integrationID != 0 {
			check.IntegrationID = github.Ptr(integrationID)
		}
		checks = append(checks, check)
	}
	if facts.Protection != nil {
		if statusChecks := facts.Protection.GetRequiredStatusChecks(); statusChecks != nil {
			if statusChecks.Checks != nil && len(*statusChecks.Checks) > 0 {
				for _, check := range *statusChecks.Checks {
					add(check.GetContext(), check.GetAppID())
				}
			} else {
				for _, context := range statusChecks.GetContexts() {
					add(context, 0)
				}
			}
		}
	}
	for _, params := range rulesetStatusCheckRules(facts) {
		for _, check := range params.RequiredStatusChecks {
			add(check.GetContext(), check.GetIntegrationID())
		}
	}
	return checks
}

func pullRequestRule(ruleset *github.RepositoryRuleset) *github.PullRequestRuleParameters {
	if ruleset.Rules.PullRequest == nil {
		ruleset.Rules.PullRequest = &github.PullRequestRuleParameters{}
	}
	return ruleset.Rules.PullRequest
}
