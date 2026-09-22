package recommended

import (
	"context"
	"fmt"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

const branchProtectionRulesetName = "gh-secure-kit/branch-protection"
const branchProtectionReviewRulesetName = "gh-secure-kit/branch-protection-review"

// branchProtectionRulesetRemediation builds the repository-owned ruleset used
// by recommended apply. It only changes rules explicitly requested by failed
// recommendations and preserves every other rule from an existing ruleset.
type branchProtectionRulesetRemediation struct {
	name    string
	ruleset *github.RepositoryRuleset
}

func newBranchProtectionRulesetRemediation(facts *RepositoryFacts, existing *github.RepositoryRuleset) (*branchProtectionRulesetRemediation, error) {
	return newNamedBranchProtectionRulesetRemediation(facts, existing, branchProtectionRulesetName)
}

func newNamedBranchProtectionRulesetRemediation(facts *RepositoryFacts, existing *github.RepositoryRuleset, name string) (*branchProtectionRulesetRemediation, error) {
	if facts == nil || facts.Repo == nil || facts.Repo.GetDefaultBranch() == "" {
		return nil, fmt.Errorf("default branch is required to create a branch protection ruleset")
	}
	if existing != nil {
		if existing.Name != name {
			return nil, fmt.Errorf("refusing to modify ruleset %q", existing.Name)
		}
		if existing.Target == nil || *existing.Target != github.RulesetTargetBranch {
			return nil, fmt.Errorf("ruleset %q does not target branches", name)
		}
		if !rulesetTargetsBranch(existing.Conditions, facts.Repo.GetDefaultBranch()) {
			return nil, fmt.Errorf("ruleset %q does not target the default branch", name)
		}
		if existing.Rules == nil {
			existing.Rules = &github.RepositoryRulesetRules{}
		}
		// Ensure the managed ruleset is active so the applied rules actually
		// enforce protection; an evaluate/disabled ruleset would leave the
		// branch-protection checks failing after remediation.
		existing.Enforcement = github.RulesetEnforcementActive
		return &branchProtectionRulesetRemediation{name: name, ruleset: existing}, nil
	}

	target := github.RulesetTargetBranch
	enforcement := github.RulesetEnforcementActive
	return &branchProtectionRulesetRemediation{name: name, ruleset: &github.RepositoryRuleset{
		Name:        name,
		Target:      &target,
		Enforcement: enforcement,
		Conditions: &github.RepositoryRulesetConditions{
			RefName: &github.RepositoryRulesetRefConditionParameters{
				Include: []string{"~DEFAULT_BRANCH"},
				Exclude: []string{},
			},
		},
		Rules: &github.RepositoryRulesetRules{},
	}}, nil
}

// Apply adds the minimum rule changes required to remediate ruleID. GSK110 adds
// pull-request protection; every additional requirement needs its own failed,
// selected recommendation.
func (r *branchProtectionRulesetRemediation) Apply(ruleID string, facts *RepositoryFacts) error {
	switch ruleID {
	case "GSK110":
		pullRequestRule(r.ruleset)
	case "GSK117":
		r.ruleset.Rules.NonFastForward = &github.EmptyRuleParameters{}
	case "GSK111":
		if pullRequestRule(r.ruleset).RequiredApprovingReviewCount < 1 {
			r.ruleset.Rules.PullRequest.RequiredApprovingReviewCount = 1
		}
	case "GSK112":
		if pullRequestRule(r.ruleset).RequiredApprovingReviewCount < 2 {
			r.ruleset.Rules.PullRequest.RequiredApprovingReviewCount = 2
		}
	case "GSK113":
		pullRequestRule(r.ruleset).DismissStaleReviewsOnPush = true
	case "GSK114":
		pullRequestRule(r.ruleset).RequireCodeOwnerReview = true
	case "GSK115":
		checks := branchProtectionStatusChecks(facts)
		if len(checks) == 0 && r.ruleset.Rules.RequiredStatusChecks != nil {
			checks = append(checks, r.ruleset.Rules.RequiredStatusChecks.RequiredStatusChecks...)
		}
		if r.ruleset.Rules.RequiredStatusChecks == nil {
			r.ruleset.Rules.RequiredStatusChecks = &github.RequiredStatusChecksRuleParameters{RequiredStatusChecks: nonNilStatusChecks(checks)}
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
	return true
}

func oneMemberRepository(facts *RepositoryFacts) bool {
	maximum, known := maximumReviewCount(facts)
	return known && maximum == 0
}

func nonNilStatusChecks(checks []*github.RuleStatusCheck) []*github.RuleStatusCheck {
	if checks == nil {
		return []*github.RuleStatusCheck{}
	}
	return checks
}

// applyBranchProtectionRuleset persists all requested branch-protection fixes
// as a single create or update operation.
func applyBranchProtectionRuleset(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, facts *RepositoryFacts, ruleIDs []string) error {
	return applyNamedBranchProtectionRuleset(ctx, g, repo, facts, branchProtectionRulesetName, ruleIDs, false)
}

func applyNamedBranchProtectionRuleset(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, facts *RepositoryFacts, name string, ruleIDs []string, bypassOwner bool) error {
	if len(ruleIDs) == 0 {
		return nil
	}
	existing, err := gh.FindRepositoryRulesetByName(ctx, g, repo, name, false)
	if err != nil {
		return fmt.Errorf("failed to find ruleset %q: %w", name, err)
	}
	if existing != nil {
		if existing.GetID() == 0 {
			return fmt.Errorf("ruleset %q has no ID", name)
		}
		existing, err = gh.GetRepositoryRuleset(ctx, g, repo, existing.GetID(), false)
		if err != nil {
			return fmt.Errorf("failed to get ruleset %q: %w", name, err)
		}
	}
	remediation, err := newNamedBranchProtectionRulesetRemediation(facts, existing, name)
	if err != nil {
		return err
	}
	for _, id := range ruleIDs {
		if err := remediation.Apply(id, facts); err != nil {
			return err
		}
	}
	if bypassOwner {
		if reviewRulesetHasUnexpectedRules(remediation.Ruleset().Rules) {
			return fmt.Errorf("refusing to add owner bypass: ruleset %q contains rules other than pull request review", name)
		}
		if err := addOwnerBypassActor(remediation.Ruleset(), facts); err != nil {
			return err
		}
	}
	if existing == nil {
		if _, err := gh.CreateRepositoryRuleset(ctx, g, repo, remediation.Ruleset()); err != nil {
			return fmt.Errorf("failed to create ruleset %q: %w", name, err)
		}
		return nil
	}
	if _, err := gh.UpdateRepositoryRuleset(ctx, g, repo, existing.GetID(), remediation.UpdatePayload()); err != nil {
		return fmt.Errorf("failed to update ruleset %q: %w", name, err)
	}
	return nil
}

// reviewRulesetHasUnexpectedRules reports whether the ruleset that is expected
// to hold only the isolated pull-request review requirement carries any other
// rule type. The owner bypass added for a single-member repository exempts the
// owner from every rule in the ruleset, so the caller must refuse to attach it
// when a ruleset adopted by name contains protections the tool does not manage.
func reviewRulesetHasUnexpectedRules(rules *github.RepositoryRulesetRules) bool {
	if rules == nil {
		return false
	}
	return rules.Creation != nil ||
		rules.Update != nil ||
		rules.Deletion != nil ||
		rules.RequiredLinearHistory != nil ||
		rules.MergeQueue != nil ||
		rules.RequiredDeployments != nil ||
		rules.RequiredSignatures != nil ||
		rules.RequiredStatusChecks != nil ||
		rules.NonFastForward != nil ||
		rules.CommitMessagePattern != nil ||
		rules.CommitAuthorEmailPattern != nil ||
		rules.CommitterEmailPattern != nil ||
		rules.BranchNamePattern != nil ||
		rules.TagNamePattern != nil ||
		rules.Workflows != nil ||
		rules.CodeScanning != nil ||
		rules.CopilotCodeReview != nil ||
		rules.FileExtensionRestriction != nil ||
		rules.FilePathRestriction != nil ||
		rules.MaxFilePathLength != nil ||
		rules.MaxFileSize != nil ||
		rules.RepositoryCreate != nil ||
		rules.RepositoryDelete != nil ||
		rules.RepositoryName != nil ||
		rules.RepositoryTransfer != nil ||
		rules.RepositoryVisibility != nil
}

func addOwnerBypassActor(ruleset *github.RepositoryRuleset, facts *RepositoryFacts) error {
	owner := facts.Repo.GetOwner()
	if owner == nil || owner.GetID() == 0 {
		return fmt.Errorf("repository owner ID is required for review ruleset bypass")
	}
	// The bypass actor below is serialized as a "User" actor, which GitHub only
	// accepts for a user account. An organization owner ID would be rejected, so
	// refuse rather than emit an invalid payload even if a caller reaches here
	// without going through oneMemberRepository.
	if owner.GetType() != "User" {
		return fmt.Errorf("owner bypass is only supported for user-owned repositories")
	}
	const userActorType github.BypassActorType = "User"
	for _, actor := range ruleset.BypassActors {
		if actor.GetActorID() == owner.GetID() && actor.GetActorType() != nil && *actor.GetActorType() == userActorType {
			actor.BypassMode = github.Ptr(github.BypassModeExempt)
			return nil
		}
	}
	ruleset.BypassActors = append(ruleset.BypassActors, &github.BypassActor{
		ActorID:    github.Ptr(owner.GetID()),
		ActorType:  github.Ptr(userActorType),
		BypassMode: github.Ptr(github.BypassModeExempt),
	})
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
