package recommended

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

func init() {
	registerBranchProtectionRules()
}

// activeRulesetProtectsDefaultBranch reports whether an active branch ruleset
// actually targets (and imposes at least one rule on) the repository's default
// branch. A ruleset that only targets other branches, or that carries no rules,
// does not count as default-branch protection.
func activeRulesetProtectsDefaultBranch(f *RepositoryFacts) bool {
	for _, rs := range activeDefaultBranchRulesets(f) {
		if gh.HasAnyRulesetRule(rs.Rules) {
			return true
		}
	}
	return false
}

// activeDefaultBranchRulesets returns active branch rulesets that apply to the
// repository's default branch, including rulesets with no branch-protection rule.
// It returns no candidates while the ruleset state is unknown, so callers skip
// rather than evaluate a partial ruleset slice that could change the effective
// protection once the missing details are read.
func activeDefaultBranchRulesets(f *RepositoryFacts) []*github.RepositoryRuleset {
	if f == nil || f.Repo == nil || !f.RulesetsKnown {
		return nil
	}
	branch := f.Repo.GetDefaultBranch()
	var result []*github.RepositoryRuleset
	for _, rs := range f.Rulesets {
		if rs.GetEnforcement() != "active" {
			continue
		}
		if t := rs.Target; t != nil && *t != github.RulesetTargetBranch {
			continue
		}
		if rulesetTargetsBranch(rs.Conditions, branch) {
			result = append(result, rs)
		}
	}
	return result
}

// combinedRequirement decides a boolean branch-protection requirement whose
// effective value is the union (most restrictive) of legacy branch protection and
// every applicable active ruleset. satisfied reports whether a readable source
// already enforces the requirement; because overlapping rules combine into the
// most restrictive setting, a satisfied requirement is authoritative even when
// another source could not be read. When no readable source enforces it, the
// requirement is only failed once both the legacy protection and ruleset states
// are known and the default branch has some protection, so an unreadable source
// or a wholly unprotected branch is not misreported as a specific
// misconfiguration (GSK110 reports the missing protection instead).
func combinedRequirement(f *RepositoryFacts, satisfied bool, passDetail, failDetail string) Outcome {
	if satisfied {
		return Pass(passDetail)
	}
	if !f.ProtectionKnown || !f.RulesetsKnown {
		return Skip("could not determine branch protection or ruleset status for the default branch")
	}
	if f.Protection == nil && !activeRulesetProtectsDefaultBranch(f) {
		return Skip("no branch protection or active ruleset is configured on the default branch")
	}
	return Fail(failDetail)
}

// combinedReviewCount returns the effective required approving review count for
// the default branch: the maximum required by legacy protection and by any
// applicable active ruleset, because overlapping rules combine into the most
// restrictive setting.
func combinedReviewCount(f *RepositoryFacts) int {
	count := 0
	if f.Protection != nil {
		count = f.Protection.GetRequiredPullRequestReviews().GetRequiredApprovingReviewCount()
	}
	for _, review := range rulesetPullRequestRules(f) {
		if review.RequiredApprovingReviewCount > count {
			count = review.RequiredApprovingReviewCount
		}
	}
	return count
}

// hasPullRequestReviewConfig reports whether any readable source configures pull
// request reviews on the default branch, used to distinguish a missing
// reviews block from an explicit zero-review requirement.
func hasPullRequestReviewConfig(f *RepositoryFacts) bool {
	if f.Protection != nil && f.Protection.GetRequiredPullRequestReviews() != nil {
		return true
	}
	return len(rulesetPullRequestRules(f)) > 0
}

// combinedRequiredStatusCheckCount returns the number of distinct required status
// checks enforced on the default branch across legacy protection and every
// applicable active ruleset. Checks are keyed by context and integration so the
// same check enforced by two sources is counted once; entries without a context
// are ignored.
func combinedRequiredStatusCheckCount(f *RepositoryFacts) int {
	seen := map[string]struct{}{}
	add := func(context string, integration int64) {
		if context == "" {
			return
		}
		seen[fmt.Sprintf("%s\x00%d", context, integration)] = struct{}{}
	}
	if f.Protection != nil {
		if checks := f.Protection.GetRequiredStatusChecks(); checks != nil {
			if checks.Checks != nil && len(*checks.Checks) > 0 {
				for _, c := range *checks.Checks {
					add(c.GetContext(), c.GetAppID())
				}
			} else {
				// Contexts is the deprecated projection of the same checks; use it
				// only when the newer Checks representation is absent or empty so a
				// check present in both is not counted twice.
				for _, context := range checks.GetContexts() {
					add(context, 0)
				}
			}
		}
	}
	for _, params := range rulesetStatusCheckRules(f) {
		for _, c := range params.RequiredStatusChecks {
			add(c.GetContext(), c.GetIntegrationID())
		}
	}
	return len(seen)
}

func rulesetPullRequestRules(f *RepositoryFacts) []*github.PullRequestRuleParameters {
	var result []*github.PullRequestRuleParameters
	for _, rs := range activeDefaultBranchRulesets(f) {
		if rs.Rules != nil && rs.Rules.PullRequest != nil {
			result = append(result, rs.Rules.PullRequest)
		}
	}
	return result
}

func rulesetStatusCheckRules(f *RepositoryFacts) []*github.RequiredStatusChecksRuleParameters {
	var result []*github.RequiredStatusChecksRuleParameters
	for _, rs := range activeDefaultBranchRulesets(f) {
		if rs.Rules != nil && rs.Rules.RequiredStatusChecks != nil {
			result = append(result, rs.Rules.RequiredStatusChecks)
		}
	}
	return result
}

// rulesetTargetsBranch reports whether a ruleset's ref-name conditions include
// the given branch and do not exclude it.
func rulesetTargetsBranch(conditions *github.RepositoryRulesetConditions, branch string) bool {
	if conditions == nil || conditions.RefName == nil {
		return false
	}
	ref := conditions.RefName
	for _, pattern := range ref.Exclude {
		if matchRefPattern(pattern, branch) {
			return false
		}
	}
	for _, pattern := range ref.Include {
		if matchRefPattern(pattern, branch) {
			return true
		}
	}
	return false
}

// matchRefPattern reports whether a ruleset ref-name pattern matches the given
// branch. It understands the "~ALL" and "~DEFAULT_BRANCH" tokens (the branch is
// always the default branch here) and matches fnmatch-style patterns against the
// full "refs/heads/<branch>" ref.
func matchRefPattern(pattern, branch string) bool {
	switch pattern {
	case "~ALL", "~DEFAULT_BRANCH":
		return true
	}
	re, err := fnmatchToRegexp(pattern)
	if err != nil {
		return false
	}
	return re.MatchString("refs/heads/" + branch)
}

// fnmatchToRegexp converts a GitHub ruleset fnmatch pattern into a regexp. "**"
// matches across path separators, "*" matches within a segment, and "?" matches
// a single non-separator character; every other character is matched literally.
func fnmatchToRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

func registerBranchProtectionRules() {
	register(Rule{
		ID: "GSK110", GHQRID: "repo-bp-001", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityCritical, Title: "No branch protection configured on default branch", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.Protection != nil || activeRulesetProtectsDefaultBranch(f) {
				return Pass("default branch is protected by a branch protection rule or ruleset")
			}
			// Only fail when both protection sources were determined; otherwise
			// the branch may be protected in a way that could not be read.
			if !f.ProtectionKnown || !f.RulesetsKnown {
				return Skip("could not determine branch protection or ruleset status for the default branch")
			}
			return Fail("default branch has no branch protection rule or ruleset")
		},
	})

	register(Rule{
		ID: "GSK111", GHQRID: "repo-bp-002", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityCritical, Title: "No approving reviews required before merge", Fixable: true,
		CheckRepo: checkRequiredReviews(0, "no approving reviews are required before merge"),
	})

	register(Rule{
		ID: "GSK112", GHQRID: "repo-bp-003", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityMedium, Title: "Only 1 approving review required", Fixable: true,
		CheckRepo: checkRequiredReviews(1, "only 1 approving review is required"),
	})

	register(Rule{
		ID: "GSK113", GHQRID: "repo-bp-004", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityHigh, Title: "Stale reviews not dismissed on new commits", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			// Effective value is the union of legacy protection and every
			// applicable active ruleset, so the requirement is met when any
			// readable source enables it.
			satisfied := false
			if f.Protection != nil {
				satisfied = f.Protection.GetRequiredPullRequestReviews().GetDismissStaleReviews()
			}
			for _, review := range rulesetPullRequestRules(f) {
				if review.DismissStaleReviewsOnPush {
					satisfied = true
				}
			}
			return combinedRequirement(f, satisfied,
				"stale reviews are dismissed on new commits",
				"stale reviews are not dismissed on new commits")
		},
	})

	register(Rule{
		ID: "GSK114", GHQRID: "repo-bp-005", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityMedium, Title: "Code owner review not required", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			satisfied := false
			if f.Protection != nil {
				satisfied = f.Protection.GetRequiredPullRequestReviews().GetRequireCodeOwnerReviews()
			}
			for _, review := range rulesetPullRequestRules(f) {
				if review.RequireCodeOwnerReview {
					satisfied = true
				}
			}
			return combinedRequirement(f, satisfied,
				"code owner review is required",
				"code owner review is not required")
		},
	})

	register(Rule{
		ID: "GSK115", GHQRID: "repo-bp-007", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityHigh, Title: "Strict status checks not enabled", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			satisfied := false
			if f.Protection != nil {
				if checks := f.Protection.GetRequiredStatusChecks(); checks != nil {
					satisfied = checks.Strict
				}
			}
			for _, check := range rulesetStatusCheckRules(f) {
				if check.StrictRequiredStatusChecksPolicy {
					satisfied = true
				}
			}
			return combinedRequirement(f, satisfied,
				"required status checks require branches to be up to date",
				"required status checks do not require branches to be up to date")
		},
	})

	register(Rule{
		ID: "GSK116", GHQRID: "repo-bp-009", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityHigh, Title: "No required status checks configured",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			count := combinedRequiredStatusCheckCount(f)
			return combinedRequirement(f, count > 0,
				fmt.Sprintf("%d required status checks configured", count),
				"no required status checks are configured; CI failures do not block merges")
		},
	})

	register(Rule{
		ID: "GSK117", GHQRID: "repo-bp-010", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityCritical, Title: "Force pushes allowed on protected branch", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			// Legacy protection satisfies the rule only when it is present and does
			// not allow force pushes; an applicable ruleset satisfies it with a
			// non-fast-forward rule.
			satisfied := f.Protection != nil && !f.Protection.GetAllowForcePushes().GetEnabled()
			for _, rs := range activeDefaultBranchRulesets(f) {
				if rs.Rules != nil && rs.Rules.NonFastForward != nil {
					satisfied = true
				}
			}
			return combinedRequirement(f, satisfied,
				"force pushes are disabled on the protected branch",
				"force pushes are allowed on the protected branch")
		},
	})

	register(Rule{
		ID: "GSK118", GHQRID: "repo-bp-012", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityMedium, Title: "Signed commits not required", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			satisfied := false
			if f.Protection != nil {
				satisfied = f.Protection.GetRequiredSignatures().GetEnabled()
			}
			for _, rs := range activeDefaultBranchRulesets(f) {
				if rs.Rules != nil && rs.Rules.RequiredSignatures != nil {
					satisfied = true
				}
			}
			return combinedRequirement(f, satisfied,
				"signed commits are required",
				"signed commits are not required")
		},
	})
}

// checkRequiredReviews returns a CheckRepo function that fails when the effective
// required approving review count equals expected. The effective count is the
// union (maximum) of legacy protection and every applicable active ruleset, so a
// weak legacy setting no longer hides a stricter ruleset (or vice versa). Using
// equality (rather than a threshold) keeps each rule aligned with its title and
// avoids GSK111/GSK112 overlapping at a count of 0. An absent required-reviews
// block is treated as a count of 0 so only the zero-review rule (GSK111) reports
// it.
func checkRequiredReviews(expected int, failDetail string) RepositoryCheckFunc {
	return func(f *RepositoryFacts) Outcome {
		count := combinedReviewCount(f)
		if count > expected {
			// The union only raises the count, so a readable source already above
			// the failing threshold is authoritative even under unknowns.
			return Pass(fmt.Sprintf("%d approving reviews are required", count))
		}
		if !f.ProtectionKnown || !f.RulesetsKnown {
			return Skip("could not determine branch protection or ruleset status for the default branch")
		}
		if f.Protection == nil && !activeRulesetProtectsDefaultBranch(f) {
			return Skip("no branch protection or active ruleset is configured on the default branch")
		}
		if count != expected {
			return Pass(fmt.Sprintf("%d approving reviews are required", count))
		}
		if !hasPullRequestReviewConfig(f) {
			return Fail(fmt.Sprintf("%s (pull request reviews are not configured)", failDetail))
		}
		return Fail(fmt.Sprintf("%s (required: %d)", failDetail, count))
	}
}
