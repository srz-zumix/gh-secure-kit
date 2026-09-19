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

// rulesetFallback returns the active rulesets that protect the default branch
// when legacy branch protection is absent. ok is false, with the Skip outcome to
// return, when the branch-protection facts are incomplete (either the legacy
// protection or the ruleset state is unknown) or when no active ruleset targets
// the default branch. In those cases a missing rule must not be treated as a
// known absence, so the caller returns the Skip outcome instead of evaluating
// the rulesets.
func rulesetFallback(f *RepositoryFacts) ([]*github.RepositoryRuleset, Outcome, bool) {
	if !f.ProtectionKnown || !f.RulesetsKnown {
		return nil, Skip("could not determine branch protection or ruleset status for the default branch"), false
	}
	rulesets := activeDefaultBranchRulesets(f)
	if len(rulesets) == 0 {
		return nil, Skip("no active branch ruleset targets the default branch"), false
	}
	return rulesets, Outcome{}, true
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
		Category: "branch_protection", Severity: SeverityCritical, Title: "No branch protection configured on default branch",
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
		Category: "branch_protection", Severity: SeverityCritical, Title: "No approving reviews required before merge",
		CheckRepo: checkRequiredReviews(0, "no approving reviews are required before merge"),
	})

	register(Rule{
		ID: "GSK112", GHQRID: "repo-bp-003", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityMedium, Title: "Only 1 approving review required",
		CheckRepo: checkRequiredReviews(1, "only 1 approving review is required"),
	})

	register(Rule{
		ID: "GSK113", GHQRID: "repo-bp-004", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityHigh, Title: "Stale reviews not dismissed on new commits",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.Protection == nil {
				if _, skip, ok := rulesetFallback(f); !ok {
					return skip
				}
				// Overlapping active rulesets combine into the most restrictive
				// setting, so the requirement is met if any applicable review rule
				// enables it. An applicable ruleset with no pull request rule is a
				// known absence of the requirement.
				for _, review := range rulesetPullRequestRules(f) {
					if review.DismissStaleReviewsOnPush {
						return Pass("stale reviews are dismissed on new commits")
					}
				}
				return Fail("stale reviews are not dismissed on new commits")
			}
			if f.Protection.GetRequiredPullRequestReviews().GetDismissStaleReviews() {
				return Pass("stale reviews are dismissed on new commits")
			}
			return Fail("stale reviews are not dismissed on new commits")
		},
	})

	register(Rule{
		ID: "GSK114", GHQRID: "repo-bp-005", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityMedium, Title: "Code owner review not required",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.Protection == nil {
				if _, skip, ok := rulesetFallback(f); !ok {
					return skip
				}
				// Overlapping active rulesets combine into the most restrictive
				// setting, so code owner review is required if any applicable review
				// rule requires it. An applicable ruleset with no pull request rule
				// is a known absence of the requirement.
				for _, review := range rulesetPullRequestRules(f) {
					if review.RequireCodeOwnerReview {
						return Pass("code owner review is required")
					}
				}
				return Fail("code owner review is not required")
			}
			if f.Protection.GetRequiredPullRequestReviews().GetRequireCodeOwnerReviews() {
				return Pass("code owner review is required")
			}
			return Fail("code owner review is not required")
		},
	})

	register(Rule{
		ID: "GSK115", GHQRID: "repo-bp-007", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityHigh, Title: "Strict status checks not enabled",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.Protection == nil {
				if _, skip, ok := rulesetFallback(f); !ok {
					return skip
				}
				// Overlapping active rulesets combine into the most restrictive
				// setting, so strict checks are enabled if any applicable status
				// check rule enables them. An applicable ruleset with no status
				// check rule is a known absence.
				for _, check := range rulesetStatusCheckRules(f) {
					if check.StrictRequiredStatusChecksPolicy {
						return Pass("required status checks require branches to be up to date")
					}
				}
				return Fail("required status checks do not require branches to be up to date")
			}
			checks := f.Protection.GetRequiredStatusChecks()
			if checks == nil {
				return Fail("no required status checks are configured")
			}
			if checks.Strict {
				return Pass("required status checks require branches to be up to date")
			}
			return Fail("required status checks do not require branches to be up to date")
		},
	})

	register(Rule{
		ID: "GSK116", GHQRID: "repo-bp-009", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityHigh, Title: "No required status checks configured",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.Protection == nil {
				if _, skip, ok := rulesetFallback(f); !ok {
					return skip
				}
				// Overlapping active rulesets combine their required status checks,
				// so count them across every applicable rule. An applicable ruleset
				// with no configured check is a known absence.
				count := 0
				for _, check := range rulesetStatusCheckRules(f) {
					count += len(check.RequiredStatusChecks)
				}
				if count == 0 {
					return Fail("no required status checks are configured; CI failures do not block merges")
				}
				return Pass(fmt.Sprintf("%d required status checks configured", count))
			}
			checks := f.Protection.GetRequiredStatusChecks()
			count := 0
			if checks != nil && checks.Checks != nil {
				count = len(*checks.Checks)
			}
			if count == 0 {
				return Fail("no required status checks are configured; CI failures do not block merges")
			}
			return Pass(fmt.Sprintf("%d required status checks configured", count))
		},
	})

	register(Rule{
		ID: "GSK117", GHQRID: "repo-bp-010", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityCritical, Title: "Force pushes allowed on protected branch",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.Protection == nil {
				rulesets, skip, ok := rulesetFallback(f)
				if !ok {
					return skip
				}
				for _, rs := range rulesets {
					if rs.Rules != nil && rs.Rules.NonFastForward != nil {
						return Pass("force pushes are disabled on the protected branch")
					}
				}
				return Fail("force pushes are allowed on the protected branch")
			}
			if f.Protection.GetAllowForcePushes().GetEnabled() {
				return Fail("force pushes are allowed on the protected branch")
			}
			return Pass("force pushes are disabled on the protected branch")
		},
	})

	register(Rule{
		ID: "GSK118", GHQRID: "repo-bp-012", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityMedium, Title: "Signed commits not required",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.Protection == nil {
				rulesets, skip, ok := rulesetFallback(f)
				if !ok {
					return skip
				}
				for _, rs := range rulesets {
					if rs.Rules != nil && rs.Rules.RequiredSignatures != nil {
						return Pass("signed commits are required")
					}
				}
				return Fail("signed commits are not required")
			}
			if f.Protection.GetRequiredSignatures().GetEnabled() {
				return Pass("signed commits are required")
			}
			return Fail("signed commits are not required")
		},
	})
}

// checkRequiredReviews returns a CheckRepo function that fails when the
// required approving review count equals expected. Using equality (rather than
// a threshold) keeps each rule aligned with its title and avoids GSK111/GSK112
// overlapping at a count of 0. An absent required-reviews block is treated as a
// count of 0 so only the zero-review rule (GSK111) reports it.
func checkRequiredReviews(expected int, failDetail string) RepositoryCheckFunc {
	return func(f *RepositoryFacts) Outcome {
		if f.Protection == nil {
			if _, skip, ok := rulesetFallback(f); !ok {
				return skip
			}
			// Overlapping active rulesets combine into the most restrictive
			// setting, so the required count is the maximum across applicable
			// review rules. An applicable ruleset with no pull request rule is a
			// known absence, i.e. zero required reviews.
			count := 0
			for _, review := range rulesetPullRequestRules(f) {
				if review.RequiredApprovingReviewCount > count {
					count = review.RequiredApprovingReviewCount
				}
			}
			if count != expected {
				return Pass(fmt.Sprintf("%d approving reviews are required", count))
			}
			return Fail(fmt.Sprintf("%s (required: %d)", failDetail, count))
		}
		reviews := f.Protection.GetRequiredPullRequestReviews()
		count := 0
		if reviews != nil {
			count = reviews.GetRequiredApprovingReviewCount()
		}
		if count != expected {
			return Pass(fmt.Sprintf("%d approving reviews are required", count))
		}
		if reviews == nil {
			return Fail(fmt.Sprintf("%s (pull request reviews are not configured)", failDetail))
		}
		return Fail(fmt.Sprintf("%s (required: %d)", failDetail, count))
	}
}
