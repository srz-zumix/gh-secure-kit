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
	branch := f.Repo.GetDefaultBranch()
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
		if rulesetTargetsBranch(rs.Conditions, branch) {
			return true
		}
	}
	return false
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
				return Skip("no legacy branch protection rule; verify equivalent settings in repository rulesets")
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
				return Skip("no legacy branch protection rule; verify equivalent settings in repository rulesets")
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
				return Skip("no legacy branch protection rule; verify equivalent settings in repository rulesets")
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
				return Skip("no legacy branch protection rule; verify equivalent settings in repository rulesets")
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
				return Skip("no legacy branch protection rule; verify equivalent settings in repository rulesets")
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
				return Skip("no legacy branch protection rule; verify equivalent settings in repository rulesets")
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
			return Skip("no legacy branch protection rule; verify equivalent settings in repository rulesets")
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
