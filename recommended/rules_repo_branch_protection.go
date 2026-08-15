package recommended

import "fmt"

func init() {
	registerBranchProtectionRules()
}

// hasActiveRuleset reports whether any active ruleset targets the given branch.
func hasActiveRuleset(f *RepositoryFacts) bool {
	for _, rs := range f.Rulesets {
		if rs.GetEnforcement() == "active" {
			return true
		}
	}
	return false
}

func registerBranchProtectionRules() {
	register(Rule{
		ID: "GSK110", GHQRID: "repo-bp-001", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityCritical, Title: "No branch protection configured on default branch",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.Protection != nil || hasActiveRuleset(f) {
				return Pass("default branch is protected by a branch protection rule or ruleset")
			}
			return Fail("default branch has no branch protection rule or ruleset")
		},
	})

	register(Rule{
		ID: "GSK111", GHQRID: "repo-bp-002", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityCritical, Title: "No approving reviews required before merge",
		CheckRepo: checkRequiredReviews(0, SeverityCritical, "no approving reviews are required before merge"),
	})

	register(Rule{
		ID: "GSK112", GHQRID: "repo-bp-003", Scope: ScopeRepository,
		Category: "branch_protection", Severity: SeverityMedium, Title: "Only 1 approving review required",
		CheckRepo: checkRequiredReviews(1, SeverityMedium, "only 1 approving review is required"),
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
			if f.Protection.GetAllowForcePushes().Enabled {
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
// required approving review count is at or below threshold.
func checkRequiredReviews(threshold int, severity Severity, failDetail string) RepositoryCheckFunc {
	return func(f *RepositoryFacts) Outcome {
		if f.Protection == nil {
			return Skip("no legacy branch protection rule; verify equivalent settings in repository rulesets")
		}
		reviews := f.Protection.GetRequiredPullRequestReviews()
		if reviews == nil {
			return Fail("pull request reviews are not configured")
		}
		if reviews.GetRequiredApprovingReviewCount() <= threshold {
			return Fail(fmt.Sprintf("%s (required: %d)", failDetail, reviews.GetRequiredApprovingReviewCount()))
		}
		return Pass(fmt.Sprintf("%d approving reviews are required", reviews.GetRequiredApprovingReviewCount()))
	}
}
