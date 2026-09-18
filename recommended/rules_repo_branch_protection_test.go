package recommended

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-github/v90/github"
)

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "branch protection response",
			err:  &github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusNotFound}},
			want: true,
		},
		{
			name: "branch protection message without response",
			err:  &github.ErrorResponse{Message: "Branch not protected"},
			want: true,
		},
		{name: "branch protection client error", err: errors.New("branch is not protected"), want: true},
		{name: "wrapped branch protection message", err: errors.New("GET branch: Branch not protected (HTTP 404)"), want: true},
		{name: "other error", err: errors.New("request failed"), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNotFound(tc.err); got != tc.want {
				t.Errorf("isNotFound() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMatchRefPattern(t *testing.T) {
	cases := []struct {
		pattern string
		branch  string
		want    bool
	}{
		{"~ALL", "main", true},
		{"~DEFAULT_BRANCH", "main", true},
		{"refs/heads/main", "main", true},
		{"refs/heads/main", "master", false},
		{"refs/heads/*", "main", true},
		{"refs/heads/*", "feature/x", false}, // single star does not cross '/'
		{"refs/heads/**", "feature/x", true},
		{"**/main", "main", true},
		{"refs/heads/relea?e", "release", true},
		{"refs/heads/dev", "main", false},
	}
	for _, c := range cases {
		if got := matchRefPattern(c.pattern, c.branch); got != c.want {
			t.Errorf("matchRefPattern(%q, %q) = %v, want %v", c.pattern, c.branch, got, c.want)
		}
	}
}

// branchRuleset builds an active branch ruleset with the given ref conditions
// and (unless noRules) a single pull-request rule.
func branchRuleset(include, exclude []string, noRules bool) *github.RepositoryRuleset {
	target := github.RulesetTargetBranch
	rs := &github.RepositoryRuleset{
		Name:        "rs",
		Target:      &target,
		Enforcement: "active",
		Conditions: &github.RepositoryRulesetConditions{
			RefName: &github.RepositoryRulesetRefConditionParameters{
				Include: include,
				Exclude: exclude,
			},
		},
	}
	if !noRules {
		rs.Rules = &github.RepositoryRulesetRules{PullRequest: &github.PullRequestRuleParameters{}}
	}
	return rs
}

func factsWithRulesets(rulesets ...*github.RepositoryRuleset) *RepositoryFacts {
	return &RepositoryFacts{
		Repo:            &github.Repository{DefaultBranch: github.Ptr("main")},
		Rulesets:        rulesets,
		ProtectionKnown: true,
		RulesetsKnown:   true,
	}
}

func TestActiveRulesetProtectsDefaultBranch(t *testing.T) {
	tests := []struct {
		name string
		rs   *github.RepositoryRuleset
		want bool
	}{
		{"targets default branch", branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, false), true},
		{"targets all", branchRuleset([]string{"~ALL"}, nil, false), true},
		{"explicit ref", branchRuleset([]string{"refs/heads/main"}, nil, false), true},
		{"other branch only", branchRuleset([]string{"refs/heads/develop"}, nil, false), false},
		{"default excluded", branchRuleset([]string{"~ALL"}, []string{"~DEFAULT_BRANCH"}, false), false},
		{"no rules", branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, true), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := factsWithRulesets(tc.rs)
			if got := activeRulesetProtectsDefaultBranch(f); got != tc.want {
				t.Errorf("activeRulesetProtectsDefaultBranch = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestActiveRulesetIgnoresInactiveAndNonBranch(t *testing.T) {
	inactive := branchRuleset([]string{"~ALL"}, nil, false)
	inactive.Enforcement = "evaluate"
	if activeRulesetProtectsDefaultBranch(factsWithRulesets(inactive)) {
		t.Error("evaluate-mode ruleset must not count as protection")
	}

	tagTarget := github.RulesetTargetTag
	tag := branchRuleset([]string{"~ALL"}, nil, false)
	tag.Target = &tagTarget
	if activeRulesetProtectsDefaultBranch(factsWithRulesets(tag)) {
		t.Error("tag-target ruleset must not count as branch protection")
	}
}

func gsk110(t *testing.T) Rule {
	t.Helper()
	r, ok := RuleByID("GSK110")
	if !ok {
		t.Fatal("GSK110 not registered")
	}
	return r
}

func TestGSK110TriState(t *testing.T) {
	rule := gsk110(t)

	// Protected by a ruleset targeting the default branch -> pass.
	f := factsWithRulesets(branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, false))
	if got := rule.CheckRepo(f).Status; got != StatusPass {
		t.Errorf("protected: got %v, want pass", got)
	}

	// Determined, no protection -> fail.
	f = factsWithRulesets()
	if got := rule.CheckRepo(f).Status; got != StatusFail {
		t.Errorf("unprotected+known: got %v, want fail", got)
	}

	// Ruleset state indeterminate -> skip instead of a false fail.
	f = factsWithRulesets()
	f.RulesetsKnown = false
	if got := rule.CheckRepo(f).Status; got != StatusSkip {
		t.Errorf("rulesets unknown: got %v, want skip", got)
	}

	// Protection state indeterminate -> skip.
	f = factsWithRulesets()
	f.ProtectionKnown = false
	if got := rule.CheckRepo(f).Status; got != StatusSkip {
		t.Errorf("protection unknown: got %v, want skip", got)
	}

	// Legacy protection present -> pass regardless of rulesets.
	f = factsWithRulesets()
	f.Protection = &github.Protection{}
	if got := rule.CheckRepo(f).Status; got != StatusPass {
		t.Errorf("legacy protection: got %v, want pass", got)
	}
}

func TestGSK117AllowForcePushesNilSafe(t *testing.T) {
	rule, ok := RuleByID("GSK117")
	if !ok {
		t.Fatal("GSK117 not registered")
	}

	// No legacy protection -> skip.
	if got := rule.CheckRepo(&RepositoryFacts{}).Status; got != StatusSkip {
		t.Errorf("no protection: got %v, want skip", got)
	}

	// Protection present but AllowForcePushes omitted (nil) must not panic
	// and is treated as disabled -> pass.
	f := &RepositoryFacts{Protection: &github.Protection{}}
	if got := rule.CheckRepo(f).Status; got != StatusPass {
		t.Errorf("nil AllowForcePushes: got %v, want pass", got)
	}

	// Explicitly enabled -> fail.
	f = &RepositoryFacts{Protection: &github.Protection{
		AllowForcePushes: &github.AllowForcePushes{Enabled: true},
	}}
	if got := rule.CheckRepo(f).Status; got != StatusFail {
		t.Errorf("force pushes enabled: got %v, want fail", got)
	}

	// Explicitly disabled -> pass.
	f = &RepositoryFacts{Protection: &github.Protection{
		AllowForcePushes: &github.AllowForcePushes{Enabled: false},
	}}
	if got := rule.CheckRepo(f).Status; got != StatusPass {
		t.Errorf("force pushes disabled: got %v, want pass", got)
	}
}

func TestBranchProtectionRulesUseRulesets(t *testing.T) {
	reviewRule := branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, false)
	reviewRule.Rules.PullRequest = &github.PullRequestRuleParameters{
		RequiredApprovingReviewCount: 2,
		DismissStaleReviewsOnPush:    true,
		RequireCodeOwnerReview:       true,
	}
	statusRule := branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, true)
	statusRule.Rules = &github.RepositoryRulesetRules{
		RequiredStatusChecks: &github.RequiredStatusChecksRuleParameters{
			RequiredStatusChecks:             []*github.RuleStatusCheck{{Context: "test"}},
			StrictRequiredStatusChecksPolicy: true,
		},
	}
	protectedRule := branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, true)
	protectedRule.Rules = &github.RepositoryRulesetRules{
		NonFastForward:     &github.EmptyRuleParameters{},
		RequiredSignatures: &github.EmptyRuleParameters{},
	}
	facts := factsWithRulesets(reviewRule, statusRule, protectedRule)

	for _, id := range []string{"GSK111", "GSK112", "GSK113", "GSK114", "GSK115", "GSK116", "GSK117", "GSK118"} {
		rule, ok := RuleByID(id)
		if !ok {
			t.Fatalf("%s not registered", id)
		}
		if got := rule.CheckRepo(facts).Status; got != StatusPass {
			t.Errorf("%s: got %v, want pass", id, got)
		}
	}
}

func TestBranchProtectionRulesetFailures(t *testing.T) {
	ruleCases := []struct {
		id string
		rs *github.RepositoryRuleset
	}{
		{"GSK111", branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, false)},
		{"GSK112", branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, false)},
		{"GSK113", branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, false)},
		{"GSK114", branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, false)},
		{"GSK115", branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, true)},
		{"GSK116", branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, true)},
		{"GSK117", branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, false)},
		{"GSK118", branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, false)},
	}
	ruleCases[1].rs.Rules.PullRequest.RequiredApprovingReviewCount = 1
	ruleCases[2].rs.Rules.PullRequest.DismissStaleReviewsOnPush = false
	ruleCases[3].rs.Rules.PullRequest.RequireCodeOwnerReview = false
	ruleCases[4].rs.Rules = &github.RepositoryRulesetRules{
		RequiredStatusChecks: &github.RequiredStatusChecksRuleParameters{},
	}
	ruleCases[5].rs.Rules = &github.RepositoryRulesetRules{
		RequiredStatusChecks: &github.RequiredStatusChecksRuleParameters{},
	}

	for _, tc := range ruleCases {
		t.Run(tc.id, func(t *testing.T) {
			rule, ok := RuleByID(tc.id)
			if !ok {
				t.Fatalf("%s not registered", tc.id)
			}
			if got := rule.CheckRepo(factsWithRulesets(tc.rs)).Status; got != StatusFail {
				t.Errorf("got %v, want fail", got)
			}
		})
	}
}

func TestRequiredReviewsEquality(t *testing.T) {
	gsk111, ok := RuleByID("GSK111")
	if !ok {
		t.Fatal("GSK111 not registered")
	}
	gsk112, ok := RuleByID("GSK112")
	if !ok {
		t.Fatal("GSK112 not registered")
	}

	factsWithCount := func(n int) *RepositoryFacts {
		return &RepositoryFacts{Protection: &github.Protection{
			RequiredPullRequestReviews: &github.PullRequestReviewsEnforcement{
				RequiredApprovingReviewCount: n,
			},
		}}
	}

	// count 0: only GSK111 (Critical) fails; GSK112 passes (no overlap).
	f := factsWithCount(0)
	if got := gsk111.CheckRepo(f).Status; got != StatusFail {
		t.Errorf("count0 GSK111: got %v, want fail", got)
	}
	if got := gsk112.CheckRepo(f).Status; got != StatusPass {
		t.Errorf("count0 GSK112: got %v, want pass", got)
	}

	// count 1: only GSK112 fails; GSK111 passes.
	f = factsWithCount(1)
	if got := gsk111.CheckRepo(f).Status; got != StatusPass {
		t.Errorf("count1 GSK111: got %v, want pass", got)
	}
	out := gsk112.CheckRepo(f)
	if out.Status != StatusFail {
		t.Errorf("count1 GSK112: got %v, want fail", out.Status)
	}
	if want := "only 1 approving review is required (required: 1)"; out.Detail != want {
		t.Errorf("count1 GSK112 detail: got %q, want %q", out.Detail, want)
	}

	// count 2: both pass.
	f = factsWithCount(2)
	if got := gsk111.CheckRepo(f).Status; got != StatusPass {
		t.Errorf("count2 GSK111: got %v, want pass", got)
	}
	if got := gsk112.CheckRepo(f).Status; got != StatusPass {
		t.Errorf("count2 GSK112: got %v, want pass", got)
	}

	// Reviews block absent (nil): treated as count 0 -> only GSK111 fails
	// with a "not configured" detail; GSK112 passes.
	f = &RepositoryFacts{Protection: &github.Protection{}}
	out = gsk111.CheckRepo(f)
	if out.Status != StatusFail {
		t.Errorf("nil reviews GSK111: got %v, want fail", out.Status)
	}
	if want := "no approving reviews are required before merge (pull request reviews are not configured)"; out.Detail != want {
		t.Errorf("nil reviews GSK111 detail: got %q, want %q", out.Detail, want)
	}
	if got := gsk112.CheckRepo(f).Status; got != StatusPass {
		t.Errorf("nil reviews GSK112: got %v, want pass", got)
	}

	// No legacy protection -> skip.
	f = &RepositoryFacts{}
	if got := gsk111.CheckRepo(f).Status; got != StatusSkip {
		t.Errorf("no protection GSK111: got %v, want skip", got)
	}
	if got := gsk112.CheckRepo(f).Status; got != StatusSkip {
		t.Errorf("no protection GSK112: got %v, want skip", got)
	}
}

func TestFilterApplySortsByID(t *testing.T) {
	unsorted := []Rule{
		{ID: "GSK120", Scope: ScopeRepository},
		{ID: "GSK101", Scope: ScopeRepository},
		{ID: "GSK110", Scope: ScopeRepository},
	}
	out := Filter{}.Apply(unsorted)
	got := make([]string, len(out))
	for i, r := range out {
		got[i] = r.ID
	}
	want := []string{"GSK101", "GSK110", "GSK120"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Apply order: got %v, want %v", got, want)
		}
	}
}
