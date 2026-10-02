package recommended

import (
	"reflect"
	"testing"

	"github.com/google/go-github/v90/github"
)

func tag(name, sha string) *github.RepositoryTag {
	return &github.RepositoryTag{Name: github.Ptr(name), Commit: &github.Commit{SHA: github.Ptr(sha)}}
}

func TestAbbreviatedTagExcludePatterns(t *testing.T) {
	tests := []struct {
		name string
		tags []*github.RepositoryTag
		want []string
	}{
		{name: "no tags", tags: nil, want: []string{}},
		{
			name: "major tag at the same commit as a full semver tag",
			tags: []*github.RepositoryTag{tag("v1.2.3", "aaa"), tag("v1", "aaa")},
			want: []string{"refs/tags/v[0-9]", "refs/tags/v[0-9][0-9]"},
		},
		{
			name: "major.minor tag at the same commit as a full semver tag",
			tags: []*github.RepositoryTag{tag("v1.2.3", "aaa"), tag("v1.2", "aaa")},
			want: []string{
				"refs/tags/v[0-9].[0-9]",
				"refs/tags/v[0-9].[0-9][0-9]",
				"refs/tags/v[0-9][0-9].[0-9]",
				"refs/tags/v[0-9][0-9].[0-9][0-9]",
			},
		},
		{
			name: "prefix without v",
			tags: []*github.RepositoryTag{tag("1.2.3", "aaa"), tag("1", "aaa")},
			want: []string{"refs/tags/[0-9]", "refs/tags/[0-9][0-9]"},
		},
		{
			name: "abbreviated name at a different commit is not a moving tag",
			tags: []*github.RepositoryTag{tag("v1.2.3", "aaa"), tag("v1", "bbb")},
			want: []string{},
		},
		{
			name: "prefix must match the full semver tag",
			tags: []*github.RepositoryTag{tag("v1.2.3", "aaa"), tag("1", "aaa")},
			want: []string{},
		},
		{
			name: "no full semver tag",
			tags: []*github.RepositoryTag{tag("v1", "aaa"), tag("release", "aaa")},
			want: []string{},
		},
		{
			name: "pre-release counts as a full semver tag",
			tags: []*github.RepositoryTag{tag("v2.0.0-rc.1", "aaa"), tag("v2", "aaa")},
			want: []string{"refs/tags/v[0-9]", "refs/tags/v[0-9][0-9]"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := abbreviatedTagExcludePatterns(tt.tags); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func tagRuleset(enforcement github.RulesetEnforcement, include []string, rules *github.RepositoryRulesetRules) *github.RepositoryRuleset {
	return &github.RepositoryRuleset{
		Target:      github.Ptr(github.RulesetTargetTag),
		Enforcement: enforcement,
		Conditions: &github.RepositoryRulesetConditions{
			RefName: &github.RepositoryRulesetRefConditionParameters{Include: include},
		},
		Rules: rules,
	}
}

func TestGSK140TagRuleset(t *testing.T) {
	both := &github.RepositoryRulesetRules{
		Deletion: &github.EmptyRuleParameters{},
		Update:   &github.UpdateRuleParameters{},
	}
	tests := []struct {
		name  string
		facts *RepositoryFacts
		want  Status
	}{
		{"unknown tags", &RepositoryFacts{}, StatusSkip},
		{"no tags", &RepositoryFacts{HasTags: github.Ptr(false), RulesetsKnown: true}, StatusSkip},
		{"rulesets unknown", &RepositoryFacts{HasTags: github.Ptr(true)}, StatusSkip},
		{"no ruleset", &RepositoryFacts{HasTags: github.Ptr(true), RulesetsKnown: true}, StatusFail},
		{
			"active ruleset with deletion and update",
			&RepositoryFacts{HasTags: github.Ptr(true), RulesetsKnown: true, Rulesets: []*github.RepositoryRuleset{
				tagRuleset(github.RulesetEnforcementActive, []string{"~ALL"}, both),
			}},
			StatusPass,
		},
		{
			"rules split across two rulesets",
			&RepositoryFacts{HasTags: github.Ptr(true), RulesetsKnown: true, Rulesets: []*github.RepositoryRuleset{
				tagRuleset(github.RulesetEnforcementActive, []string{"~ALL"}, &github.RepositoryRulesetRules{Deletion: &github.EmptyRuleParameters{}}),
				tagRuleset(github.RulesetEnforcementActive, []string{"refs/tags/**"}, &github.RepositoryRulesetRules{Update: &github.UpdateRuleParameters{}}),
			}},
			StatusPass,
		},
		{
			"deletion only",
			&RepositoryFacts{HasTags: github.Ptr(true), RulesetsKnown: true, Rulesets: []*github.RepositoryRuleset{
				tagRuleset(github.RulesetEnforcementActive, []string{"~ALL"}, &github.RepositoryRulesetRules{Deletion: &github.EmptyRuleParameters{}}),
			}},
			StatusFail,
		},
		{
			"evaluate-only ruleset",
			&RepositoryFacts{HasTags: github.Ptr(true), RulesetsKnown: true, Rulesets: []*github.RepositoryRuleset{
				tagRuleset(github.RulesetEnforcementEvaluate, []string{"~ALL"}, both),
			}},
			StatusFail,
		},
		{
			"ruleset covering a single tag pattern",
			&RepositoryFacts{HasTags: github.Ptr(true), RulesetsKnown: true, Rulesets: []*github.RepositoryRuleset{
				tagRuleset(github.RulesetEnforcementActive, []string{"refs/tags/v1"}, both),
			}},
			StatusFail,
		},
		{
			"branch ruleset is ignored",
			&RepositoryFacts{HasTags: github.Ptr(true), RulesetsKnown: true, Rulesets: []*github.RepositoryRuleset{
				{
					Target:      github.Ptr(github.RulesetTargetBranch),
					Enforcement: github.RulesetEnforcementActive,
					Conditions:  &github.RepositoryRulesetConditions{RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"~ALL"}}},
					Rules:       both,
				},
			}},
			StatusFail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ruleOutcome(t, "GSK140", tt.facts); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGSK143PushRuleset(t *testing.T) {
	private := &github.Repository{Visibility: github.Ptr("private")}
	pushRuleset := func(enforcement github.RulesetEnforcement, rules *github.RepositoryRulesetRules) *github.RepositoryRuleset {
		return &github.RepositoryRuleset{Target: github.Ptr(github.RulesetTargetPush), Enforcement: enforcement, Rules: rules}
	}
	tests := []struct {
		name  string
		facts *RepositoryFacts
		want  Status
	}{
		{"public repository", &RepositoryFacts{Repo: &github.Repository{Visibility: github.Ptr("public")}, RulesetsKnown: true}, StatusSkip},
		{"rulesets unknown", &RepositoryFacts{Repo: private}, StatusSkip},
		{"no ruleset", &RepositoryFacts{Repo: private, RulesetsKnown: true}, StatusFail},
		{
			"file path restriction",
			&RepositoryFacts{Repo: private, RulesetsKnown: true, Rulesets: []*github.RepositoryRuleset{
				pushRuleset(github.RulesetEnforcementActive, &github.RepositoryRulesetRules{FilePathRestriction: &github.FilePathRestrictionRuleParameters{}}),
			}},
			StatusPass,
		},
		{
			"max file size",
			&RepositoryFacts{Repo: private, RulesetsKnown: true, Rulesets: []*github.RepositoryRuleset{
				pushRuleset(github.RulesetEnforcementActive, &github.RepositoryRulesetRules{MaxFileSize: &github.MaxFileSizeRuleParameters{}}),
			}},
			StatusPass,
		},
		{
			"disabled push ruleset",
			&RepositoryFacts{Repo: private, RulesetsKnown: true, Rulesets: []*github.RepositoryRuleset{
				pushRuleset(github.RulesetEnforcementDisabled, &github.RepositoryRulesetRules{FilePathRestriction: &github.FilePathRestrictionRuleParameters{}}),
			}},
			StatusFail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ruleOutcome(t, "GSK143", tt.facts); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
