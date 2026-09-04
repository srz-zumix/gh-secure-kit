package recommended

import (
	"testing"

	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

// ruleOutcome runs the CheckRepo function of the rule with the given ID against
// the supplied facts and returns its outcome status.
func ruleOutcome(t *testing.T, id string, f *RepositoryFacts) Status {
	t.Helper()
	r, ok := RuleByID(id)
	if !ok {
		t.Fatalf("rule %s not found", id)
	}
	if r.CheckRepo == nil {
		t.Fatalf("rule %s has no CheckRepo", id)
	}
	return r.CheckRepo(f).Status
}

func TestCollaboratorRulesSkipWhenDataUnknown(t *testing.T) {
	for _, id := range []string{"GSK119", "GSK120"} {
		t.Run(id+"/unknown skips", func(t *testing.T) {
			if got := ruleOutcome(t, id, &RepositoryFacts{}); got != StatusSkip {
				t.Fatalf("%s with unknown collaborators = %s, want %s", id, got, StatusSkip)
			}
		})
		t.Run(id+"/known empty passes", func(t *testing.T) {
			f := &RepositoryFacts{CollaboratorsKnown: true}
			if got := ruleOutcome(t, id, f); got != StatusPass {
				t.Fatalf("%s with no collaborators = %s, want %s", id, got, StatusPass)
			}
		})
	}
}

func TestGSK120FailsWithDirectCollaborators(t *testing.T) {
	f := &RepositoryFacts{
		CollaboratorsKnown: true,
		Collaborators:      []*github.User{{Login: github.Ptr("alice")}},
	}
	if got := ruleOutcome(t, "GSK120", f); got != StatusFail {
		t.Fatalf("GSK120 with a direct collaborator = %s, want %s", got, StatusFail)
	}
}

func TestDeployKeyRulesSkipWhenDataUnknown(t *testing.T) {
	for _, id := range []string{"GSK121", "GSK122"} {
		t.Run(id+"/unknown skips", func(t *testing.T) {
			if got := ruleOutcome(t, id, &RepositoryFacts{}); got != StatusSkip {
				t.Fatalf("%s with unknown deploy keys = %s, want %s", id, got, StatusSkip)
			}
		})
		t.Run(id+"/known empty passes", func(t *testing.T) {
			f := &RepositoryFacts{DeployKeysKnown: true}
			if got := ruleOutcome(t, id, f); got != StatusPass {
				t.Fatalf("%s with no deploy keys = %s, want %s", id, got, StatusPass)
			}
		})
	}
}

func TestGSK102SkipsWhenAlertsUnknownOrDisabled(t *testing.T) {
	tests := []struct {
		name string
		f    *RepositoryFacts
		want Status
	}{
		{"alerts unknown", &RepositoryFacts{}, StatusSkip},
		{"alerts disabled", &RepositoryFacts{VulnerabilityAlerts: &gh.RepositorySecurityFeatureStatus{Enabled: false}}, StatusSkip},
		{"enabled without yml", &RepositoryFacts{VulnerabilityAlerts: &gh.RepositorySecurityFeatureStatus{Enabled: true}, HasDependabotYML: github.Ptr(false)}, StatusFail},
		{"enabled with yml", &RepositoryFacts{VulnerabilityAlerts: &gh.RepositorySecurityFeatureStatus{Enabled: true}, HasDependabotYML: github.Ptr(true)}, StatusPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ruleOutcome(t, "GSK102", tt.f); got != tt.want {
				t.Fatalf("GSK102 (%s) = %s, want %s", tt.name, got, tt.want)
			}
		})
	}
}

func TestFilterMatchesRuleIDsCaseInsensitively(t *testing.T) {
	rules := AllRules()

	got := Filter{IDs: []string{"gsk101"}}.Apply(rules)
	if len(got) != 1 || got[0].ID != "GSK101" {
		t.Fatalf("lowercase --rule gsk101 = %v, want exactly GSK101", ruleIDs(got))
	}

	ignored := Filter{IgnoreIDs: []string{"gsk101"}}.Apply(rules)
	for _, r := range ignored {
		if r.ID == "GSK101" {
			t.Fatalf("lowercase --ignore gsk101 did not exclude GSK101")
		}
	}
}

func ruleIDs(rules []Rule) []string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}

func TestFilterOnlyFixableControlsNonFixableInclusion(t *testing.T) {
	rules := AllRules()

	// Find a non-fixable rule to assert on.
	var nonFixableID string
	for _, r := range rules {
		if !r.Fixable {
			nonFixableID = r.ID
			break
		}
	}
	if nonFixableID == "" {
		t.Skip("no non-fixable rule in the catalog")
	}

	// Default filter (as `recommended apply` now uses) must include
	// non-fixable rules so they are evaluated and reported.
	if !containsID(Filter{}.Apply(rules), nonFixableID) {
		t.Fatalf("default filter dropped non-fixable rule %s", nonFixableID)
	}

	// OnlyFixable must still exclude them (used by `check --fixable-only`).
	if containsID(Filter{OnlyFixable: true}.Apply(rules), nonFixableID) {
		t.Fatalf("OnlyFixable filter kept non-fixable rule %s", nonFixableID)
	}
}

func containsID(rules []Rule, id string) bool {
	for _, r := range rules {
		if r.ID == id {
			return true
		}
	}
	return false
}
