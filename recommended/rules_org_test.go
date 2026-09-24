package recommended

import (
	"testing"

	"github.com/google/go-github/v90/github"
)

func orgRuleOutcome(t *testing.T, id string, f *OrganizationFacts) Status {
	t.Helper()
	r, ok := RuleByID(id)
	if !ok {
		t.Fatalf("rule %s not found", id)
	}
	if r.CheckOrg == nil {
		t.Fatalf("rule %s has no CheckOrg", id)
	}
	return r.CheckOrg(f).Status
}

func TestGSK507DefaultCodeSecurityConfiguration(t *testing.T) {
	if got := orgRuleOutcome(t, "GSK507", &OrganizationFacts{}); got != StatusFail {
		t.Errorf("no defaults: got %v, want fail", got)
	}

	f := &OrganizationFacts{DefaultSecurityConfigs: []*github.CodeSecurityConfigurationWithDefaultForNewRepos{
		{DefaultForNewRepos: github.Ptr("none")},
	}}
	if got := orgRuleOutcome(t, "GSK507", f); got != StatusFail {
		t.Errorf("only none: got %v, want fail", got)
	}

	f = &OrganizationFacts{DefaultSecurityConfigs: []*github.CodeSecurityConfigurationWithDefaultForNewRepos{
		{DefaultForNewRepos: github.Ptr("none")},
		{DefaultForNewRepos: github.Ptr("public")},
	}}
	if got := orgRuleOutcome(t, "GSK507", f); got != StatusPass {
		t.Errorf("one applied: got %v, want pass", got)
	}
}

func TestGSK508ActionsEnabledRepositories(t *testing.T) {
	if got := orgRuleOutcome(t, "GSK508", &OrganizationFacts{}); got != StatusSkip {
		t.Errorf("unknown permissions: got %v, want skip", got)
	}

	f := &OrganizationFacts{ActionsPermissions: &github.ActionsPermissions{EnabledRepositories: github.Ptr("all")}}
	if got := orgRuleOutcome(t, "GSK508", f); got != StatusFail {
		t.Errorf("all repositories: got %v, want fail", got)
	}

	f = &OrganizationFacts{ActionsPermissions: &github.ActionsPermissions{EnabledRepositories: github.Ptr("selected")}}
	if got := orgRuleOutcome(t, "GSK508", f); got != StatusPass {
		t.Errorf("selected repositories: got %v, want pass", got)
	}
}
