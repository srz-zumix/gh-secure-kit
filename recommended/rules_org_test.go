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
	if got := orgRuleOutcome(t, "GSK507", &OrganizationFacts{}); got != StatusSkip {
		t.Errorf("unknown configs: got %v, want skip", got)
	}

	if got := orgRuleOutcome(t, "GSK507", &OrganizationFacts{DefaultSecurityConfigsKnown: true}); got != StatusFail {
		t.Errorf("no defaults: got %v, want fail", got)
	}

	f := &OrganizationFacts{DefaultSecurityConfigsKnown: true, DefaultSecurityConfigs: []*github.CodeSecurityConfigurationWithDefaultForNewRepos{
		{DefaultForNewRepos: github.Ptr("none")},
	}}
	if got := orgRuleOutcome(t, "GSK507", f); got != StatusFail {
		t.Errorf("only none: got %v, want fail", got)
	}

	f = &OrganizationFacts{DefaultSecurityConfigsKnown: true, DefaultSecurityConfigs: []*github.CodeSecurityConfigurationWithDefaultForNewRepos{
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

func TestGSK509MembersCanForkPrivateRepos(t *testing.T) {
	f := &OrganizationFacts{Org: &github.Organization{MembersCanForkPrivateRepos: github.Ptr(true)}}
	if got := orgRuleOutcome(t, "GSK509", f); got != StatusFail {
		t.Errorf("enabled: got %v, want fail", got)
	}

	f = &OrganizationFacts{Org: &github.Organization{MembersCanForkPrivateRepos: github.Ptr(false)}}
	if got := orgRuleOutcome(t, "GSK509", f); got != StatusPass {
		t.Errorf("disabled: got %v, want pass", got)
	}
}

func TestGSK515MembersCanCreatePrivateRepos(t *testing.T) {
	f := &OrganizationFacts{Org: &github.Organization{MembersCanCreatePrivateRepos: github.Ptr(true)}}
	if got := orgRuleOutcome(t, "GSK515", f); got != StatusFail {
		t.Errorf("enabled: got %v, want fail", got)
	}

	f = &OrganizationFacts{Org: &github.Organization{MembersCanCreatePrivateRepos: github.Ptr(false)}}
	if got := orgRuleOutcome(t, "GSK515", f); got != StatusPass {
		t.Errorf("disabled: got %v, want pass", got)
	}
}

func TestGSK516MembersCanCreateInternalRepos(t *testing.T) {
	f := &OrganizationFacts{Org: &github.Organization{MembersCanCreateInternalRepos: github.Ptr(true)}}
	if got := orgRuleOutcome(t, "GSK516", f); got != StatusFail {
		t.Errorf("enabled: got %v, want fail", got)
	}

	f = &OrganizationFacts{Org: &github.Organization{MembersCanCreateInternalRepos: github.Ptr(false)}}
	if got := orgRuleOutcome(t, "GSK516", f); got != StatusPass {
		t.Errorf("disabled: got %v, want pass", got)
	}
}

func TestGSK510MembersCanDeleteRepositories(t *testing.T) {
	f := &OrganizationFacts{Org: &github.Organization{MembersCanDeleteRepositories: github.Ptr(true)}}
	if got := orgRuleOutcome(t, "GSK510", f); got != StatusFail {
		t.Errorf("enabled: got %v, want fail", got)
	}

	f = &OrganizationFacts{Org: &github.Organization{MembersCanDeleteRepositories: github.Ptr(false)}}
	if got := orgRuleOutcome(t, "GSK510", f); got != StatusPass {
		t.Errorf("disabled: got %v, want pass", got)
	}
}

func TestGSK511MembersCanChangeRepoVisibility(t *testing.T) {
	f := &OrganizationFacts{Org: &github.Organization{MembersCanChangeRepoVisibility: github.Ptr(true)}}
	if got := orgRuleOutcome(t, "GSK511", f); got != StatusFail {
		t.Errorf("enabled: got %v, want fail", got)
	}

	f = &OrganizationFacts{Org: &github.Organization{MembersCanChangeRepoVisibility: github.Ptr(false)}}
	if got := orgRuleOutcome(t, "GSK511", f); got != StatusPass {
		t.Errorf("disabled: got %v, want pass", got)
	}
}

func TestGSK512DefaultWorkflowPermissionsWrite(t *testing.T) {
	if got := orgRuleOutcome(t, "GSK512", &OrganizationFacts{}); got != StatusSkip {
		t.Errorf("unknown permissions: got %v, want skip", got)
	}

	f := &OrganizationFacts{DefaultWorkflowPermissions: &github.DefaultWorkflowPermissionOrganization{
		DefaultWorkflowPermissions: github.Ptr("write"),
	}}
	if got := orgRuleOutcome(t, "GSK512", f); got != StatusFail {
		t.Errorf("write: got %v, want fail", got)
	}

	f = &OrganizationFacts{DefaultWorkflowPermissions: &github.DefaultWorkflowPermissionOrganization{
		DefaultWorkflowPermissions: github.Ptr("read"),
	}}
	if got := orgRuleOutcome(t, "GSK512", f); got != StatusPass {
		t.Errorf("read: got %v, want pass", got)
	}
}

func TestGSK513ActionsCanApprovePullRequests(t *testing.T) {
	if got := orgRuleOutcome(t, "GSK513", &OrganizationFacts{}); got != StatusSkip {
		t.Errorf("unknown permissions: got %v, want skip", got)
	}

	f := &OrganizationFacts{DefaultWorkflowPermissions: &github.DefaultWorkflowPermissionOrganization{
		CanApprovePullRequestReviews: github.Ptr(true),
	}}
	if got := orgRuleOutcome(t, "GSK513", f); got != StatusFail {
		t.Errorf("enabled: got %v, want fail", got)
	}

	f = &OrganizationFacts{DefaultWorkflowPermissions: &github.DefaultWorkflowPermissionOrganization{
		CanApprovePullRequestReviews: github.Ptr(false),
	}}
	if got := orgRuleOutcome(t, "GSK513", f); got != StatusPass {
		t.Errorf("disabled: got %v, want pass", got)
	}
}

func TestGSK514ForkPRContributorApprovalPolicy(t *testing.T) {
	if got := orgRuleOutcome(t, "GSK514", &OrganizationFacts{}); got != StatusSkip {
		t.Errorf("unknown policy: got %v, want skip", got)
	}

	f := &OrganizationFacts{ForkPRContributorApproval: &github.ContributorApprovalPermissions{
		ApprovalPolicy: "first_time_contributors_new_to_github",
	}}
	if got := orgRuleOutcome(t, "GSK514", f); got != StatusFail {
		t.Errorf("loose policy: got %v, want fail", got)
	}

	f = &OrganizationFacts{ForkPRContributorApproval: &github.ContributorApprovalPermissions{
		ApprovalPolicy: "all_external_contributors",
	}}
	if got := orgRuleOutcome(t, "GSK514", f); got != StatusPass {
		t.Errorf("strict policy: got %v, want pass", got)
	}
}

func TestGSK517OrgSHAPinningRequired(t *testing.T) {
	tests := []struct {
		name string
		perm *github.ActionsPermissions
		want Status
	}{
		{"unknown permissions", nil, StatusSkip},
		{"actions disabled", &github.ActionsPermissions{EnabledRepositories: github.Ptr("none")}, StatusSkip},
		{"not required", &github.ActionsPermissions{EnabledRepositories: github.Ptr("all")}, StatusFail},
		{"required", &github.ActionsPermissions{EnabledRepositories: github.Ptr("all"), SHAPinningRequired: github.Ptr(true)}, StatusPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := orgRuleOutcome(t, "GSK517", &OrganizationFacts{ActionsPermissions: tt.perm}); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGSK518OrgImmutableReleases(t *testing.T) {
	tests := []struct {
		name     string
		settings *github.ImmutableReleaseSettings
		want     Status
	}{
		{"unknown settings", nil, StatusSkip},
		{"none", &github.ImmutableReleaseSettings{EnforcedRepositories: github.Ptr("none")}, StatusFail},
		{"selected", &github.ImmutableReleaseSettings{EnforcedRepositories: github.Ptr("selected")}, StatusFail},
		{"all", &github.ImmutableReleaseSettings{EnforcedRepositories: github.Ptr("all")}, StatusPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := orgRuleOutcome(t, "GSK518", &OrganizationFacts{ImmutableReleases: tt.settings}); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGSK519OrgPrivateForkPRWorkflows(t *testing.T) {
	if got := orgRuleOutcome(t, "GSK519", &OrganizationFacts{}); got != StatusSkip {
		t.Errorf("unknown settings: got %v, want skip", got)
	}
	f := &OrganizationFacts{PrivateForkPRWorkflows: &github.WorkflowsPermissions{
		RunWorkflowsFromForkPullRequests: github.Ptr(true),
		SendWriteTokensToWorkflows:       github.Ptr(true),
	}}
	if got := orgRuleOutcome(t, "GSK519", f); got != StatusFail {
		t.Errorf("write tokens sent: got %v, want fail", got)
	}
	f = &OrganizationFacts{PrivateForkPRWorkflows: &github.WorkflowsPermissions{
		RunWorkflowsFromForkPullRequests: github.Ptr(false),
		SendSecretsAndVariables:          github.Ptr(true),
	}}
	if got := orgRuleOutcome(t, "GSK519", f); got != StatusPass {
		t.Errorf("fork workflows disabled: got %v, want pass", got)
	}
}

func TestGSK520ExcessiveOrgOwners(t *testing.T) {
	owners := func(n int) []*github.User {
		users := make([]*github.User, n)
		for i := range users {
			users[i] = &github.User{Login: github.Ptr("owner")}
		}
		return users
	}
	if got := orgRuleOutcome(t, "GSK520", &OrganizationFacts{}); got != StatusSkip {
		t.Errorf("unknown owners: got %v, want skip", got)
	}
	if got := orgRuleOutcome(t, "GSK520", &OrganizationFacts{OwnersKnown: true, Owners: owners(3)}); got != StatusPass {
		t.Errorf("3 owners: got %v, want pass", got)
	}
	if got := orgRuleOutcome(t, "GSK520", &OrganizationFacts{OwnersKnown: true, Owners: owners(4)}); got != StatusFail {
		t.Errorf("4 owners: got %v, want fail", got)
	}
}
