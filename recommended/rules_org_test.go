package recommended

import (
	"testing"

	"github.com/google/go-github/v93/github"
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

func TestGSK501TwoFactorAuthentication(t *testing.T) {
	tests := []struct {
		name    string
		managed bool
		enabled bool
		want    Status
	}{
		{"required", false, true, StatusPass},
		{"not required", false, false, StatusFail},
		{"managed users", true, false, StatusSkip},
		{"managed users with requirement", true, true, StatusSkip},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := &OrganizationFacts{
				Org:                    &github.Organization{TwoFactorRequirementEnabled: new(test.enabled)},
				EnterpriseManagedUsers: test.managed,
			}
			if got := orgRuleOutcome(t, "GSK501", facts); got != test.want {
				t.Errorf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestGSK507DefaultCodeSecurityConfiguration(t *testing.T) {
	if got := orgRuleOutcome(t, "GSK507", &OrganizationFacts{}); got != StatusSkip {
		t.Errorf("unknown configs: got %v, want skip", got)
	}

	if got := orgRuleOutcome(t, "GSK507", &OrganizationFacts{DefaultSecurityConfigsKnown: true}); got != StatusFail {
		t.Errorf("no defaults: got %v, want fail", got)
	}

	f := &OrganizationFacts{DefaultSecurityConfigsKnown: true, DefaultSecurityConfigs: []*github.CodeSecurityConfigurationWithDefaultForNewRepos{
		{DefaultForNewRepos: new("none")},
	}}
	if got := orgRuleOutcome(t, "GSK507", f); got != StatusFail {
		t.Errorf("only none: got %v, want fail", got)
	}

	f = &OrganizationFacts{DefaultSecurityConfigsKnown: true, DefaultSecurityConfigs: []*github.CodeSecurityConfigurationWithDefaultForNewRepos{
		{DefaultForNewRepos: new("none")},
		{DefaultForNewRepos: new("public")},
	}}
	if got := orgRuleOutcome(t, "GSK507", f); got != StatusPass {
		t.Errorf("one applied: got %v, want pass", got)
	}
}

func TestGSK508ActionsEnabledRepositories(t *testing.T) {
	if got := orgRuleOutcome(t, "GSK508", &OrganizationFacts{}); got != StatusSkip {
		t.Errorf("unknown permissions: got %v, want skip", got)
	}

	f := &OrganizationFacts{ActionsPermissions: &github.ActionsPermissions{EnabledRepositories: "all"}}
	if got := orgRuleOutcome(t, "GSK508", f); got != StatusFail {
		t.Errorf("all repositories: got %v, want fail", got)
	}

	f = &OrganizationFacts{ActionsPermissions: &github.ActionsPermissions{EnabledRepositories: "selected"}}
	if got := orgRuleOutcome(t, "GSK508", f); got != StatusPass {
		t.Errorf("selected repositories: got %v, want pass", got)
	}
}

func TestGSK509MembersCanForkPrivateRepos(t *testing.T) {
	f := &OrganizationFacts{Org: &github.Organization{MembersCanForkPrivateRepos: new(true)}}
	if got := orgRuleOutcome(t, "GSK509", f); got != StatusFail {
		t.Errorf("enabled: got %v, want fail", got)
	}

	f = &OrganizationFacts{Org: &github.Organization{MembersCanForkPrivateRepos: new(false)}}
	if got := orgRuleOutcome(t, "GSK509", f); got != StatusPass {
		t.Errorf("disabled: got %v, want pass", got)
	}
}

func TestGSK515MembersCanCreatePrivateRepos(t *testing.T) {
	f := &OrganizationFacts{Org: &github.Organization{MembersCanCreatePrivateRepos: new(true)}}
	if got := orgRuleOutcome(t, "GSK515", f); got != StatusFail {
		t.Errorf("enabled: got %v, want fail", got)
	}

	f = &OrganizationFacts{Org: &github.Organization{MembersCanCreatePrivateRepos: new(false)}}
	if got := orgRuleOutcome(t, "GSK515", f); got != StatusPass {
		t.Errorf("disabled: got %v, want pass", got)
	}
}

func TestGSK516MembersCanCreateInternalRepos(t *testing.T) {
	f := &OrganizationFacts{Org: &github.Organization{MembersCanCreateInternalRepos: new(true)}}
	if got := orgRuleOutcome(t, "GSK516", f); got != StatusFail {
		t.Errorf("enabled: got %v, want fail", got)
	}

	f = &OrganizationFacts{Org: &github.Organization{MembersCanCreateInternalRepos: new(false)}}
	if got := orgRuleOutcome(t, "GSK516", f); got != StatusPass {
		t.Errorf("disabled: got %v, want pass", got)
	}
}

func TestGSK510MembersCanDeleteRepositories(t *testing.T) {
	f := &OrganizationFacts{Org: &github.Organization{MembersCanDeleteRepositories: new(true)}}
	if got := orgRuleOutcome(t, "GSK510", f); got != StatusFail {
		t.Errorf("enabled: got %v, want fail", got)
	}

	f = &OrganizationFacts{Org: &github.Organization{MembersCanDeleteRepositories: new(false)}}
	if got := orgRuleOutcome(t, "GSK510", f); got != StatusPass {
		t.Errorf("disabled: got %v, want pass", got)
	}
}

func TestGSK511MembersCanChangeRepoVisibility(t *testing.T) {
	f := &OrganizationFacts{Org: &github.Organization{MembersCanChangeRepoVisibility: new(true)}}
	if got := orgRuleOutcome(t, "GSK511", f); got != StatusFail {
		t.Errorf("enabled: got %v, want fail", got)
	}

	f = &OrganizationFacts{Org: &github.Organization{MembersCanChangeRepoVisibility: new(false)}}
	if got := orgRuleOutcome(t, "GSK511", f); got != StatusPass {
		t.Errorf("disabled: got %v, want pass", got)
	}
}

func TestGSK512DefaultWorkflowPermissionsWrite(t *testing.T) {
	if got := orgRuleOutcome(t, "GSK512", &OrganizationFacts{}); got != StatusSkip {
		t.Errorf("unknown permissions: got %v, want skip", got)
	}

	f := &OrganizationFacts{DefaultWorkflowPermissions: &github.DefaultWorkflowPermissionOrganization{
		DefaultWorkflowPermissions: new("write"),
	}}
	if got := orgRuleOutcome(t, "GSK512", f); got != StatusFail {
		t.Errorf("write: got %v, want fail", got)
	}

	f = &OrganizationFacts{DefaultWorkflowPermissions: &github.DefaultWorkflowPermissionOrganization{
		DefaultWorkflowPermissions: new("read"),
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
		CanApprovePullRequestReviews: new(true),
	}}
	if got := orgRuleOutcome(t, "GSK513", f); got != StatusFail {
		t.Errorf("enabled: got %v, want fail", got)
	}

	f = &OrganizationFacts{DefaultWorkflowPermissions: &github.DefaultWorkflowPermissionOrganization{
		CanApprovePullRequestReviews: new(false),
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
		{"actions disabled", &github.ActionsPermissions{EnabledRepositories: "none"}, StatusSkip},
		{"not required", &github.ActionsPermissions{EnabledRepositories: "all"}, StatusFail},
		{"required", &github.ActionsPermissions{EnabledRepositories: "all", SHAPinningRequired: new(true)}, StatusPass},
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
		{"none", &github.ImmutableReleaseSettings{EnforcedRepositories: new("none")}, StatusFail},
		{"selected", &github.ImmutableReleaseSettings{EnforcedRepositories: new("selected")}, StatusFail},
		{"all", &github.ImmutableReleaseSettings{EnforcedRepositories: new("all")}, StatusPass},
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
		RunWorkflowsFromForkPullRequests: new(true),
		SendWriteTokensToWorkflows:       new(true),
	}}
	if got := orgRuleOutcome(t, "GSK519", f); got != StatusFail {
		t.Errorf("write tokens sent: got %v, want fail", got)
	}
	f = &OrganizationFacts{PrivateForkPRWorkflows: &github.WorkflowsPermissions{
		RunWorkflowsFromForkPullRequests: new(false),
		SendSecretsAndVariables:          new(true),
	}}
	if got := orgRuleOutcome(t, "GSK519", f); got != StatusPass {
		t.Errorf("fork workflows disabled: got %v, want pass", got)
	}
}

func TestGSK520ExcessiveOrgOwners(t *testing.T) {
	owners := func(n int) []*github.User {
		users := make([]*github.User, n)
		for i := range users {
			users[i] = &github.User{Login: new("owner")}
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
