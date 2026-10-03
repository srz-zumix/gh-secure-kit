package recommended

import (
	"testing"

	"github.com/google/go-github/v90/github"
)

func TestGSK132DefaultWorkflowPermissionsWrite(t *testing.T) {
	if got := ruleOutcome(t, "GSK132", &RepositoryFacts{}); got != StatusSkip {
		t.Errorf("unknown permissions: got %v, want skip", got)
	}

	f := &RepositoryFacts{DefaultWorkflowPermissions: &github.DefaultWorkflowPermissionRepository{
		DefaultWorkflowPermissions: github.Ptr("write"),
	}}
	if got := ruleOutcome(t, "GSK132", f); got != StatusFail {
		t.Errorf("write: got %v, want fail", got)
	}

	f = &RepositoryFacts{DefaultWorkflowPermissions: &github.DefaultWorkflowPermissionRepository{
		DefaultWorkflowPermissions: github.Ptr("read"),
	}}
	if got := ruleOutcome(t, "GSK132", f); got != StatusPass {
		t.Errorf("read: got %v, want pass", got)
	}
}

func TestGSK133ActionsCanApprovePullRequests(t *testing.T) {
	if got := ruleOutcome(t, "GSK133", &RepositoryFacts{}); got != StatusSkip {
		t.Errorf("unknown permissions: got %v, want skip", got)
	}

	f := &RepositoryFacts{DefaultWorkflowPermissions: &github.DefaultWorkflowPermissionRepository{
		CanApprovePullRequestReviews: github.Ptr(true),
	}}
	if got := ruleOutcome(t, "GSK133", f); got != StatusFail {
		t.Errorf("enabled: got %v, want fail", got)
	}

	f = &RepositoryFacts{DefaultWorkflowPermissions: &github.DefaultWorkflowPermissionRepository{
		CanApprovePullRequestReviews: github.Ptr(false),
	}}
	if got := ruleOutcome(t, "GSK133", f); got != StatusPass {
		t.Errorf("disabled: got %v, want pass", got)
	}
}

func TestGSK134ForkPRContributorApprovalPolicy(t *testing.T) {
	if got := ruleOutcome(t, "GSK134", &RepositoryFacts{}); got != StatusSkip {
		t.Errorf("unknown policy: got %v, want skip", got)
	}

	f := &RepositoryFacts{ForkPRContributorApproval: &github.ContributorApprovalPermissions{
		ApprovalPolicy: "first_time_contributors_new_to_github",
	}}
	if got := ruleOutcome(t, "GSK134", f); got != StatusFail {
		t.Errorf("loose policy: got %v, want fail", got)
	}

	f = &RepositoryFacts{ForkPRContributorApproval: &github.ContributorApprovalPermissions{
		ApprovalPolicy: "all_external_contributors",
	}}
	if got := ruleOutcome(t, "GSK134", f); got != StatusPass {
		t.Errorf("strict policy: got %v, want pass", got)
	}
}

func TestGSK138SHAPinningRequired(t *testing.T) {
	tests := []struct {
		name string
		perm *github.ActionsPermissionsRepository
		want Status
	}{
		{"unknown permissions", nil, StatusSkip},
		{"actions disabled", &github.ActionsPermissionsRepository{Enabled: github.Ptr(false)}, StatusSkip},
		{"not required", &github.ActionsPermissionsRepository{Enabled: github.Ptr(true)}, StatusFail},
		{"required", &github.ActionsPermissionsRepository{Enabled: github.Ptr(true), SHAPinningRequired: github.Ptr(true)}, StatusPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ruleOutcome(t, "GSK138", &RepositoryFacts{ActionsPermissions: tt.perm}); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGSK141PrivateForkPRWorkflows(t *testing.T) {
	private := &github.Repository{Visibility: github.Ptr("private")}
	tests := []struct {
		name  string
		repo  *github.Repository
		perms *github.WorkflowsPermissions
		want  Status
	}{
		{"public repository", &github.Repository{Visibility: github.Ptr("public")}, nil, StatusSkip},
		{"unknown settings", private, nil, StatusSkip},
		{"fork workflows disabled", private, &github.WorkflowsPermissions{
			RunWorkflowsFromForkPullRequests: github.Ptr(false),
			SendWriteTokensToWorkflows:       github.Ptr(true),
		}, StatusPass},
		{"write tokens sent", private, &github.WorkflowsPermissions{
			RunWorkflowsFromForkPullRequests: github.Ptr(true),
			SendWriteTokensToWorkflows:       github.Ptr(true),
		}, StatusFail},
		{"secrets sent", private, &github.WorkflowsPermissions{
			RunWorkflowsFromForkPullRequests: github.Ptr(true),
			SendSecretsAndVariables:          github.Ptr(true),
		}, StatusFail},
		{"nothing sensitive sent", private, &github.WorkflowsPermissions{
			RunWorkflowsFromForkPullRequests: github.Ptr(true),
		}, StatusPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &RepositoryFacts{Repo: tt.repo, PrivateForkPRWorkflows: tt.perms}
			if got := ruleOutcome(t, "GSK141", f); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRestrictedForkPRWorkflowSettingsKeepsOtherSettings(t *testing.T) {
	got := restrictedForkPRWorkflowSettings(&github.WorkflowsPermissions{
		RunWorkflowsFromForkPullRequests:  github.Ptr(true),
		SendWriteTokensToWorkflows:        github.Ptr(true),
		SendSecretsAndVariables:           github.Ptr(true),
		RequireApprovalForForkPRWorkflows: github.Ptr(true),
	})
	if !got.RunWorkflowsFromForkPullRequests || got.SendWriteTokensToWorkflows == nil || *got.SendWriteTokensToWorkflows ||
		got.SendSecretsAndVariables == nil || *got.SendSecretsAndVariables ||
		got.RequireApprovalForForkPRWorkflows == nil || !*got.RequireApprovalForForkPRWorkflows {
		t.Errorf("unexpected restricted settings: %+v", got)
	}
}
