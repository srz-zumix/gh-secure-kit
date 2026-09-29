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
