package recommended

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path"
	"testing"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v90/github"
)

func TestGSK135EnvironmentRequiredReviewers(t *testing.T) {
	if got := ruleOutcome(t, "GSK135", &RepositoryFacts{}); got != StatusSkip {
		t.Errorf("unknown environments: got %v, want skip", got)
	}

	if got := ruleOutcome(t, "GSK135", &RepositoryFacts{EnvironmentsKnown: true}); got != StatusSkip {
		t.Errorf("unknown environment secrets: got %v, want skip", got)
	}

	f := &RepositoryFacts{EnvironmentsKnown: true, EnvironmentSecretsKnown: true}
	if got := ruleOutcome(t, "GSK135", f); got != StatusPass {
		t.Errorf("no environments: got %v, want pass", got)
	}

	f = &RepositoryFacts{EnvironmentsKnown: true, EnvironmentSecretsKnown: true, Environments: []*github.Environment{
		{Name: github.Ptr("production")},
	}}
	if got := ruleOutcome(t, "GSK135", f); got != StatusPass {
		t.Errorf("environment without secrets: got %v, want pass", got)
	}

	f = &RepositoryFacts{
		EnvironmentsKnown: true, EnvironmentSecretsKnown: true,
		Environments: []*github.Environment{
			{Name: github.Ptr("production")},
		},
		EnvironmentSecrets: map[string][]*github.Secret{
			"production": {{Name: "TOKEN"}},
		},
	}
	if got := ruleOutcome(t, "GSK135", f); got != StatusFail {
		t.Errorf("environment with secrets but no protection rules: got %v, want fail", got)
	}

	f = &RepositoryFacts{
		EnvironmentsKnown: true, EnvironmentSecretsKnown: true,
		Environments: []*github.Environment{
			{Name: github.Ptr("production"), ProtectionRules: []*github.ProtectionRule{
				{Type: github.Ptr("required_reviewers"), Reviewers: []*github.RequiredReviewer{{Type: github.Ptr("User")}}},
			}},
		},
		EnvironmentSecrets: map[string][]*github.Secret{
			"production": {{Name: "TOKEN"}},
		},
	}
	if got := ruleOutcome(t, "GSK135", f); got != StatusPass {
		t.Errorf("environment with secrets and required reviewers configured: got %v, want pass", got)
	}
}

func TestGSK136EnvironmentAllowsSelfReview(t *testing.T) {
	if got := ruleOutcome(t, "GSK136", &RepositoryFacts{}); got != StatusSkip {
		t.Errorf("unknown environments: got %v, want skip", got)
	}

	if got := ruleOutcome(t, "GSK136", &RepositoryFacts{EnvironmentsKnown: true}); got != StatusSkip {
		t.Errorf("unknown environment secrets: got %v, want skip", got)
	}

	f := &RepositoryFacts{
		EnvironmentsKnown: true, EnvironmentSecretsKnown: true,
		Environments: []*github.Environment{
			{Name: github.Ptr("production"), ProtectionRules: []*github.ProtectionRule{
				{
					Type:              github.Ptr("required_reviewers"),
					Reviewers:         []*github.RequiredReviewer{{Type: github.Ptr("User")}},
					PreventSelfReview: github.Ptr(false),
				},
			}},
		},
	}
	if got := ruleOutcome(t, "GSK136", f); got != StatusPass {
		t.Errorf("environment without secrets allowing self-review: got %v, want pass", got)
	}

	f = &RepositoryFacts{
		EnvironmentsKnown: true, EnvironmentSecretsKnown: true,
		Environments: []*github.Environment{
			{Name: github.Ptr("production"), ProtectionRules: []*github.ProtectionRule{
				{
					Type:              github.Ptr("required_reviewers"),
					Reviewers:         []*github.RequiredReviewer{{Type: github.Ptr("User")}},
					PreventSelfReview: github.Ptr(false),
				},
			}},
		},
		EnvironmentSecrets: map[string][]*github.Secret{
			"production": {{Name: "TOKEN"}},
		},
	}
	if got := ruleOutcome(t, "GSK136", f); got != StatusFail {
		t.Errorf("environment with secrets allowing self-review: got %v, want fail", got)
	}

	f = &RepositoryFacts{
		EnvironmentsKnown: true, EnvironmentSecretsKnown: true,
		Environments: []*github.Environment{
			{Name: github.Ptr("production"), ProtectionRules: []*github.ProtectionRule{
				{
					Type:              github.Ptr("required_reviewers"),
					Reviewers:         []*github.RequiredReviewer{{Type: github.Ptr("User")}},
					PreventSelfReview: github.Ptr(true),
				},
			}},
		},
		EnvironmentSecrets: map[string][]*github.Secret{
			"production": {{Name: "TOKEN"}},
		},
	}
	if got := ruleOutcome(t, "GSK136", f); got != StatusPass {
		t.Errorf("environment with secrets and self-review prevented: got %v, want pass", got)
	}
}

func TestGSK137EnvironmentDeploymentBranchPolicy(t *testing.T) {
	if got := ruleOutcome(t, "GSK137", &RepositoryFacts{}); got != StatusSkip {
		t.Errorf("unknown environments: got %v, want skip", got)
	}

	f := &RepositoryFacts{EnvironmentsKnown: true, Environments: []*github.Environment{
		{Name: github.Ptr("production")},
	}}
	if got := ruleOutcome(t, "GSK137", f); got != StatusFail {
		t.Errorf("no deployment branch policy: got %v, want fail", got)
	}

	// "Protected branches only" without any confirmed branch protection is
	// effectively unrestricted on GitHub, so the outcome is indeterminate rather
	// than a false pass.
	f = &RepositoryFacts{EnvironmentsKnown: true, Environments: []*github.Environment{
		{Name: github.Ptr("production"), DeploymentBranchPolicy: &github.BranchPolicy{ProtectedBranches: github.Ptr(true)}},
	}}
	if got := ruleOutcome(t, "GSK137", f); got != StatusSkip {
		t.Errorf("protected branches without confirmed protection: got %v, want skip", got)
	}

	// With confirmed default-branch protection, "protected branches only" does
	// restrict which branches can deploy.
	f = &RepositoryFacts{
		EnvironmentsKnown: true,
		ProtectionKnown:   true,
		Protection:        &github.Protection{},
		Environments: []*github.Environment{
			{Name: github.Ptr("production"), DeploymentBranchPolicy: &github.BranchPolicy{ProtectedBranches: github.Ptr(true)}},
		},
	}
	if got := ruleOutcome(t, "GSK137", f); got != StatusPass {
		t.Errorf("protected branches with confirmed protection: got %v, want pass", got)
	}

	// An explicit allow-list of branch name patterns always restricts.
	f = &RepositoryFacts{EnvironmentsKnown: true, Environments: []*github.Environment{
		{Name: github.Ptr("production"), DeploymentBranchPolicy: &github.BranchPolicy{CustomBranchPolicies: github.Ptr(true)}},
	}}
	if got := ruleOutcome(t, "GSK137", f); got != StatusPass {
		t.Errorf("custom branch policies: got %v, want pass", got)
	}

	// A definitely-unrestricted environment fails even when another environment
	// is only indeterminate.
	f = &RepositoryFacts{EnvironmentsKnown: true, Environments: []*github.Environment{
		{Name: github.Ptr("staging"), DeploymentBranchPolicy: &github.BranchPolicy{ProtectedBranches: github.Ptr(true)}},
		{Name: github.Ptr("production")},
	}}
	if got := ruleOutcome(t, "GSK137", f); got != StatusFail {
		t.Errorf("mixed unrestricted and indeterminate: got %v, want fail", got)
	}
}

// gsk136SecretEnvironment builds an environment that allows self-review, with a
// wait timer, a required reviewer, and a deployment branch policy that
// remediation must preserve when it enables prevent-self-review.
func gsk136SecretEnvironment(name string) *github.Environment {
	return &github.Environment{
		Name:                   github.Ptr(name),
		DeploymentBranchPolicy: &github.BranchPolicy{ProtectedBranches: github.Ptr(true)},
		ProtectionRules: []*github.ProtectionRule{
			{Type: github.Ptr("wait_timer"), WaitTimer: github.Ptr(30)},
			{
				Type:              github.Ptr("required_reviewers"),
				PreventSelfReview: github.Ptr(false),
				Reviewers:         []*github.RequiredReviewer{{Type: github.Ptr("User"), Reviewer: &github.User{ID: github.Ptr(int64(42))}}},
			},
		},
	}
}

func TestGSK136ApplyRepoUpdatesOnlySecretBearingEnvironments(t *testing.T) {
	rule, ok := RuleByID("GSK136")
	if !ok || rule.ApplyRepo == nil {
		t.Fatal("GSK136 rule with ApplyRepo not found")
	}

	// "staging" has no secrets, so remediation must leave it untouched even
	// though its configuration also allows self-review.
	f := &RepositoryFacts{
		EnvironmentsKnown: true, EnvironmentSecretsKnown: true,
		Environments: []*github.Environment{
			gsk136SecretEnvironment("production"),
			gsk136SecretEnvironment("staging"),
		},
		EnvironmentSecrets: map[string][]*github.Secret{
			"production": {{Name: "TOKEN"}},
		},
	}

	var updated []string
	var lastBody github.CreateUpdateEnvironment
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPut {
			t.Errorf("unexpected method %s", req.Method)
		}
		updated = append(updated, path.Base(req.URL.Path))
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if err := json.Unmarshal(body, &lastBody); err != nil {
			t.Fatalf("unmarshal request body: %v", err)
		}
		return rulesetResponse(req, http.StatusOK, "{}"), nil
	})

	repo := repository.Repository{Owner: "OWNER", Name: "REPO"}
	if err := rule.ApplyRepo(context.Background(), newRulesetTestClient(t, transport), repo, f); err != nil {
		t.Fatalf("ApplyRepo() error = %v", err)
	}

	if len(updated) != 1 || updated[0] != "production" {
		t.Fatalf("updated environments = %v, want [production]", updated)
	}
	if !lastBody.GetPreventSelfReview() {
		t.Error("PreventSelfReview was not enabled")
	}
	if lastBody.GetWaitTimer() != 30 {
		t.Errorf("wait timer = %d, want 30 (existing settings not preserved)", lastBody.GetWaitTimer())
	}
	if lastBody.DeploymentBranchPolicy == nil || !lastBody.DeploymentBranchPolicy.GetProtectedBranches() {
		t.Error("deployment branch policy was not preserved")
	}
	if len(lastBody.Reviewers) != 1 || lastBody.Reviewers[0].GetID() != 42 {
		t.Errorf("reviewers = %+v, want a single reviewer with id 42", lastBody.Reviewers)
	}
}

func TestGSK136ApplyRepoPropagatesUpdateError(t *testing.T) {
	rule, ok := RuleByID("GSK136")
	if !ok || rule.ApplyRepo == nil {
		t.Fatal("GSK136 rule with ApplyRepo not found")
	}

	f := &RepositoryFacts{
		EnvironmentsKnown: true, EnvironmentSecretsKnown: true,
		Environments: []*github.Environment{gsk136SecretEnvironment("production")},
		EnvironmentSecrets: map[string][]*github.Secret{
			"production": {{Name: "TOKEN"}},
		},
	}

	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return rulesetResponse(req, http.StatusForbidden, `{"message":"forbidden"}`), nil
	})

	repo := repository.Repository{Owner: "OWNER", Name: "REPO"}
	if err := rule.ApplyRepo(context.Background(), newRulesetTestClient(t, transport), repo, f); err == nil {
		t.Fatal("ApplyRepo() error = nil, want update error to propagate")
	}
}
