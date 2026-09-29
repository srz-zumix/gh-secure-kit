package recommended

import (
	"testing"

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

	f = &RepositoryFacts{EnvironmentsKnown: true, Environments: []*github.Environment{
		{Name: github.Ptr("production"), DeploymentBranchPolicy: &github.BranchPolicy{ProtectedBranches: github.Ptr(true)}},
	}}
	if got := ruleOutcome(t, "GSK137", f); got != StatusPass {
		t.Errorf("restricted to protected branches: got %v, want pass", got)
	}
}
