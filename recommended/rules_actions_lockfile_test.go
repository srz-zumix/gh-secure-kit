package recommended

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v93/github"
)

func fixtureActionsPolicy(t *testing.T, overrides map[string]any) json.RawMessage {
	t.Helper()
	policy := map[string]any{
		"id":          101,
		"name":        "fixture policy",
		"target":      "actions",
		"source_type": "Repository",
		"source":      "fixture-org/fixture-repo",
		"enforcement": "active",
		"rules":       []any{map[string]any{"type": "require_lockfile"}},
	}
	for key, value := range overrides {
		policy[key] = value
	}
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func fixtureWorkflowSelector(include, exclude []string) map[string]any {
	return map[string]any{"include": include, "exclude": exclude}
}

func fixtureRepoNameSelector(include, exclude []string) map[string]any {
	return map[string]any{"include": include, "exclude": exclude}
}

func fixtureOrgPolicy(t *testing.T, overrides map[string]any) json.RawMessage {
	t.Helper()
	fields := map[string]any{
		"source_type": "Organization",
		"source":      "fixture-org",
		"conditions": map[string]any{
			"repository_name": fixtureRepoNameSelector([]string{"~ALL"}, []string{}),
		},
	}
	for key, value := range overrides {
		fields[key] = value
	}
	return fixtureActionsPolicy(t, fields)
}

func TestRequireLockfileRepositoryCoverage(t *testing.T) {
	tests := []struct {
		name     string
		policies []json.RawMessage
		known    bool
		want     Status
	}{
		{"unavailable", nil, false, StatusSkip},
		{"known empty", nil, true, StatusFail},
		{"unconditional", []json.RawMessage{fixtureActionsPolicy(t, nil)}, true, StatusPass},
		{"empty workflow include", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"conditions": map[string]any{"workflow_path": fixtureWorkflowSelector([]string{}, []string{})},
		})}, true, StatusPass},
		{"all workflows", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"conditions": map[string]any{"workflow_path": fixtureWorkflowSelector([]string{"~ALL"}, []string{})},
		})}, true, StatusPass},
		{"excluded workflow", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"conditions": map[string]any{"workflow_path": fixtureWorkflowSelector([]string{"~ALL"}, []string{".github/workflows/fixture.yml"})},
		})}, true, StatusFail},
		{"one workflow", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"conditions": map[string]any{"workflow_path": fixtureWorkflowSelector([]string{".github/workflows/fixture.yml"}, []string{})},
		})}, true, StatusFail},
		{"unproven wildcard", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"conditions": map[string]any{"workflow_path": fixtureWorkflowSelector([]string{"**"}, []string{})},
		})}, true, StatusSkip},
		{"all combined with another include", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"conditions": map[string]any{"workflow_path": fixtureWorkflowSelector([]string{"~ALL", ".github/workflows/fixture.yml"}, []string{})},
		})}, true, StatusSkip},
		{"incomplete workflow condition", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"conditions": map[string]any{"workflow_path": map[string]any{"include": []string{"~ALL"}}},
		})}, true, StatusSkip},
		{"disabled", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{"enforcement": "disabled"})}, true, StatusFail},
		{"evaluate", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{"enforcement": "evaluate"})}, true, StatusFail},
		{"unknown enforcement", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{"enforcement": "future"})}, true, StatusSkip},
		{"other rule", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"rules": []any{map[string]any{"type": "restrict_action_events"}},
		})}, true, StatusFail},
		{"empty rules", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{"rules": []any{}})}, true, StatusFail},
		{"missing rules", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{"rules": nil})}, true, StatusSkip},
		{"future rule parameters", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"rules": []any{map[string]any{"type": "require_lockfile", "parameters": map[string]any{"future": true}}},
		})}, true, StatusSkip},
		{"empty rule parameters", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"rules": []any{map[string]any{"type": "require_lockfile", "parameters": map[string]any{}}},
		})}, true, StatusPass},
		{"unknown condition", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"conditions": map[string]any{"future_selector": map[string]any{}},
		})}, true, StatusSkip},
		{"unknown workflow property", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"conditions": map[string]any{"workflow_path": map[string]any{"include": []string{"~ALL"}, "exclude": []string{}, "future": true}},
		})}, true, StatusSkip},
		{"unknown policy property", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{"future_condition": true})}, true, StatusSkip},
		{"unknown source", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{"source_type": "Future"})}, true, StatusSkip},
		{"null conditions", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{"conditions": nil})}, true, StatusSkip},
		{"repository selector on repository policy", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"conditions": map[string]any{"repository_name": fixtureRepoNameSelector([]string{"~ALL"}, []string{})},
		})}, true, StatusSkip},
		{"applicable inherited organization policy", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"source_type": "Organization",
			"source":      "fixture-org",
			"conditions": map[string]any{
				"repository_name": fixtureRepoNameSelector([]string{"fixture-repo"}, []string{}),
				"workflow_path":   fixtureWorkflowSelector([]string{"~ALL"}, []string{}),
			},
		})}, true, StatusPass},
		{"applicable inherited enterprise policy", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"source_type": "Enterprise",
			"source":      "fixture-enterprise",
			"conditions": map[string]any{
				"organization_name": map[string]any{"include": []string{"fixture-org"}, "exclude": []string{}},
				"repository_id":     map[string]any{"repository_ids": []int64{101}},
			},
		})}, true, StatusPass},
		{"unknown inherited selector field", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"source_type": "Organization",
			"source":      "fixture-org",
			"conditions":  map[string]any{"repository_name": map[string]any{"include": []string{"fixture-repo"}, "future": true}},
		})}, true, StatusSkip},
		{"missing inherited name include", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"source_type": "Organization",
			"source":      "fixture-org",
			"conditions":  map[string]any{"repository_name": map[string]any{}},
		})}, true, StatusSkip},
		{"missing inherited property selector", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"source_type": "Organization",
			"source":      "fixture-org",
			"conditions":  map[string]any{"repository_property": map[string]any{}},
		})}, true, StatusSkip},
		{"unknown inherited property source", []json.RawMessage{fixtureActionsPolicy(t, map[string]any{
			"source_type": "Organization",
			"source":      "fixture-org",
			"conditions": map[string]any{"repository_property": map[string]any{
				"include": []any{map[string]any{"name": "fixture", "property_values": []string{"yes"}, "source": "future"}},
			}},
		})}, true, StatusSkip},
		{"partial policies do not combine", []json.RawMessage{
			fixtureActionsPolicy(t, map[string]any{"id": 101, "conditions": map[string]any{
				"workflow_path": fixtureWorkflowSelector([]string{".github/workflows/a.yml"}, []string{}),
			}}),
			fixtureActionsPolicy(t, map[string]any{"id": 102, "conditions": map[string]any{
				"workflow_path": fixtureWorkflowSelector([]string{".github/workflows/b.yml"}, []string{}),
			}}),
		}, true, StatusFail},
		{"unknown and universal", []json.RawMessage{
			fixtureActionsPolicy(t, map[string]any{"id": 101, "rules": nil}),
			fixtureActionsPolicy(t, map[string]any{"id": 102}),
		}, true, StatusPass},
		{"duplicate list entry", []json.RawMessage{fixtureActionsPolicy(t, nil), fixtureActionsPolicy(t, nil)}, true, StatusSkip},
		{"invalid JSON", []json.RawMessage{json.RawMessage(`{"id":`)}, true, StatusSkip},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkRequireLockfilePolicies(tt.policies, tt.known, ScopeRepository); got.Status != tt.want {
				t.Errorf("status = %s (%s), want %s", got.Status, got.Detail, tt.want)
			}
		})
	}
}

func TestRequireLockfileOrganizationCoverage(t *testing.T) {
	tests := []struct {
		name     string
		policies []json.RawMessage
		known    bool
		want     Status
	}{
		{"unavailable", nil, false, StatusSkip},
		{"known empty", nil, true, StatusFail},
		{"all repositories and workflows", []json.RawMessage{fixtureOrgPolicy(t, nil)}, true, StatusPass},
		{"all explicit workflows", []json.RawMessage{fixtureOrgPolicy(t, map[string]any{
			"conditions": map[string]any{
				"repository_name": fixtureRepoNameSelector([]string{"~ALL"}, []string{}),
				"workflow_path":   fixtureWorkflowSelector([]string{"~ALL"}, []string{}),
			},
		})}, true, StatusPass},
		{"selected repository", []json.RawMessage{fixtureOrgPolicy(t, map[string]any{
			"conditions": map[string]any{"repository_name": fixtureRepoNameSelector([]string{"fixture-repo"}, []string{})},
		})}, true, StatusFail},
		{"empty repository include is not all", []json.RawMessage{fixtureOrgPolicy(t, map[string]any{
			"conditions": map[string]any{"repository_name": fixtureRepoNameSelector([]string{}, []string{})},
		})}, true, StatusFail},
		{"excluded repository", []json.RawMessage{fixtureOrgPolicy(t, map[string]any{
			"conditions": map[string]any{"repository_name": fixtureRepoNameSelector([]string{"~ALL"}, []string{"fixture-repo"})},
		})}, true, StatusFail},
		{"repository ids", []json.RawMessage{fixtureOrgPolicy(t, map[string]any{
			"conditions": map[string]any{"repository_id": map[string]any{"repository_ids": []int64{101}}},
		})}, true, StatusFail},
		{"repository properties cannot prove all", []json.RawMessage{fixtureOrgPolicy(t, map[string]any{
			"conditions": map[string]any{"repository_property": map[string]any{
				"include": []any{map[string]any{"name": "fixture", "property_values": []string{"yes"}}}, "exclude": []any{},
			}},
		})}, true, StatusSkip},
		{"missing repository selector", []json.RawMessage{fixtureOrgPolicy(t, map[string]any{"conditions": map[string]any{}})}, true, StatusSkip},
		{"unknown repository selector field", []json.RawMessage{fixtureOrgPolicy(t, map[string]any{
			"conditions": map[string]any{"repository_name": map[string]any{"include": []string{"~ALL"}, "exclude": []string{}, "future": true}},
		})}, true, StatusSkip},
		{"repository wildcard not proven", []json.RawMessage{fixtureOrgPolicy(t, map[string]any{
			"conditions": map[string]any{"repository_name": fixtureRepoNameSelector([]string{"*"}, []string{})},
		})}, true, StatusSkip},
		{"one excluded workflow", []json.RawMessage{fixtureOrgPolicy(t, map[string]any{
			"conditions": map[string]any{
				"repository_name": fixtureRepoNameSelector([]string{"~ALL"}, []string{}),
				"workflow_path":   fixtureWorkflowSelector([]string{"~ALL"}, []string{".github/workflows/fixture.yml"}),
			},
		})}, true, StatusFail},
		{"enterprise policy applicable to organization", []json.RawMessage{fixtureOrgPolicy(t, map[string]any{
			"source_type": "Enterprise",
			"source":      "fixture-enterprise",
			"conditions": map[string]any{
				"organization_name": map[string]any{"include": []string{"fixture-org"}, "exclude": []string{}},
				"repository_name":   fixtureRepoNameSelector([]string{"~ALL"}, []string{}),
			},
		})}, true, StatusPass},
		{"repository policy cannot prove organization coverage", []json.RawMessage{fixtureActionsPolicy(t, nil)}, true, StatusSkip},
		{"partial policies do not combine", []json.RawMessage{
			fixtureOrgPolicy(t, map[string]any{"id": 101, "conditions": map[string]any{
				"repository_name": fixtureRepoNameSelector([]string{"fixture-a"}, []string{}),
			}}),
			fixtureOrgPolicy(t, map[string]any{"id": 102, "conditions": map[string]any{
				"repository_name": fixtureRepoNameSelector([]string{"fixture-b"}, []string{}),
			}}),
		}, true, StatusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkRequireLockfilePolicies(tt.policies, tt.known, ScopeOrganization); got.Status != tt.want {
				t.Errorf("status = %s (%s), want %s", got.Status, got.Detail, tt.want)
			}
		})
	}
}

func TestRequireLockfileRuleMetadataAndPermissions(t *testing.T) {
	for _, test := range []struct {
		id       string
		scope    Scope
		checkNil func(Rule) Outcome
		checkOff func(Rule) Outcome
	}{
		{
			id: "GSK146", scope: ScopeRepository,
			checkNil: func(r Rule) Outcome { return r.CheckRepo(&RepositoryFacts{}) },
			checkOff: func(r Rule) Outcome {
				return r.CheckRepo(&RepositoryFacts{ActionsPermissions: &github.ActionsPermissionsRepository{Enabled: false}})
			},
		},
		{
			id: "GSK526", scope: ScopeOrganization,
			checkNil: func(r Rule) Outcome { return r.CheckOrg(&OrganizationFacts{}) },
			checkOff: func(r Rule) Outcome {
				return r.CheckOrg(&OrganizationFacts{ActionsPermissions: &github.ActionsPermissions{EnabledRepositories: "none"}})
			},
		},
	} {
		t.Run(test.id, func(t *testing.T) {
			rule, ok := RuleByID(test.id)
			if !ok {
				t.Fatalf("%s not registered", test.id)
			}
			if rule.Scope != test.scope || rule.Severity != SeverityHigh || rule.Category != "actions" || rule.Fixable || rule.ApplyRepo != nil || rule.ApplyOrg != nil {
				t.Fatalf("unexpected metadata: %+v", rule)
			}
			if test.checkNil(rule).Status != StatusSkip || test.checkOff(rule).Status != StatusSkip {
				t.Fatal("unknown permissions and disabled Actions must skip")
			}
			if got := (Filter{IDs: []string{test.id}, OnlyFixable: true}).Apply(AllRules()); len(got) != 0 {
				t.Fatalf("non-fixable rule included in fixable-only filter: %v", got)
			}
			target := repository.Repository{Host: "github.example.test", Owner: "fixture-org", Name: "fixture-repo"}
			url := rule.settingsURL(target)
			if !strings.HasSuffix(url, "/settings/actions/policies") {
				t.Errorf("settings URL = %q", url)
			}
		})
	}
	if got := orgRuleOutcome(t, "GSK526", &OrganizationFacts{
		ActionsPermissions: &github.ActionsPermissions{EnabledRepositories: ""},
	}); got != StatusSkip {
		t.Errorf("unknown enabled repository selection: got %s, want skip", got)
	}
}
