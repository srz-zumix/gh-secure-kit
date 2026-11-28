package recommended

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v93/github"
)

func testSecurityObject(t *testing.T, fields map[string]string) map[string]json.RawMessage {
	t.Helper()
	object := make(map[string]json.RawMessage, len(fields))
	for key, value := range fields {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		object[key] = raw
	}
	return object
}

func testSecurityAnalysis(t *testing.T, fields map[string]string) map[string]json.RawMessage {
	t.Helper()
	analysis := make(map[string]json.RawMessage, len(fields))
	for key, value := range fields {
		raw, err := json.Marshal(map[string]string{"status": value})
		if err != nil {
			t.Fatal(err)
		}
		analysis[key] = raw
	}
	return analysis
}

func testSecurityDefault(t *testing.T, name, visibility string, fields map[string]string) securityDefaultConfiguration {
	t.Helper()
	config := testSecurityObject(t, fields)
	nameJSON, err := json.Marshal(name)
	if err != nil {
		t.Fatal(err)
	}
	config["name"] = nameJSON
	return securityDefaultConfiguration{DefaultForNewRepos: visibility, Configuration: config}
}

func securityRule(t *testing.T, id string) Rule {
	t.Helper()
	rule, ok := RuleByID(id)
	if !ok {
		t.Fatalf("rule %s not found", id)
	}
	return rule
}

func TestRepositorySecuritySettings(t *testing.T) {
	tests := []struct {
		id            string
		field         string
		prerequisites []string
	}{
		{"GSK147", "secret_scanning_validity_checks", []string{"secret_scanning"}},
		{"GSK148", "secret_scanning_non_provider_patterns", []string{"secret_scanning"}},
		{"GSK149", "secret_scanning_ai_detection", []string{"secret_scanning"}},
		{"GSK150", "secret_scanning_delegated_bypass", []string{"secret_scanning", "secret_scanning_push_protection"}},
		{"GSK151", "secret_scanning_delegated_alert_dismissal", []string{"secret_scanning"}},
		{"GSK152", "code_security", nil},
		{"GSK153", "advanced_security", nil},
	}
	for _, test := range tests {
		t.Run(test.id, func(t *testing.T) {
			rule := securityRule(t, test.id)
			for _, state := range []struct {
				value string
				want  Status
			}{{"enabled", StatusPass}, {"disabled", StatusFail}, {"not_set", StatusSkip}, {"", StatusSkip}} {
				fields := map[string]string{}
				for _, prerequisite := range test.prerequisites {
					fields[prerequisite] = "enabled"
				}
				if state.value != "" {
					fields[test.field] = state.value
				}
				facts := &RepositoryFacts{
					Repo:             &github.Repository{Visibility: new("private"), Owner: &github.User{Type: new("Organization")}},
					securityAnalysis: testSecurityAnalysis(t, fields),
				}
				if got := rule.CheckRepo(facts).Status; got != state.want {
					t.Errorf("%s = %s, want %s", state.value, got, state.want)
				}
			}
		})
	}
}

func TestRepositorySecurityApplicability(t *testing.T) {
	rule := securityRule(t, "GSK150")
	for _, test := range []struct {
		fields map[string]string
		want   Status
	}{
		{map[string]string{"secret_scanning": "disabled", "secret_scanning_push_protection": "enabled", "secret_scanning_delegated_bypass": "disabled"}, StatusSkip},
		{map[string]string{"secret_scanning": "enabled", "secret_scanning_push_protection": "disabled", "secret_scanning_delegated_bypass": "disabled"}, StatusSkip},
		{map[string]string{"secret_scanning_push_protection": "disabled", "secret_scanning_delegated_bypass": "disabled"}, StatusSkip},
		{map[string]string{"secret_scanning": "enabled", "secret_scanning_delegated_bypass": "enabled"}, StatusSkip},
		{map[string]string{"secret_scanning_push_protection": "enabled", "secret_scanning_delegated_bypass": "disabled"}, StatusFail},
	} {
		outcome := rule.CheckRepo(&RepositoryFacts{
			Repo:             &github.Repository{Owner: &github.User{Type: new("Organization")}},
			securityAnalysis: testSecurityAnalysis(t, test.fields),
		})
		if outcome.Status != test.want {
			t.Errorf("%v: got %s, want %s", test.fields, outcome.Status, test.want)
		}
		if test.want == StatusFail && !strings.Contains(outcome.Detail, "prerequisite status") {
			t.Errorf("unknown prerequisite missing from failure detail: %s", outcome.Detail)
		}
	}

	for _, repo := range []*github.Repository{nil, {}, {Owner: &github.User{Type: new("User")}}} {
		facts := &RepositoryFacts{Repo: repo, securityAnalysis: testSecurityAnalysis(t, map[string]string{"secret_scanning": "enabled", "secret_scanning_validity_checks": "disabled"})}
		if got := securityRule(t, "GSK147").CheckRepo(facts).Status; got != StatusSkip {
			t.Errorf("repository owner %v: got %s, want skip", repo, got)
		}
	}

	productRule := securityRule(t, "GSK152")
	for _, repo := range []*github.Repository{
		nil,
		{Visibility: new("public")},
		{Visibility: new("unexpected"), Private: new(true)},
	} {
		facts := &RepositoryFacts{Repo: repo, securityAnalysis: testSecurityAnalysis(t, map[string]string{"code_security": "disabled"})}
		if got := productRule.CheckRepo(facts).Status; got != StatusSkip {
			t.Errorf("repository visibility %v: got %s, want skip", repo, got)
		}
	}
	for _, test := range []struct {
		private bool
		want    Status
	}{{true, StatusFail}, {false, StatusSkip}} {
		facts := &RepositoryFacts{
			Repo:             &github.Repository{Private: new(test.private)},
			securityAnalysis: testSecurityAnalysis(t, map[string]string{"code_security": "disabled"}),
		}
		if got := productRule.CheckRepo(facts).Status; got != test.want {
			t.Errorf("private=%v with no visibility: got %s, want %s", test.private, got, test.want)
		}
	}
}

func TestOrganizationDefaultSecuritySettings(t *testing.T) {
	tests := []struct {
		id, field, enabled, disabled string
	}{
		{"GSK527", "dependency_graph", "enabled", "disabled"},
		{"GSK528", "dependency_graph_autosubmit_action", "enabled", "disabled"},
		{"GSK529", "dependabot_alerts", "enabled", "disabled"},
		{"GSK530", "dependabot_security_updates", "enabled", "disabled"},
		{"GSK531", "dependabot_delegated_alert_dismissal", "enabled", "disabled"},
		{"GSK532", "dependabot_reachability", "enabled", "disabled"},
		{"GSK533", "code_scanning_default_setup", "enabled", "disabled"},
		{"GSK534", "code_scanning_delegated_alert_dismissal", "enabled", "disabled"},
		{"GSK535", "secret_scanning", "enabled", "disabled"},
		{"GSK536", "secret_scanning_push_protection", "enabled", "disabled"},
		{"GSK537", "secret_scanning_delegated_bypass", "enabled", "disabled"},
		{"GSK538", "secret_scanning_validity_checks", "enabled", "disabled"},
		{"GSK539", "secret_scanning_non_provider_patterns", "enabled", "disabled"},
		{"GSK540", "secret_scanning_generic_secrets", "enabled", "disabled"},
		{"GSK541", "secret_scanning_generic_secrets_push_protection", "enabled", "disabled"},
		{"GSK542", "secret_scanning_delegated_alert_dismissal", "enabled", "disabled"},
		{"GSK543", "secret_scanning_extended_metadata", "enabled", "disabled"},
		{"GSK544", "private_vulnerability_reporting", "enabled", "disabled"},
		{"GSK545", "advanced_security", "enabled", "disabled"},
		{"GSK546", "code_security", "enabled", "disabled"},
		{"GSK547", "secret_protection", "enabled", "disabled"},
		{"GSK548", "enforcement", "enforced", "unenforced"},
	}
	for _, test := range tests {
		t.Run(test.id, func(t *testing.T) {
			rule := securityRule(t, test.id)
			for _, state := range []struct {
				value string
				want  Status
			}{{test.enabled, StatusPass}, {test.disabled, StatusFail}, {"not_set", StatusSkip}, {"", StatusSkip}} {
				fields := map[string]string{
					"dependency_graph":                "enabled",
					"dependabot_alerts":               "enabled",
					"secret_scanning":                 "enabled",
					"secret_scanning_push_protection": "enabled",
					"secret_scanning_validity_checks": "enabled",
					"secret_scanning_generic_secrets": "enabled",
					"advanced_security":               "not_set",
				}
				delete(fields, test.field)
				if state.value != "" {
					fields[test.field] = state.value
				}
				facts := &OrganizationFacts{
					securityDefaultsKnown: true,
					securityDefaults:      []securityDefaultConfiguration{testSecurityDefault(t, "fixture-default", "all", fields)},
				}
				if got := rule.CheckOrg(facts).Status; got != state.want {
					t.Errorf("%s = %s, want %s", state.value, got, state.want)
				}
			}
		})
	}
}

func TestOrganizationSecurityDefaultAggregation(t *testing.T) {
	rule := securityRule(t, "GSK527")
	enabled := testSecurityDefault(t, "fixture-public", "public", map[string]string{"dependency_graph": "enabled"})
	disabled := testSecurityDefault(t, "fixture-private", "private_and_internal", map[string]string{"dependency_graph": "disabled"})
	unknown := testSecurityDefault(t, "fixture-unknown", "all", map[string]string{"dependency_graph": "not_set"})
	ignoredPattern, err := CompileTargetPattern("fixture-private")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		known    bool
		defaults []securityDefaultConfiguration
		ignores  TargetIgnores
		want     Status
		targets  []string
		detail   string
	}{
		{"unavailable", false, nil, nil, StatusSkip, nil, ""},
		{"no defaults", true, nil, nil, StatusSkip, nil, ""},
		{"enabled and unknown", true, []securityDefaultConfiguration{enabled, unknown}, nil, StatusSkip, nil, "fixture-unknown"},
		{"disabled and unknown", true, []securityDefaultConfiguration{disabled, unknown}, nil, StatusFail, []string{"fixture-private"}, "fixture-unknown"},
		{"ignored and unknown", true, []securityDefaultConfiguration{disabled, unknown}, TargetIgnores{"GSK527": {ignoredPattern}}, StatusSkip, nil, "fixture-unknown"},
		{"ignored with passing default", true, []securityDefaultConfiguration{enabled, disabled}, TargetIgnores{"GSK527": {ignoredPattern}}, StatusSkip, nil, "fixture-private"},
		{"unknown visibility", true, []securityDefaultConfiguration{enabled, {DefaultForNewRepos: "unexpected"}}, nil, StatusSkip, nil, ""},
		{"missing configuration", true, []securityDefaultConfiguration{enabled, {DefaultForNewRepos: "private_and_internal"}}, nil, StatusSkip, nil, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := &OrganizationFacts{securityDefaultsKnown: test.known, securityDefaults: test.defaults, ignores: test.ignores}
			got := rule.CheckOrg(facts)
			if got.Status != test.want || !reflect.DeepEqual(got.Targets, test.targets) || !strings.Contains(got.Detail, test.detail) {
				t.Errorf("got %+v, want status %s, targets %v and detail %q", got, test.want, test.targets, test.detail)
			}
		})
	}
}

func TestOrganizationSecurityApplicabilityAndProducts(t *testing.T) {
	private := testSecurityDefault(t, "fixture-private", "private_and_internal", map[string]string{"private_vulnerability_reporting": "disabled"})
	public := testSecurityDefault(t, "fixture-public", "public", map[string]string{"private_vulnerability_reporting": "disabled"})
	reporting := securityRule(t, "GSK544")
	if got := reporting.CheckOrg(&OrganizationFacts{securityDefaultsKnown: true, securityDefaults: []securityDefaultConfiguration{private}}).Status; got != StatusSkip {
		t.Errorf("private-only vulnerability reporting = %s, want skip", got)
	}
	if got := reporting.CheckOrg(&OrganizationFacts{securityDefaultsKnown: true, securityDefaults: []securityDefaultConfiguration{private, public}}).Status; got != StatusFail {
		t.Errorf("public vulnerability reporting = %s, want fail", got)
	}

	bypass := securityRule(t, "GSK537")
	withoutPush := testSecurityDefault(t, "fixture-default", "all", map[string]string{
		"secret_scanning": "enabled", "secret_scanning_push_protection": "disabled", "secret_scanning_delegated_bypass": "disabled",
	})
	if got := bypass.CheckOrg(&OrganizationFacts{securityDefaultsKnown: true, securityDefaults: []securityDefaultConfiguration{withoutPush}}).Status; got != StatusSkip {
		t.Errorf("delegated bypass without push protection = %s, want skip", got)
	}
	for _, test := range []struct {
		fields     map[string]string
		want       Status
		incomplete bool
	}{
		{map[string]string{"secret_scanning_push_protection": "disabled", "secret_scanning_delegated_bypass": "disabled"}, StatusSkip, false},
		{map[string]string{"secret_scanning_push_protection": "enabled", "secret_scanning_delegated_bypass": "enabled"}, StatusSkip, false},
		{map[string]string{"secret_scanning_push_protection": "enabled", "secret_scanning_delegated_bypass": "disabled"}, StatusFail, true},
	} {
		config := testSecurityDefault(t, "fixture-default", "all", test.fields)
		got := bypass.CheckOrg(&OrganizationFacts{securityDefaultsKnown: true, securityDefaults: []securityDefaultConfiguration{config}})
		if got.Status != test.want || got.TargetsIncomplete != test.incomplete {
			t.Errorf("%v: got %+v, want %s and incomplete=%v", test.fields, got, test.want, test.incomplete)
		}
	}
	disabledBypass := testSecurityDefault(t, "fixture-enabled", "public", map[string]string{
		"secret_scanning": "enabled", "secret_scanning_push_protection": "enabled", "secret_scanning_delegated_bypass": "disabled",
	})
	mixed := bypass.CheckOrg(&OrganizationFacts{securityDefaultsKnown: true, securityDefaults: []securityDefaultConfiguration{withoutPush, disabledBypass}})
	if mixed.Status != StatusFail || !mixed.TargetsIncomplete || !strings.Contains(mixed.Detail, "not applicable") {
		t.Errorf("mixed failure and inapplicable configuration: got %+v", mixed)
	}

	for _, test := range []struct {
		advanced, id string
		want         Status
	}{
		{"enabled", "GSK546", StatusPass},
		{"enabled", "GSK547", StatusPass},
		{"code_security", "GSK546", StatusPass},
		{"code_security", "GSK547", StatusSkip},
		{"secret_protection", "GSK546", StatusSkip},
		{"secret_protection", "GSK547", StatusPass},
		{"disabled", "GSK546", StatusSkip},
		{"disabled", "GSK547", StatusSkip},
		{"code_security", "GSK545", StatusSkip},
	} {
		t.Run(test.advanced+"/"+test.id, func(t *testing.T) {
			config := testSecurityDefault(t, "fixture-private", "private_and_internal", map[string]string{"advanced_security": test.advanced})
			if got := securityRule(t, test.id).CheckOrg(&OrganizationFacts{securityDefaultsKnown: true, securityDefaults: []securityDefaultConfiguration{config}}).Status; got != test.want {
				t.Errorf("got %s, want %s", got, test.want)
			}
		})
	}
	for _, field := range []struct {
		id, name string
	}{
		{"GSK546", "code_security"},
		{"GSK547", "secret_protection"},
	} {
		for _, raw := range []string{"null", "true", `{}`, `"not_set"`} {
			config := testSecurityDefault(t, "fixture-private", "private_and_internal", map[string]string{"advanced_security": "enabled"})
			config.Configuration[field.name] = json.RawMessage(raw)
			facts := &OrganizationFacts{securityDefaultsKnown: true, securityDefaults: []securityDefaultConfiguration{config}}
			if got := securityRule(t, field.id).CheckOrg(facts).Status; got != StatusSkip {
				t.Errorf("%s = %s with advanced_security enabled: got %s, want skip", field.name, raw, got)
			}
		}
	}
	enforced := testSecurityDefault(t, "fixture-default", "all", map[string]string{"enforcement": "enterprise_enforced"})
	if got := securityRule(t, "GSK548").CheckOrg(&OrganizationFacts{securityDefaultsKnown: true, securityDefaults: []securityDefaultConfiguration{enforced}}).Status; got != StatusPass {
		t.Errorf("enterprise enforcement = %s, want pass", got)
	}
}

func TestAIScanSecuritySettings(t *testing.T) {
	for _, test := range []struct {
		id, field string
		scope     Scope
	}{
		{"GSK154", "pr_scan", ScopeRepository},
		{"GSK155", "repository_scan", ScopeRepository},
		{"GSK549", "pr_scan", ScopeOrganization},
		{"GSK550", "repository_scan", ScopeOrganization},
	} {
		t.Run(test.id, func(t *testing.T) {
			rule := securityRule(t, test.id)
			for _, state := range []struct {
				value string
				want  Status
			}{{"enabled", StatusPass}, {"disabled", StatusFail}, {"unknown", StatusSkip}, {"", StatusSkip}} {
				fields := map[string]string{}
				if state.value != "" {
					fields[test.field] = state.value
				}
				settings := testSecurityObject(t, fields)
				var got Outcome
				if test.scope == ScopeRepository {
					got = rule.CheckRepo(&RepositoryFacts{aiScanSettings: settings})
				} else {
					got = rule.CheckOrg(&OrganizationFacts{aiScanSettings: settings})
				}
				if got.Status != state.want {
					t.Errorf("%s = %s, want %s", state.value, got.Status, state.want)
				}
			}
		})
	}
}

func TestRepositorySecurityCollectionIsSelective(t *testing.T) {
	for _, test := range []struct {
		id        string
		rootCalls int
		aiCalls   int
		want      Status
	}{
		{"GSK101", 1, 0, StatusFail},
		{"GSK148", 2, 0, StatusFail},
		{"GSK154", 1, 1, StatusPass},
		{"GSK155", 1, 1, StatusSkip},
	} {
		t.Run(test.id, func(t *testing.T) {
			rootCalls, aiCalls := 0, 0
			client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/repos/fixture-org/fixture-repo":
					rootCalls++
					return rulesetResponse(request, 200, `{"default_branch":"main","private":true,"owner":{"type":"Organization"},"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_non_provider_patterns":{"status":"disabled"}}}`), nil
				case "/repos/fixture-org/fixture-repo/code-scanning/ai-scan":
					aiCalls++
					return rulesetResponse(request, 200, `{"pr_scan":"enabled"}`), nil
				default:
					return rulesetResponse(request, 404, `{"message":"Not Found"}`), nil
				}
			}))
			rule := securityRule(t, test.id)
			target := repository.Repository{Host: "github.example.test", Owner: "fixture-org", Name: "fixture-repo"}
			facts, err := CollectRepositoryFacts(context.Background(), client, target, []Rule{rule})
			if err != nil {
				t.Fatal(err)
			}
			if got := rule.CheckRepo(facts).Status; rootCalls != test.rootCalls || aiCalls != test.aiCalls || got != test.want {
				t.Errorf("root=%d, AI=%d, status=%s; want %d, %d, %s", rootCalls, aiCalls, got, test.rootCalls, test.aiCalls, test.want)
			}
		})
	}
}

func TestAIScanCollectionErrors(t *testing.T) {
	for _, test := range []struct {
		status  int
		message string
		wantErr bool
	}{
		{http.StatusUnauthorized, "denied", true},
		{http.StatusForbidden, "denied", true},
		{http.StatusForbidden, "Code Security must be enabled for this repository to use code scanning.", false},
		{http.StatusNotFound, "unavailable", false},
		{http.StatusInternalServerError, "unavailable", false},
	} {
		t.Run(fmt.Sprintf("%d/%s", test.status, test.message), func(t *testing.T) {
			client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/repos/fixture-org/fixture-repo":
					return rulesetResponse(request, 200, `{"default_branch":"main","private":true}`), nil
				case "/repos/fixture-org/fixture-repo/code-scanning/ai-scan":
					return rulesetResponse(request, test.status, fmt.Sprintf(`{"message":%q}`, test.message)), nil
				default:
					return rulesetResponse(request, 404, `{"message":"Not Found"}`), nil
				}
			}))
			rule := securityRule(t, "GSK154")
			target := repository.Repository{Owner: "fixture-org", Name: "fixture-repo"}
			facts, err := CollectRepositoryFacts(context.Background(), client, target, []Rule{rule})
			if test.wantErr {
				var response *github.ErrorResponse
				if !errors.As(err, &response) || response.Response.StatusCode != test.status {
					t.Fatalf("got %v, want HTTP %d", err, test.status)
				}
			} else if err != nil || rule.CheckRepo(facts).Status != StatusSkip {
				t.Fatalf("got facts=%v, error=%v; want skip", facts, err)
			}
		})
	}
}

func TestAdditionalSecuritySettingCollectionErrors(t *testing.T) {
	for _, scope := range []struct {
		name, id, path string
	}{
		{"repository analysis", "GSK148", "/repos/fixture-org/fixture-repo"},
		{"organization AI Scan", "GSK549", "/orgs/fixture-org/code-scanning/ai-scan"},
	} {
		for _, test := range []struct {
			status  int
			body    string
			wantErr bool
		}{
			{http.StatusUnauthorized, `{"message":"denied"}`, true},
			{http.StatusForbidden, `{"message":"denied"}`, true},
			{http.StatusNotFound, `{"message":"unavailable"}`, false},
			{http.StatusInternalServerError, `{"message":"unavailable"}`, false},
			{http.StatusOK, `{"invalid":`, false},
			{http.StatusOK, `null`, false},
		} {
			t.Run(fmt.Sprintf("%s/%d/%s", scope.name, test.status, test.body), func(t *testing.T) {
				rootCalls := 0
				client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
					if request.URL.Path == "/repos/fixture-org/fixture-repo" {
						rootCalls++
						if rootCalls == 1 {
							return rulesetResponse(request, 200, `{"default_branch":"main","private":true}`), nil
						}
					}
					if request.URL.Path == scope.path {
						return rulesetResponse(request, test.status, test.body), nil
					}
					if request.URL.Path == "/orgs/fixture-org" {
						return rulesetResponse(request, 200, `{"login":"fixture-org"}`), nil
					}
					return rulesetResponse(request, 404, `{"message":"Not Found"}`), nil
				}))
				rule := securityRule(t, scope.id)
				target := repository.Repository{Owner: "fixture-org"}
				var outcome Outcome
				var err error
				if rule.Scope == ScopeRepository {
					target.Name = "fixture-repo"
					var facts *RepositoryFacts
					facts, err = CollectRepositoryFacts(context.Background(), client, target, []Rule{rule})
					if err == nil {
						outcome = rule.CheckRepo(facts)
					}
				} else {
					var facts *OrganizationFacts
					facts, err = CollectOrganizationFacts(context.Background(), client, target, []Rule{rule})
					if err == nil {
						outcome = rule.CheckOrg(facts)
					}
				}
				if test.wantErr {
					var response *github.ErrorResponse
					if !errors.As(err, &response) || response.Response.StatusCode != test.status {
						t.Fatalf("got %v, want HTTP %d", err, test.status)
					}
				} else if err != nil || outcome.Status != StatusSkip {
					t.Fatalf("outcome=%+v, error=%v; want skip", outcome, err)
				}
			})
		}
	}
}

func TestAIScanCollectionWhenCodeSecurityDisabled(t *testing.T) {
	aiCalls := 0
	client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/repos/fixture-org/fixture-repo":
			return rulesetResponse(request, 200, `{"default_branch":"main","private":true}`), nil
		case "/repos/fixture-org/fixture-repo/code-scanning/default-setup":
			return rulesetResponse(request, 403, `{"message":"Code Security must be enabled for this repository to use code scanning."}`), nil
		case "/repos/fixture-org/fixture-repo/code-scanning/ai-scan":
			aiCalls++
			return rulesetResponse(request, 403, `{"message":"denied"}`), nil
		default:
			return rulesetResponse(request, 404, `{"message":"Not Found"}`), nil
		}
	}))
	rule := securityRule(t, "GSK154")
	facts, err := CollectRepositoryFacts(context.Background(), client, repository.Repository{Owner: "fixture-org", Name: "fixture-repo"}, []Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if got := rule.CheckRepo(facts).Status; aiCalls != 0 || got != StatusSkip {
		t.Errorf("AI calls=%d status=%s, want zero calls and skip", aiCalls, got)
	}
}

func TestAIScanCollectionPropagatesCancellation(t *testing.T) {
	for _, canceled := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(canceled.Error(), func(t *testing.T) {
			client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/repos/fixture-org/fixture-repo":
					return rulesetResponse(request, 200, `{"default_branch":"main","private":true}`), nil
				case "/repos/fixture-org/fixture-repo/code-scanning/ai-scan":
					return nil, canceled
				default:
					return rulesetResponse(request, 404, `{"message":"Not Found"}`), nil
				}
			}))
			rule := securityRule(t, "GSK154")
			_, err := CollectRepositoryFacts(context.Background(), client, repository.Repository{Owner: "fixture-org", Name: "fixture-repo"}, []Rule{rule})
			if !errors.Is(err, canceled) {
				t.Fatalf("got %v, want %v", err, canceled)
			}
		})
	}
}

func TestOrganizationSecurityCollectionUsesOneSnapshot(t *testing.T) {
	defaultCalls := 0
	client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/orgs/fixture-org":
			return rulesetResponse(request, 200, `{"login":"fixture-org"}`), nil
		case "/orgs/fixture-org/code-security/configurations/defaults":
			defaultCalls++
			if defaultCalls == 1 {
				return rulesetResponse(request, 200, `[{"default_for_new_repos":"public","configuration":{"name":"fixture-old","dependabot_alerts":"enabled","dependabot_reachability":"enabled"}}]`), nil
			}
			return rulesetResponse(request, 200, `[{"default_for_new_repos":"private_and_internal","configuration":{"name":"fixture-new","dependabot_alerts":"enabled","dependabot_reachability":"disabled"}},{"default_for_new_repos":"public","configuration":{"name":"fixture-unknown","dependabot_alerts":"enabled","dependabot_reachability":"not_set"}}]`), nil
		default:
			return rulesetResponse(request, 404, `{"message":"Not Found"}`), nil
		}
	}))
	rule := securityRule(t, "GSK532")
	target := repository.Repository{Owner: "fixture-org"}
	results, _, err := EvaluateOrganization(context.Background(), client, target, []Rule{rule}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want one", len(results))
	}
	got := results[0]
	if defaultCalls != 2 || got.Status != StatusFail || !got.TargetsIncomplete || !reflect.DeepEqual(got.Targets, []string{"fixture-new"}) {
		t.Errorf("calls=%d, outcome=%+v; want the new snapshot's failing configuration", defaultCalls, got)
	}
	base := &Config{Ignore: []IgnoreEntry{{ID: "GSK532", Targets: []string{"fixture-unknown"}}}}
	want := []IgnoreEntry{{ID: "GSK532", Targets: []string{"fixture-new", "fixture-unknown"}}}
	if golden := GoldenConfig(base, results, true); !reflect.DeepEqual(golden.Ignore, want) {
		t.Errorf("pruned ignores = %v, want %v", golden.Ignore, want)
	}
}

func TestOrganizationSecurityCollectionIsSelective(t *testing.T) {
	for _, test := range []struct {
		id           string
		defaultCalls int
		aiCalls      int
	}{
		{"GSK501", 1, 0},
		{"GSK527", 2, 0},
		{"GSK549", 1, 1},
		{"GSK550", 1, 1},
	} {
		t.Run(test.id, func(t *testing.T) {
			defaultCalls, aiCalls := 0, 0
			client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/orgs/fixture-org":
					return rulesetResponse(request, 200, `{"login":"fixture-org"}`), nil
				case "/orgs/fixture-org/code-security/configurations/defaults":
					defaultCalls++
					return rulesetResponse(request, 200, `[]`), nil
				case "/orgs/fixture-org/code-scanning/ai-scan":
					aiCalls++
					return rulesetResponse(request, 200, `{"pr_scan":"enabled","repository_scan":"disabled"}`), nil
				default:
					return rulesetResponse(request, 404, `{"message":"Not Found"}`), nil
				}
			}))
			rule := securityRule(t, test.id)
			facts, err := CollectOrganizationFacts(context.Background(), client, repository.Repository{Owner: "fixture-org"}, []Rule{rule})
			if err != nil {
				t.Fatal(err)
			}
			if defaultCalls != test.defaultCalls || aiCalls != test.aiCalls {
				t.Errorf("defaults=%d AI=%d, want %d and %d", defaultCalls, aiCalls, test.defaultCalls, test.aiCalls)
			}
			if test.id == "GSK549" && rule.CheckOrg(facts).Status != StatusPass {
				t.Error("enabled organization AI Scan did not pass")
			}
			if test.id == "GSK550" && rule.CheckOrg(facts).Status != StatusFail {
				t.Error("disabled organization repository AI Scan did not fail")
			}
		})
	}
}

func TestOrganizationSecurityDefaultsCollectionErrors(t *testing.T) {
	for _, test := range []struct {
		status  int
		body    string
		wantErr bool
	}{
		{http.StatusUnauthorized, `{"message":"denied"}`, true},
		{http.StatusForbidden, `{"message":"denied"}`, true},
		{http.StatusNotFound, `{"message":"unavailable"}`, false},
		{http.StatusInternalServerError, `{"message":"unavailable"}`, false},
		{http.StatusOK, `null`, false},
		{http.StatusOK, `{"unexpected":"object"}`, false},
	} {
		t.Run(fmt.Sprintf("%d/%s", test.status, test.body), func(t *testing.T) {
			defaultCalls := 0
			client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/orgs/fixture-org":
					return rulesetResponse(request, 200, `{"login":"fixture-org"}`), nil
				case "/orgs/fixture-org/code-security/configurations/defaults":
					defaultCalls++
					if defaultCalls == 1 {
						return rulesetResponse(request, 200, `[]`), nil
					}
					return rulesetResponse(request, test.status, test.body), nil
				default:
					return rulesetResponse(request, 404, `{"message":"Not Found"}`), nil
				}
			}))
			rule := securityRule(t, "GSK527")
			facts, err := CollectOrganizationFacts(context.Background(), client, repository.Repository{Owner: "fixture-org"}, []Rule{rule})
			if test.wantErr {
				var response *github.ErrorResponse
				if !errors.As(err, &response) || response.Response.StatusCode != test.status {
					t.Fatalf("got %v, want HTTP %d", err, test.status)
				}
			} else if err != nil || rule.CheckOrg(facts).Status != StatusSkip {
				t.Fatalf("got facts=%v, error=%v; want skip", facts, err)
			}
		})
	}
}
