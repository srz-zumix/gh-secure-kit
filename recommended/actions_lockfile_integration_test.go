package recommended

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"testing"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v93/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

type lockfileFixtureResponse struct {
	status int
	body   string
	next   bool
}

type lockfileFixtureAPI struct {
	t                 *testing.T
	scope             Scope
	permission        lockfileFixtureResponse
	pages             map[int]lockfileFixtureResponse
	details           map[string]lockfileFixtureResponse
	policyCalls       int
	detailCalls       int
	unexpectedMethods []string
}

func (api *lockfileFixtureAPI) root() string {
	if api.scope == ScopeOrganization {
		return "/orgs/fixture-org"
	}
	return "/repos/fixture-org/fixture-repo"
}

func (api *lockfileFixtureAPI) client() *gh.GitHubClient {
	api.t.Helper()
	return newRulesetTestClient(api.t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			api.unexpectedMethods = append(api.unexpectedMethods, request.Method+" "+request.URL.Path)
		}
		switch request.URL.Path {
		case api.root():
			return rulesetResponse(request, 200, `{"default_branch":"main","login":"fixture-org"}`), nil
		case api.root() + "/actions/permissions":
			response := api.permission
			if response.status == 0 {
				response.status = 200
				response.body = `{"enabled":true}`
				if api.scope == ScopeOrganization {
					response.body = `{"enabled_repositories":"all"}`
				}
			}
			return rulesetResponse(request, response.status, response.body), nil
		case api.root() + "/actions/policies":
			api.policyCalls++
			if got := request.URL.Query().Get("has_parents"); got != "true" {
				api.t.Errorf("has_parents = %q, want true", got)
			}
			if got := request.Header.Get("X-GitHub-Api-Version"); got != "2026-03-10" {
				api.t.Errorf("API version = %q", got)
			}
			page, _ := strconv.Atoi(request.URL.Query().Get("page"))
			response, ok := api.pages[page]
			if !ok {
				response = lockfileFixtureResponse{status: 200, body: `{"total_count":0,"policies":[]}`}
			}
			result := rulesetResponse(request, response.status, response.body)
			if response.next {
				next := *request.URL
				query := next.Query()
				query.Set("page", strconv.Itoa(page+1))
				next.RawQuery = query.Encode()
				result.Header.Set("Link", fmt.Sprintf("<%s>; rel=\"next\"", next.String()))
			}
			return result, nil
		}
		if response, ok := api.details[request.URL.Path]; ok {
			api.detailCalls++
			if got := request.Header.Get("X-GitHub-Api-Version"); got != "2026-03-10" {
				api.t.Errorf("detail API version = %q", got)
			}
			return rulesetResponse(request, response.status, response.body), nil
		}
		return rulesetResponse(request, 404, `{"message":"not found"}`), nil
	}))
}

func fixtureLockfileTarget(scope Scope) repository.Repository {
	target := repository.Repository{Host: "github.example.test", Owner: "fixture-org", Name: "fixture-repo"}
	if scope == ScopeOrganization {
		target.Name = ""
	}
	return target
}

func fixtureLockfileRule(t *testing.T, scope Scope) Rule {
	t.Helper()
	id := "GSK146"
	if scope == ScopeOrganization {
		id = "GSK526"
	}
	rule, ok := RuleByID(id)
	if !ok {
		t.Fatalf("%s not registered", id)
	}
	return rule
}

func fixturePolicyPage(t *testing.T, total int, policies ...json.RawMessage) string {
	t.Helper()
	data, err := json.Marshal(struct {
		TotalCount int               `json:"total_count"`
		Policies   []json.RawMessage `json:"policies"`
	}{total, policies})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func evaluateLockfileFixture(t *testing.T, api *lockfileFixtureAPI, rules []Rule) ([]Result, bool, error) {
	t.Helper()
	client := api.client()
	target := fixtureLockfileTarget(api.scope)
	if api.scope == ScopeRepository {
		results, facts, err := EvaluateRepository(context.Background(), client, target, rules, nil)
		return results, facts != nil && facts.ActionsPoliciesKnown, err
	}
	results, facts, err := EvaluateOrganization(context.Background(), client, target, rules, nil)
	return results, facts != nil && facts.ActionsPoliciesKnown, err
}

func TestRequireLockfileCollectionSelection(t *testing.T) {
	for _, scope := range []Scope{ScopeRepository, ScopeOrganization} {
		rule := fixtureLockfileRule(t, scope)
		otherID := "GSK101"
		if scope == ScopeOrganization {
			otherID = "GSK501"
		}
		other, _ := RuleByID(otherID)
		for _, test := range []struct {
			name        string
			rules       []Rule
			permission  lockfileFixtureResponse
			wantCalls   int
			wantKnown   bool
			wantResults int
		}{
			{"selected", []Rule{rule}, lockfileFixtureResponse{}, 1, true, 1},
			{"other rule", []Rule{other}, lockfileFixtureResponse{}, 0, false, 1},
			{"empty selection", []Rule{}, lockfileFixtureResponse{}, 0, false, 0},
			{"scope filter", (Filter{Scope: scope, IDs: []string{otherID}, IgnoreIDs: []string{otherID}}).Apply(AllRules()), lockfileFixtureResponse{}, 0, false, 0},
			{"ignored", (Filter{Scope: scope, IDs: []string{rule.ID}, IgnoreIDs: []string{rule.ID}}).Apply(AllRules()), lockfileFixtureResponse{}, 0, false, 0},
			{"fixable only", (Filter{Scope: scope, IDs: []string{rule.ID}, OnlyFixable: true}).Apply(AllRules()), lockfileFixtureResponse{}, 0, false, 0},
			{"permissions missing", []Rule{rule}, lockfileFixtureResponse{status: 404, body: `{"message":"not found"}`}, 0, false, 1},
		} {
			t.Run(string(scope)+"/"+test.name, func(t *testing.T) {
				if test.rules == nil {
					t.Fatal("filter must preserve an explicit empty selection")
				}
				api := &lockfileFixtureAPI{t: t, scope: scope, permission: test.permission}
				results, known, err := evaluateLockfileFixture(t, api, test.rules)
				if err != nil {
					t.Fatal(err)
				}
				if api.policyCalls != test.wantCalls || known != test.wantKnown || len(results) != test.wantResults {
					t.Fatalf("calls=%d known=%t results=%d, want %d %t %d", api.policyCalls, known, len(results), test.wantCalls, test.wantKnown, test.wantResults)
				}
			})
		}
	}
	for _, test := range []struct {
		scope      Scope
		permission string
	}{
		{ScopeRepository, `{"enabled":false}`},
		{ScopeOrganization, `{"enabled_repositories":"none"}`},
		{ScopeOrganization, `{"enabled_repositories":""}`},
	} {
		t.Run(string(test.scope)+"/Actions disabled or unknown", func(t *testing.T) {
			api := &lockfileFixtureAPI{t: t, scope: test.scope, permission: lockfileFixtureResponse{status: 200, body: test.permission}}
			results, known, err := evaluateLockfileFixture(t, api, []Rule{fixtureLockfileRule(t, test.scope)})
			if err != nil || known || api.policyCalls != 0 || len(results) != 1 || results[0].Status != StatusSkip {
				t.Fatalf("results=%v known=%t calls=%d err=%v", results, known, api.policyCalls, err)
			}
		})
	}
	t.Run("organization selected repositories still requires coverage", func(t *testing.T) {
		api := &lockfileFixtureAPI{t: t, scope: ScopeOrganization, permission: lockfileFixtureResponse{
			status: 200, body: `{"enabled_repositories":"selected"}`,
		}}
		results, known, err := evaluateLockfileFixture(t, api, []Rule{fixtureLockfileRule(t, ScopeOrganization)})
		if err != nil || !known || api.policyCalls != 1 || len(results) != 1 || results[0].Status != StatusFail {
			t.Fatalf("results=%v known=%t calls=%d err=%v", results, known, api.policyCalls, err)
		}
	})
	t.Run("nil organization selection retains legacy all-rules collection", func(t *testing.T) {
		api := &lockfileFixtureAPI{t: t, scope: ScopeOrganization}
		_, known, err := evaluateLockfileFixture(t, api, nil)
		if err != nil || !known || api.policyCalls != 1 {
			t.Fatalf("known=%t calls=%d err=%v", known, api.policyCalls, err)
		}
	})
}

func TestRequireLockfileCollectionErrors(t *testing.T) {
	for _, scope := range []Scope{ScopeRepository, ScopeOrganization} {
		for _, test := range []struct {
			name       string
			response   lockfileFixtureResponse
			wantStatus Status
			wantKnown  bool
			wantError  int
		}{
			{"empty", lockfileFixtureResponse{200, `{"total_count":0,"policies":[]}`, false}, StatusFail, true, 0},
			{"unauthorized", lockfileFixtureResponse{401, `{"message":"unauthorized"}`, false}, "", false, 401},
			{"forbidden", lockfileFixtureResponse{403, `{"message":"forbidden"}`, false}, "", false, 403},
			{"ambiguous not found", lockfileFixtureResponse{404, `{"message":"not found"}`, false}, StatusSkip, false, 0},
			{"server error", lockfileFixtureResponse{500, `{"message":"unavailable"}`, false}, StatusSkip, false, 0},
			{"invalid JSON", lockfileFixtureResponse{200, `{"total_count":`, false}, StatusSkip, false, 0},
			{"missing count", lockfileFixtureResponse{200, `{"policies":[]}`, false}, StatusSkip, false, 0},
			{"incomplete list", lockfileFixtureResponse{200, `{"total_count":1,"policies":[]}`, false}, StatusSkip, false, 0},
			{"null policies", lockfileFixtureResponse{200, `{"total_count":0,"policies":null}`, false}, StatusSkip, false, 0},
		} {
			t.Run(fmt.Sprintf("%s/%s", scope, test.name), func(t *testing.T) {
				api := &lockfileFixtureAPI{t: t, scope: scope, pages: map[int]lockfileFixtureResponse{1: test.response}}
				results, known, err := evaluateLockfileFixture(t, api, []Rule{fixtureLockfileRule(t, scope)})
				if test.wantError != 0 {
					var response *github.ErrorResponse
					if !errors.As(err, &response) || response.Response == nil || response.Response.StatusCode != test.wantError || len(results) != 0 {
						t.Fatalf("results=%v, error=%v, want HTTP %d", results, err, test.wantError)
					}
					return
				}
				if err != nil || known != test.wantKnown || len(results) != 1 || results[0].Status != test.wantStatus {
					t.Fatalf("results=%v known=%t err=%v", results, known, err)
				}
			})
		}
	}
}

func TestRequireLockfileCollectionPagination(t *testing.T) {
	for _, scope := range []Scope{ScopeRepository, ScopeOrganization} {
		partial := fixtureActionsPolicy(t, map[string]any{
			"conditions": map[string]any{"workflow_path": fixtureWorkflowSelector([]string{"fixture.yml"}, []string{})},
		})
		universal := fixtureActionsPolicy(t, map[string]any{"id": 102})
		if scope == ScopeOrganization {
			partial = fixtureOrgPolicy(t, map[string]any{
				"conditions": map[string]any{"repository_name": fixtureRepoNameSelector([]string{"fixture-repo"}, []string{})},
			})
			universal = fixtureOrgPolicy(t, map[string]any{"id": 102})
		}
		for _, test := range []struct {
			name       string
			second     lockfileFixtureResponse
			wantStatus Status
			wantError  int
		}{
			{"universal policy on second page", lockfileFixtureResponse{200, fixturePolicyPage(t, 2, universal), false}, StatusPass, 0},
			{"failed second page", lockfileFixtureResponse{500, `{"message":"unavailable"}`, false}, StatusSkip, 0},
			{"unauthorized second page", lockfileFixtureResponse{403, `{"message":"forbidden"}`, false}, "", 403},
		} {
			t.Run(string(scope)+"/"+test.name, func(t *testing.T) {
				api := &lockfileFixtureAPI{t: t, scope: scope, pages: map[int]lockfileFixtureResponse{
					1: {200, fixturePolicyPage(t, 2, partial), true},
					2: test.second,
				}}
				results, _, err := evaluateLockfileFixture(t, api, []Rule{fixtureLockfileRule(t, scope)})
				if test.wantError != 0 {
					var response *github.ErrorResponse
					if !errors.As(err, &response) || response.Response.StatusCode != test.wantError {
						t.Fatalf("error=%v, want HTTP %d", err, test.wantError)
					}
				} else if err != nil || len(results) != 1 || results[0].Status != test.wantStatus {
					t.Fatalf("results=%v err=%v, want %s", results, err, test.wantStatus)
				}
				if api.policyCalls != 2 {
					t.Fatalf("policy calls=%d, want 2", api.policyCalls)
				}
			})
		}
	}
}

func TestRequireLockfilePolicyDetails(t *testing.T) {
	for _, test := range []struct {
		name       string
		scope      Scope
		summary    json.RawMessage
		detail     lockfileFixtureResponse
		detailPath string
		wantStatus Status
		wantCalls  int
		wantError  int
	}{
		{"repository detail", ScopeRepository, fixtureActionsPolicy(t, map[string]any{"rules": nil}),
			lockfileFixtureResponse{200, string(fixtureActionsPolicy(t, nil)), false}, "/repos/fixture-org/fixture-repo/actions/policies/101", StatusPass, 1, 0},
		{"organization detail", ScopeOrganization, fixtureOrgPolicy(t, map[string]any{"rules": nil}),
			lockfileFixtureResponse{200, string(fixtureOrgPolicy(t, nil)), false}, "/orgs/fixture-org/actions/policies/101", StatusPass, 1, 0},
		{"missing organization conditions", ScopeOrganization, fixtureOrgPolicy(t, map[string]any{"conditions": nil}),
			lockfileFixtureResponse{200, string(fixtureOrgPolicy(t, nil)), false}, "/orgs/fixture-org/actions/policies/101", StatusPass, 1, 0},
		{"inherited organization detail", ScopeRepository, fixtureOrgPolicy(t, map[string]any{"rules": nil}),
			lockfileFixtureResponse{200, string(fixtureOrgPolicy(t, nil)), false}, "/orgs/fixture-org/actions/policies/101", StatusPass, 1, 0},
		{"detail unavailable", ScopeRepository, fixtureActionsPolicy(t, map[string]any{"rules": nil}),
			lockfileFixtureResponse{404, `{"message":"not found"}`, false}, "/repos/fixture-org/fixture-repo/actions/policies/101", StatusSkip, 1, 0},
		{"detail server error", ScopeRepository, fixtureActionsPolicy(t, map[string]any{"rules": nil}),
			lockfileFixtureResponse{500, `{"message":"unavailable"}`, false}, "/repos/fixture-org/fixture-repo/actions/policies/101", StatusSkip, 1, 0},
		{"detail unauthorized", ScopeRepository, fixtureActionsPolicy(t, map[string]any{"rules": nil}),
			lockfileFixtureResponse{401, `{"message":"unauthorized"}`, false}, "/repos/fixture-org/fixture-repo/actions/policies/101", "", 1, 401},
		{"organization detail forbidden", ScopeOrganization, fixtureOrgPolicy(t, map[string]any{"rules": nil}),
			lockfileFixtureResponse{403, `{"message":"forbidden"}`, false}, "/orgs/fixture-org/actions/policies/101", "", 1, 403},
		{"detail mismatched identity", ScopeRepository, fixtureActionsPolicy(t, map[string]any{"rules": nil}),
			lockfileFixtureResponse{200, string(fixtureActionsPolicy(t, map[string]any{"id": 102})), false}, "/repos/fixture-org/fixture-repo/actions/policies/101", StatusSkip, 1, 0},
		{"detail drops list conditions", ScopeRepository, fixtureActionsPolicy(t, map[string]any{
			"rules": nil, "conditions": map[string]any{"workflow_path": fixtureWorkflowSelector([]string{"fixture.yml"}, []string{})},
		}), lockfileFixtureResponse{200, string(fixtureActionsPolicy(t, nil)), false},
			"/repos/fixture-org/fixture-repo/actions/policies/101", StatusSkip, 1, 0},
		{"detail changes list rules", ScopeOrganization, fixtureOrgPolicy(t, map[string]any{"conditions": nil}),
			lockfileFixtureResponse{200, string(fixtureOrgPolicy(t, map[string]any{"rules": []any{map[string]any{"type": "restrict_action_events"}}})), false},
			"/orgs/fixture-org/actions/policies/101", StatusSkip, 1, 0},
		{"unrecognized list field is not discarded", ScopeRepository, fixtureActionsPolicy(t, map[string]any{"rules": nil, "future": true}),
			lockfileFixtureResponse{200, string(fixtureActionsPolicy(t, nil)), false}, "/repos/fixture-org/fixture-repo/actions/policies/101", StatusSkip, 0, 0},
		{"enterprise parent detail unavailable", ScopeOrganization, fixtureOrgPolicy(t, map[string]any{"source_type": "Enterprise", "source": "fixture-enterprise", "rules": nil}),
			lockfileFixtureResponse{}, "", StatusSkip, 0, 0},
		{"disabled policy", ScopeRepository, fixtureActionsPolicy(t, map[string]any{"rules": nil, "enforcement": "disabled"}),
			lockfileFixtureResponse{}, "", StatusFail, 0, 0},
		{"complete policy", ScopeRepository, fixtureActionsPolicy(t, nil),
			lockfileFixtureResponse{}, "", StatusPass, 0, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &lockfileFixtureAPI{
				t: t, scope: test.scope,
				pages:   map[int]lockfileFixtureResponse{1: {200, fixturePolicyPage(t, 1, test.summary), false}},
				details: map[string]lockfileFixtureResponse{test.detailPath: test.detail},
			}
			results, _, err := evaluateLockfileFixture(t, api, []Rule{fixtureLockfileRule(t, test.scope)})
			if test.wantError != 0 {
				var response *github.ErrorResponse
				if !errors.As(err, &response) || response.Response.StatusCode != test.wantError {
					t.Fatalf("error=%v, want HTTP %d", err, test.wantError)
				}
			} else if err != nil || len(results) != 1 || results[0].Status != test.wantStatus {
				t.Fatalf("results=%v err=%v, want %s", results, err, test.wantStatus)
			}
			if api.detailCalls != test.wantCalls {
				t.Fatalf("detail calls=%d, want %d", api.detailCalls, test.wantCalls)
			}
		})
	}
}

func TestRequireLockfileApplyGoldenAndOutput(t *testing.T) {
	for _, scope := range []Scope{ScopeRepository, ScopeOrganization} {
		rule := fixtureLockfileRule(t, scope)
		for _, dryRun := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/dryrun=%t", scope, dryRun), func(t *testing.T) {
				api := &lockfileFixtureAPI{t: t, scope: scope}
				client := api.client()
				target := fixtureLockfileTarget(scope)
				var results []ApplyResult
				var err error
				if scope == ScopeRepository {
					results, err = ApplyRepository(context.Background(), client, target, []Rule{rule}, nil, dryRun)
				} else {
					results, err = ApplyOrganization(context.Background(), client, target, []Rule{rule}, nil, dryRun)
				}
				if err != nil || len(results) != 1 || results[0].Status != StatusFail || results[0].Applied || results[0].DryRun != dryRun || results[0].Error != nil {
					t.Fatalf("results=%v err=%v", results, err)
				}
				if len(api.unexpectedMethods) != 0 {
					t.Fatalf("unexpected writes: %v", api.unexpectedMethods)
				}
				result := results[0].Result
				output := newResultJSON(result)
				wantURL := "https://github.example.test/fixture-org/fixture-repo/settings/actions/policies"
				if scope == ScopeOrganization {
					wantURL = "https://github.example.test/organizations/fixture-org/settings/actions/policies"
				}
				if output.Rule != rule.ID || output.Scope != scope || output.Category != "actions" || output.Severity != SeverityHigh ||
					output.Fixable || output.Status != StatusFail || output.SettingsURL != wantURL {
					t.Fatalf("unexpected output: %+v", output)
				}
				base := &Config{}
				golden := GoldenConfig(base, []Result{result}, false)
				if !reflect.DeepEqual(golden.IgnoreIDs(), []string{rule.ID}) {
					t.Fatalf("golden ignores=%v", golden.IgnoreIDs())
				}
				filter := Filter{Scope: scope, IDs: []string{rule.ID}}
				selected, err := GoldenRules(golden, filter, false)
				if err != nil || selected == nil || len(selected) != 0 {
					t.Fatalf("ignored golden rule selected: %v, err=%v", selected, err)
				}
				selected, err = GoldenRules(golden, filter, true)
				if err != nil || len(selected) != 1 || selected[0].ID != rule.ID {
					t.Fatalf("pruning did not select golden rule: %v, err=%v", selected, err)
				}
				result.Status = StatusSkip
				if got := GoldenConfig(golden, []Result{result}, true); !reflect.DeepEqual(got.IgnoreIDs(), []string{rule.ID}) {
					t.Fatalf("skip must preserve golden ignore: %v", got.IgnoreIDs())
				}
				result.Status = StatusPass
				if got := GoldenConfig(golden, []Result{result}, true); len(got.IgnoreIDs()) != 0 {
					t.Fatalf("pass must prune golden ignore: %v", got.IgnoreIDs())
				}
			})
		}
	}
}
