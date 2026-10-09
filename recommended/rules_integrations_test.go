package recommended

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v90/github"
)

func TestSuspendedUserRules(t *testing.T) {
	for _, id := range []string{"GSK521", "GSK522"} {
		for _, tc := range []struct {
			name             string
			known, suspended bool
			want             Status
		}{
			{"unknown", false, false, StatusSkip},
			{"empty", true, false, StatusPass},
			{"suspended", true, true, StatusFail},
			{"partial violation", false, true, StatusFail},
		} {
			t.Run(id+"/"+tc.name, func(t *testing.T) {
				facts := &OrganizationFacts{SuspendedOwnersKnown: tc.known, SuspendedMembersKnown: tc.known}
				if tc.suspended {
					users := []*github.User{{Login: github.Ptr("suspended")}}
					facts.SuspendedOwners, facts.SuspendedMembers = users, users
				}
				if got := orgRuleOutcome(t, id, facts); got != tc.want {
					t.Fatalf("got %s, want %s", got, tc.want)
				}
			})
		}
	}
}

func TestCollectSuspendedUsers(t *testing.T) {
	client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/users/suspended":
			return rulesetResponse(request, 200, `{"login":"suspended","suspended_at":"2026-01-01T00:00:00Z"}`), nil
		case "/users/active":
			return rulesetResponse(request, 200, `{"login":"active","suspended_at":null}`), nil
		default:
			return rulesetResponse(request, 403, `{"message":"forbidden"}`), nil
		}
	}))
	users := []*github.User{{Login: github.Ptr("suspended")}, {Login: github.Ptr("active")}}
	got, known := collectSuspendedUsers(context.Background(), client, "github.example.com", users)
	if !known || len(got) != 1 || got[0].GetLogin() != "suspended" {
		t.Fatalf("got %v, known %v", got, known)
	}
	users = append(users, &github.User{Login: github.Ptr("unknown")}, nil)
	got, known = collectSuspendedUsers(context.Background(), client, "github.example.com", users)
	if known || len(got) != 1 {
		t.Fatalf("partial results: got %v, known %v", got, known)
	}
}

func TestCollectSuspendedUsersFromList(t *testing.T) {
	const obfuscatedLogin = "0123456789abcdef0123456789abcdef_acme"
	for _, host := range []string{"github.com", "example.ghe.com", "github.example.com"} {
		t.Run(host, func(t *testing.T) {
			requests := 0
			client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				requests++
				return rulesetResponse(request, 200, `{"login":"alice_acme","suspended_at":null}`), nil
			}))
			users := []*github.User{
				{Login: github.Ptr(obfuscatedLogin)},
				{Login: github.Ptr("alice_acme")},
				{Login: github.Ptr("timestamp"), SuspendedAt: &github.Timestamp{}},
			}
			got, known := collectSuspendedUsers(context.Background(), client, host, users)
			if !known || len(got) != 2 || got[0].GetLogin() != obfuscatedLogin || got[1].GetLogin() != "timestamp" {
				t.Fatalf("got %v, known %v", got, known)
			}
			wantRequests := 0
			if host == "github.example.com" {
				wantRequests = 1
			}
			if requests != wantRequests {
				t.Fatalf("requests = %d, want %d", requests, wantRequests)
			}
			got, known = collectSuspendedUsers(context.Background(), client, host, append(users, nil))
			if known || len(got) != 2 {
				t.Fatalf("partial results: got %v, known %v", got, known)
			}
		})
	}
}

func TestRunnerGroupRule(t *testing.T) {
	for _, tc := range []struct {
		name   string
		known  bool
		groups []*github.RunnerGroup
		want   Status
	}{
		{"unknown", false, nil, StatusSkip},
		{"empty", true, nil, StatusPass},
		{"restricted", true, []*github.RunnerGroup{{AllowsPublicRepositories: github.Ptr(false)}}, StatusPass},
		{"public", true, []*github.RunnerGroup{{AllowsPublicRepositories: github.Ptr(true)}}, StatusFail},
		{"missing setting", true, []*github.RunnerGroup{{}}, StatusSkip},
		{"partial violation", true, []*github.RunnerGroup{nil, {AllowsPublicRepositories: github.Ptr(true)}}, StatusFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := orgRuleOutcome(t, "GSK523", &OrganizationFacts{RunnerGroupsKnown: tc.known, RunnerGroups: tc.groups}); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRunnerGroupApply(t *testing.T) {
	rule, _ := RuleByID("GSK523")
	requests := 0
	client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Method != "PATCH" || request.URL.Path != "/orgs/example/actions/runner-groups/1" {
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body) != 1 || body["allows_public_repositories"] != false {
			t.Fatalf("unexpected settings: %v", body)
		}
		return rulesetResponse(request, 200, `{"id":1,"allows_public_repositories":false}`), nil
	}))
	facts := &OrganizationFacts{RunnerGroupsKnown: true, RunnerGroups: []*github.RunnerGroup{
		{ID: github.Ptr(int64(1)), AllowsPublicRepositories: github.Ptr(true)},
		{ID: github.Ptr(int64(2)), AllowsPublicRepositories: github.Ptr(false)},
	}}
	repo := repository.Repository{Owner: "example"}
	if err := rule.ApplyOrg(context.Background(), client, repo, facts); err != nil || requests != 1 {
		t.Fatalf("requests %d, error %v", requests, err)
	}
	facts.RunnerGroups[0].Inherited = github.Ptr(true)
	if err := rule.ApplyOrg(context.Background(), client, repo, facts); err == nil || requests != 1 {
		t.Fatalf("inherited group: requests %d, error %v", requests, err)
	}
}

func TestWebhookRules(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint, ssl string
		secret              *string
		active              bool
		transport, signing  Status
	}{
		{"secure", "https://example.com/hook", "0", github.Ptr("********"), true, StatusPass, StatusPass},
		{"http", "http://example.com/hook?token=hidden", "0", github.Ptr("********"), true, StatusFail, StatusPass},
		{"insecure ssl", "https://example.com", "1", github.Ptr("********"), true, StatusFail, StatusPass},
		{"no secret", "https://example.com", "0", github.Ptr(""), true, StatusPass, StatusFail},
		{"omitted secret", "https://example.com", "0", nil, true, StatusPass, StatusSkip},
		{"invalid url", "%%%hidden", "0", github.Ptr("********"), true, StatusSkip, StatusPass},
		{"inactive", "http://example.com", "1", github.Ptr(""), false, StatusPass, StatusPass},
		{"unknown ssl", "https://example.com", "unknown", github.Ptr("********"), true, StatusSkip, StatusPass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hooks := []*github.Hook{{ID: github.Ptr(int64(7)), Active: github.Ptr(tc.active), Config: &github.HookConfig{
				URL: github.Ptr(tc.endpoint), InsecureSSL: github.Ptr(tc.ssl), Secret: tc.secret,
			}}}
			for _, id := range []string{"GSK144", "GSK145", "GSK524", "GSK525"} {
				rule, _ := RuleByID(id)
				var outcome Outcome
				if rule.CheckOrg != nil {
					outcome = rule.CheckOrg(&OrganizationFacts{HooksKnown: true, Hooks: hooks})
				} else {
					outcome = rule.CheckRepo(&RepositoryFacts{HooksKnown: true, Hooks: hooks})
				}
				want := tc.transport
				if id == "GSK145" || id == "GSK525" {
					want = tc.signing
				}
				if outcome.Status != want {
					t.Errorf("%s: got %+v, want %s", id, outcome, want)
				}
				if strings.Contains(outcome.Detail, "hidden") || strings.Contains(outcome.Detail, "example.com") {
					t.Fatalf("URL leaked in detail: %s", outcome.Detail)
				}
			}
		})
	}
	for _, secret := range []bool{false, true} {
		for _, tc := range []struct {
			name  string
			hooks []*github.Hook
			known bool
			want  Status
		}{
			{"failed list", nil, false, StatusSkip},
			{"empty list", nil, true, StatusPass},
			{"nil hook", []*github.Hook{nil}, true, StatusSkip},
			{"missing config", []*github.Hook{{Active: github.Ptr(true)}}, true, StatusSkip},
			{"partial violation", []*github.Hook{nil, {Active: github.Ptr(true), Config: &github.HookConfig{URL: github.Ptr("http://example.com"), Secret: github.Ptr("")}}}, true, StatusFail},
		} {
			if got := checkWebhooks(tc.hooks, tc.known, secret); got.Status != tc.want {
				t.Errorf("%s secret=%v: got %+v, want %s", tc.name, secret, got, tc.want)
			}
		}
	}
}

func TestIntegrationFactSelection(t *testing.T) {
	for _, id := range []string{"GSK521", "GSK522", "GSK523", "GSK524", "GSK525"} {
		for _, host := range []string{"github.com", "example.ghe.com", "github.example.com"} {
			t.Run(id+"/"+host, func(t *testing.T) {
				var paths []string
				client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
					paths = append(paths, request.URL.Path)
					if request.URL.Path == "/orgs/example" {
						return rulesetResponse(request, 200, `{"login":"example"}`), nil
					}
					if request.URL.Path == "/orgs/example/members" {
						if host != "github.example.com" {
							return rulesetResponse(request, 200, `[{"login":"0123456789abcdef0123456789abcdef_acme"}]`), nil
						}
						return rulesetResponse(request, 200, `[{"login":"user"}]`), nil
					}
					if request.URL.Path == "/users/user" {
						return rulesetResponse(request, 200, `{"login":"user","suspended_at":"2026-01-01T00:00:00Z"}`), nil
					}
					return rulesetResponse(request, 404, `{"message":"Not Found"}`), nil
				}))
				rule, _ := RuleByID(id)
				facts, err := CollectOrganizationFacts(context.Background(), client, repository.Repository{Host: host, Owner: "example"}, []Rule{rule})
				if err != nil {
					t.Fatal(err)
				}
				ghes := host == "github.example.com"
				counts := map[string]int{}
				for _, path := range paths {
					counts[path]++
				}
				wantUser := 0
				if id == "GSK521" || id == "GSK522" {
					if ghes {
						wantUser = 1
					}
					var suspended []*github.User
					if id == "GSK521" {
						suspended = facts.SuspendedOwners
					} else {
						suspended = facts.SuspendedMembers
					}
					if len(suspended) != 1 {
						t.Fatalf("missing suspended user: %v", suspended)
					}
					if ghes && suspended[0].GetSuspendedAt().Before(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
						t.Fatalf("missing suspended timestamp: %v", suspended[0])
					}
					if got := rule.CheckOrg(facts).Status; got != StatusFail {
						t.Fatalf("suspended user: got %s, want fail", got)
					}
				}
				if counts["/users/user"] != wantUser {
					t.Errorf("user requests: got %d, want %d", counts["/users/user"], wantUser)
				}
				for path, selected := range map[string]bool{
					"/orgs/example/hooks":                 id == "GSK524" || id == "GSK525",
					"/orgs/example/actions/runner-groups": id == "GSK523",
				} {
					if (counts[path] > 0) != selected {
						t.Errorf("unexpected selection of %s: %d", path, counts[path])
					}
				}
			})
		}
	}
}
