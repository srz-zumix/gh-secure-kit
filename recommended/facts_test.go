package recommended

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v90/github"
)

func TestEvaluateAccessDenied(t *testing.T) {
	for _, scope := range []Scope{ScopeRepository, ScopeOrganization} {
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
			for _, root := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%d/root=%t", scope, status, root), func(t *testing.T) {
					target := repository.Repository{Host: "github.com", Owner: "fixture_org", Name: "fixture_repo"}
					path := "/repos/fixture_org/fixture_repo"
					if scope == ScopeOrganization {
						path = "/orgs/fixture_org"
						target.Name = ""
					}
					client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
						if request.URL.Path == path && !root {
							return rulesetResponse(request, 200, `{"default_branch":"main","login":"fixture_org"}`), nil
						}
						return rulesetResponse(request, status, `{"message":"Access denied"}`), nil
					}))
					var results []Result
					var err error
					if scope == ScopeRepository {
						results, _, err = EvaluateRepository(context.Background(), client, target, AllRules(), nil)
					} else {
						results, _, err = EvaluateOrganization(context.Background(), client, target, AllRules(), nil)
					}
					if status == http.StatusNotFound && !root {
						if err != nil {
							t.Fatalf("optional missing settings: %v", err)
						}
						return
					}
					var response *github.ErrorResponse
					if !errors.As(err, &response) || response.Response.StatusCode != status {
						t.Fatalf("got %v, want HTTP %d", err, status)
					}
					if len(results) != 0 {
						t.Fatalf("returned results without access: %v", results)
					}
				})
			}
		}
	}
}

func TestEvaluateSettingAccessDenied(t *testing.T) {
	for _, setting := range []struct {
		name, path string
		scope      Scope
	}{
		{"branch protection", "/repos/fixture_org/fixture_repo/branches/main/protection", ScopeRepository},
		{"rulesets", "/repos/fixture_org/fixture_repo/rulesets", ScopeRepository},
		{"collaborators", "/repos/fixture_org/fixture_repo/collaborators", ScopeRepository},
		{"deploy keys", "/repos/fixture_org/fixture_repo/keys", ScopeRepository},
		{"security file", "/repos/fixture_org/fixture_repo/contents/SECURITY.md", ScopeRepository},
		{"workflow permissions", "/repos/fixture_org/fixture_repo/actions/permissions/workflow", ScopeRepository},
		{"environment secrets", "/repos/fixture_org/fixture_repo/environments/fixture_env/secrets", ScopeRepository},
		{"environment policies", "/repos/fixture_org/fixture_repo/environments/fixture_env/deployment-branch-policies", ScopeRepository},
		{"repository hook config", "/repos/fixture_org/fixture_repo/hooks/7/config", ScopeRepository},
		{"organization actions", "/orgs/fixture_org/actions/permissions", ScopeOrganization},
		{"organization members", "/orgs/fixture_org/members", ScopeOrganization},
		{"organization hook config", "/orgs/fixture_org/hooks/7/config", ScopeOrganization},
	} {
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
			t.Run(fmt.Sprintf("%s/%d", setting.name, status), func(t *testing.T) {
				denied := false
				client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
					if request.URL.Path == setting.path {
						denied = true
						return rulesetResponse(request, status, `{"message":"Access denied"}`), nil
					}
					switch request.URL.Path {
					case "/repos/fixture_org/fixture_repo", "/orgs/fixture_org":
						return rulesetResponse(request, 200, `{"default_branch":"main","login":"fixture_org"}`), nil
					case "/repos/fixture_org/fixture_repo/environments":
						return rulesetResponse(request, 200, `{"environments":[{"name":"fixture_env","deployment_branch_policy":{"custom_branch_policies":true}}]}`), nil
					case "/repos/fixture_org/fixture_repo/hooks", "/orgs/fixture_org/hooks":
						return rulesetResponse(request, 200, `[{"id":7,"active":true}]`), nil
					default:
						return rulesetResponse(request, 404, `{"message":"Not Found"}`), nil
					}
				}))
				target := repository.Repository{Host: "github.com", Owner: "fixture_org", Name: "fixture_repo"}
				var results []Result
				var err error
				if setting.scope == ScopeRepository {
					results, _, err = EvaluateRepository(context.Background(), client, target, AllRules(), nil)
				} else {
					target.Name = ""
					results, _, err = EvaluateOrganization(context.Background(), client, target, AllRules(), nil)
				}
				var response *github.ErrorResponse
				if !denied || !errors.As(err, &response) || response.Response.StatusCode != status || len(results) != 0 {
					t.Fatalf("denied=%t, results=%v, error=%v; want HTTP %d and no results", denied, results, err, status)
				}
			})
		}
	}
}

func TestCollectSuspendedUsersAccessDenied(t *testing.T) {
	client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return rulesetResponse(request, http.StatusForbidden, `{"message":"Access denied"}`), nil
	}))
	users, known, err := collectSuspendedUsers(context.Background(), client, "github.example.test", []*github.User{{Login: github.Ptr("fixture_user")}})
	if err == nil || known || users != nil {
		t.Fatalf("users=%v, known=%t, error=%v; want access error", users, known, err)
	}
}
