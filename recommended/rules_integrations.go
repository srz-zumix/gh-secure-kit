package recommended

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

func init() {
	register(Rule{
		ID: "GSK521", Scope: ScopeOrganization, Category: "access_control", Severity: SeverityHigh,
		Title: "Suspended users remain organization owners",
		CheckOrg: func(f *OrganizationFacts) Outcome {
			return checkSuspendedUsers(f.SuspendedOwnersKnown, f.SuspendedOwners, "owners")
		},
	})
	register(Rule{
		ID: "GSK522", Scope: ScopeOrganization, Category: "access_control", Severity: SeverityMedium,
		Title: "Suspended users remain organization members",
		CheckOrg: func(f *OrganizationFacts) Outcome {
			return checkSuspendedUsers(f.SuspendedMembersKnown, f.SuspendedMembers, "members")
		},
	})
	register(Rule{
		ID: "GSK523", Scope: ScopeOrganization, Category: "actions", Severity: SeverityHigh,
		Title: "Self-hosted runner group allows public repositories", Fixable: true,
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if !f.RunnerGroupsKnown {
				return Skip("could not read organization runner groups")
			}
			var unsafe []string
			unknown := false
			for _, group := range f.RunnerGroups {
				if group == nil || group.AllowsPublicRepositories == nil {
					unknown = true
					continue
				}
				if group.GetAllowsPublicRepositories() {
					unsafe = append(unsafe, group.GetName())
				}
			}
			if len(unsafe) > 0 {
				sort.Strings(unsafe)
				return Fail("runner groups allowing public repositories: " + strings.Join(unsafe, ", "))
			}
			if unknown {
				return Skip("could not read public repository access for some runner groups")
			}
			return Pass("no runner group allows public repositories")
		},
		ApplyOrg: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error {
			if !f.RunnerGroupsKnown {
				return fmt.Errorf("could not read organization runner groups")
			}
			for _, group := range f.RunnerGroups {
				if !group.GetAllowsPublicRepositories() {
					continue
				}
				if group.ID == nil {
					return fmt.Errorf("runner group %q has no ID; cannot restrict public repository access", group.GetName())
				}
				if group.GetInherited() {
					return fmt.Errorf("runner group %d is inherited; restrict public repository access at the enterprise level", group.GetID())
				}
			}
			for _, group := range f.RunnerGroups {
				if group.GetAllowsPublicRepositories() {
					if _, err := gh.UpdateOrgRunnerGroup(ctx, g, repo, group.GetID(), gh.RunnerGroupSettings{AllowsPublicRepositories: github.Ptr(false)}); err != nil {
						return fmt.Errorf("failed to restrict public repository access for runner group %d: %w", group.GetID(), err)
					}
				}
			}
			return nil
		},
	})
	for _, spec := range []struct {
		id     string
		scope  Scope
		secret bool
	}{
		{"GSK524", ScopeOrganization, false}, {"GSK525", ScopeOrganization, true},
		{"GSK144", ScopeRepository, false}, {"GSK145", ScopeRepository, true},
	} {
		title, severity := "Webhook uses insecure transport", SeverityHigh
		if spec.secret {
			title, severity = "Webhook has no secret", SeverityMedium
		}
		rule := Rule{ID: spec.id, Scope: spec.scope, Category: "security", Severity: severity, Title: title}
		if spec.scope == ScopeOrganization {
			rule.CheckOrg = func(f *OrganizationFacts) Outcome { return checkWebhooks(f.Hooks, f.HooksKnown, spec.secret) }
		} else {
			rule.CheckRepo = func(f *RepositoryFacts) Outcome { return checkWebhooks(f.Hooks, f.HooksKnown, spec.secret) }
		}
		register(rule)
	}
}

func checkSuspendedUsers(known bool, users []*github.User, role string) Outcome {
	if len(users) > 0 {
		var logins []string
		for _, user := range users {
			logins = append(logins, user.GetLogin())
		}
		sort.Strings(logins)
		return Fail("suspended organization " + role + ": " + strings.Join(logins, ", "))
	}
	if !known {
		return Skip("could not read suspended status of organization " + role)
	}
	return Pass("no suspended organization " + role)
}

func checkWebhooks(hooks []*github.Hook, known, secret bool) Outcome {
	if !known {
		return Skip("could not read webhooks")
	}
	var unsafe []string
	unknown := false
	for _, hook := range hooks {
		if hook == nil || hook.Active == nil {
			unknown = true
			continue
		}
		if !hook.GetActive() {
			continue
		}
		config := hook.GetConfig()
		if config == nil {
			unknown = true
			continue
		}
		if secret {
			// The configuration fetched per hook returns the secret obfuscated
			// when one is configured and omits the field entirely when it is
			// not, so a missing or empty value means payloads are unsigned.
			if config.GetSecret() == "" {
				unsafe = append(unsafe, fmt.Sprintf("%d", hook.GetID()))
			}
			continue
		}
		endpoint, err := url.Parse(config.GetURL())
		validURL := err == nil && endpoint.Hostname() != "" && (endpoint.Scheme == "http" || endpoint.Scheme == "https")
		if config.GetInsecureSSL() == "1" || (validURL && endpoint.Scheme == "http") {
			unsafe = append(unsafe, fmt.Sprintf("%d", hook.GetID()))
		} else if !validURL || config.InsecureSSL == nil || config.GetInsecureSSL() != "0" {
			unknown = true
		}
	}
	issue := "insecure transport"
	if secret {
		issue = "no secret"
	}
	if len(unsafe) > 0 {
		sort.Strings(unsafe)
		return Fail("active webhook IDs with " + issue + ": " + strings.Join(unsafe, ", "))
	}
	if unknown {
		return Skip("could not determine webhook " + issue + " status for some webhooks")
	}
	return Pass("no active webhooks with " + issue)
}
