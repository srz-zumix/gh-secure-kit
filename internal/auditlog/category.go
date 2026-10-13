// Package auditlog detects credential-related operations (SSH keys, PATs,
// SSO credential authorizations, OAuth apps, GitHub Apps) in organization audit logs.
package auditlog

import (
	"strings"

	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// Detection categories.
const (
	CategorySSH           = "ssh"
	CategoryPAT           = "pat"
	CategorySSOCredential = "sso-credential"
	CategoryOAuthApp      = "oauth-app"
	CategoryGitHubApp     = "github-app"
)

// Categories lists every supported category in display order.
var Categories = []string{
	CategorySSH,
	CategoryPAT,
	CategorySSOCredential,
	CategoryOAuthApp,
	CategoryGitHubApp,
}

type categoryDef struct {
	name string
	// groups are audit log action groups, i.e. the part of an action before the first dot.
	groups []string
	// actions are individual actions that belong to a broader group such as "org".
	actions []string
	// targetKeys are looked up in order to describe what was operated on.
	targetKeys []string
}

var categoryDefs = []categoryDef{
	{
		name:       CategorySSH,
		groups:     []string{"public_key", "ssh_certificate_authority", "ssh_certificate_requirement"},
		targetKeys: []string{"title", "fingerprint"},
	},
	{
		name:       CategoryPAT,
		groups:     []string{"personal_access_token", "auto_approve_personal_access_token_requests"},
		targetKeys: []string{"user_programmatic_access_name"},
	},
	{
		name:       CategorySSOCredential,
		groups:     []string{"org_credential_authorization"},
		targetKeys: []string{"application_name", "fingerprint"},
	},
	{
		name:   CategoryOAuthApp,
		groups: []string{"oauth_application"},
		actions: []string{
			"org.oauth_app_access_approved",
			"org.oauth_app_access_denied",
			"org.oauth_app_access_requested",
			"org.enable_oauth_app_restrictions",
			"org.disable_oauth_app_restrictions",
		},
		targetKeys: []string{"oauth_application", "oauth_application_name"},
	},
	{
		name:   CategoryGitHubApp,
		groups: []string{"integration", "integration_installation", "integration_installation_request"},
		actions: []string{
			"org.integration_manager_added",
			"org.integration_manager_removed",
		},
		targetKeys: []string{"integration", "name", "manager"},
	},
}

func findDef(name string) (categoryDef, bool) {
	for _, d := range categoryDefs {
		if d.name == name {
			return d, true
		}
	}
	return categoryDef{}, false
}

// Queries returns the audit log search phrases that cover the given categories.
// All categories are used when categories is empty.
func Queries(categories []string) []string {
	if len(categories) == 0 {
		categories = Categories
	}
	var queries []string
	for _, c := range categories {
		d, ok := findDef(c)
		if !ok {
			continue
		}
		for _, g := range d.groups {
			queries = append(queries, "action:"+g)
		}
		for _, a := range d.actions {
			queries = append(queries, "action:"+a)
		}
	}
	return queries
}

// Classify returns the category that action belongs to, or "" if none.
func Classify(action string) string {
	group, _, _ := strings.Cut(action, ".")
	for _, d := range categoryDefs {
		for _, a := range d.actions {
			if a == action {
				return d.name
			}
		}
		for _, g := range d.groups {
			if g == group {
				return d.name
			}
		}
	}
	return ""
}

// Target returns a short description of what the entry operated on.
func Target(category string, entry *github.AuditEntry) string {
	d, ok := findDef(category)
	if !ok {
		return ""
	}
	for _, k := range d.targetKeys {
		if v := render.AuditEntryAdditionalField(entry, k); v != "" {
			return v
		}
	}
	return ""
}
