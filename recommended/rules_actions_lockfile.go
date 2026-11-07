package recommended

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

type policyCoverage uint8

const (
	policyUnknown policyCoverage = iota
	policyLimited
	policyUniversal
)

type actionsPolicy struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Target      string          `json:"target"`
	SourceType  string          `json:"source_type"`
	Source      string          `json:"source"`
	Enforcement string          `json:"enforcement"`
	Conditions  json.RawMessage `json:"conditions"`
	Rules       json.RawMessage `json:"rules"`
	NodeID      json.RawMessage `json:"node_id"`
	Links       json.RawMessage `json:"_links"`
	CreatedAt   json.RawMessage `json:"created_at"`
	UpdatedAt   json.RawMessage `json:"updated_at"`
}

type actionsPolicyConditions struct {
	WorkflowPath         json.RawMessage `json:"workflow_path"`
	RepositoryID         json.RawMessage `json:"repository_id"`
	RepositoryName       json.RawMessage `json:"repository_name"`
	RepositoryProperty   json.RawMessage `json:"repository_property"`
	OrganizationID       json.RawMessage `json:"organization_id"`
	OrganizationName     json.RawMessage `json:"organization_name"`
	OrganizationProperty json.RawMessage `json:"organization_property"`
}

type policyNameSelector struct {
	Include   *[]string `json:"include"`
	Exclude   *[]string `json:"exclude"`
	Protected *bool     `json:"protected"`
}

type policyOrgNameSelector struct {
	Include *[]string `json:"include"`
	Exclude *[]string `json:"exclude"`
}

type policyPropertySelector struct {
	Include []policyProperty `json:"include"`
	Exclude []policyProperty `json:"exclude"`
}

type policyProperty struct {
	Name           string   `json:"name"`
	PropertyValues []string `json:"property_values"`
	Source         *string  `json:"source"`
}

func init() {
	register(Rule{
		ID: "GSK146", Scope: ScopeRepository,
		SettingsPath: "actions/policies",
		Category:     "actions", Severity: SeverityHigh, Title: "Actions lockfile not required for all workflows",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.ActionsPermissions == nil {
				return Skip("could not retrieve Actions permissions for the repository")
			}
			if !f.ActionsPermissions.Enabled {
				return Skip("GitHub Actions is disabled for the repository")
			}
			return checkRequireLockfilePolicies(f.ActionsPolicies, f.ActionsPoliciesKnown, ScopeRepository)
		},
	})
	register(Rule{
		ID: "GSK526", Scope: ScopeOrganization,
		SettingsPath: "actions/policies",
		Category:     "actions", Severity: SeverityHigh, Title: "Actions lockfile not required for all repositories and workflows",
		CheckOrg: func(f *OrganizationFacts) Outcome {
			if f.ActionsPermissions == nil {
				return Skip("could not retrieve Actions permissions for the organization")
			}
			switch f.ActionsPermissions.GetEnabledRepositories() {
			case "none":
				return Skip("GitHub Actions is disabled for all repositories in the organization")
			case "all", "selected":
				return checkRequireLockfilePolicies(f.ActionsPolicies, f.ActionsPoliciesKnown, ScopeOrganization)
			default:
				return Skip("could not determine which repositories have GitHub Actions enabled")
			}
		},
	})
}

func decodePolicyObject(raw json.RawMessage, out any) bool {
	data := bytes.TrimSpace(raw)
	if len(data) == 0 || data[0] != '{' || !json.Valid(data) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out) == nil
}

func missingPolicyJSON(raw json.RawMessage) bool {
	data := bytes.TrimSpace(raw)
	return len(data) == 0 || bytes.Equal(data, []byte("null"))
}

func lockfileRuleCoverage(raw json.RawMessage) policyCoverage {
	if missingPolicyJSON(raw) {
		return policyUnknown
	}
	var rules []json.RawMessage
	if err := json.Unmarshal(raw, &rules); err != nil || rules == nil {
		return policyUnknown
	}
	unknown := false
	for _, entry := range rules {
		var rule struct {
			Type       string          `json:"type"`
			Parameters json.RawMessage `json:"parameters"`
		}
		if !decodePolicyObject(entry, &rule) || rule.Type == "" {
			unknown = true
			continue
		}
		if rule.Type != "require_lockfile" {
			continue
		}
		if missingPolicyJSON(rule.Parameters) {
			return policyUniversal
		}
		var parameters map[string]json.RawMessage
		if err := json.Unmarshal(rule.Parameters, &parameters); err != nil || parameters == nil || len(parameters) != 0 {
			unknown = true
			continue
		}
		return policyUniversal
	}
	if unknown {
		return policyUnknown
	}
	return policyLimited
}

func workflowPathCoverage(raw json.RawMessage) policyCoverage {
	if len(raw) == 0 {
		return policyUniversal
	}
	var selector struct {
		Include *[]string `json:"include"`
		Exclude *[]string `json:"exclude"`
	}
	if !decodePolicyObject(raw, &selector) || selector.Include == nil || selector.Exclude == nil {
		return policyUnknown
	}
	if len(*selector.Exclude) != 0 {
		return policyLimited
	}
	if len(*selector.Include) == 0 || len(*selector.Include) == 1 && (*selector.Include)[0] == "~ALL" {
		return policyUniversal
	}
	for _, pattern := range *selector.Include {
		if pattern == "~ALL" || strings.ContainsAny(pattern, "*?[") {
			return policyUnknown
		}
	}
	return policyLimited
}

func validPolicyPropertySelector(raw json.RawMessage) bool {
	var selector policyPropertySelector
	if !decodePolicyObject(raw, &selector) || (selector.Include == nil && selector.Exclude == nil) {
		return false
	}
	for _, property := range append(selector.Include, selector.Exclude...) {
		if property.Name == "" || property.PropertyValues == nil ||
			(property.Source != nil && *property.Source != "custom" && *property.Source != "system") {
			return false
		}
	}
	return true
}

// Parent selectors are evaluated by GitHub when has_parents=true. Their shape
// is still checked so an unrecognized condition cannot produce a false pass.
func validInheritedPolicySelectors(conditions actionsPolicyConditions, sourceType string) bool {
	repoSelectors := []json.RawMessage{conditions.RepositoryID, conditions.RepositoryName, conditions.RepositoryProperty}
	orgSelectors := []json.RawMessage{conditions.OrganizationID, conditions.OrganizationName, conditions.OrganizationProperty}
	if sourceType == "Repository" && (hasPolicySelector(repoSelectors) || hasPolicySelector(orgSelectors)) {
		return false
	}
	if sourceType == "Organization" && hasPolicySelector(orgSelectors) {
		return false
	}
	if len(conditions.RepositoryID) != 0 {
		var selector struct {
			IDs *[]int64 `json:"repository_ids"`
		}
		if !decodePolicyObject(conditions.RepositoryID, &selector) || selector.IDs == nil {
			return false
		}
	}
	if len(conditions.RepositoryName) != 0 {
		var selector policyNameSelector
		if !decodePolicyObject(conditions.RepositoryName, &selector) || selector.Include == nil {
			return false
		}
	}
	if len(conditions.RepositoryProperty) != 0 && !validPolicyPropertySelector(conditions.RepositoryProperty) {
		return false
	}
	if len(conditions.OrganizationID) != 0 {
		var selector struct {
			IDs *[]int64 `json:"organization_ids"`
		}
		if !decodePolicyObject(conditions.OrganizationID, &selector) || selector.IDs == nil {
			return false
		}
	}
	if len(conditions.OrganizationName) != 0 {
		var selector policyOrgNameSelector
		if !decodePolicyObject(conditions.OrganizationName, &selector) || selector.Include == nil {
			return false
		}
	}
	if len(conditions.OrganizationProperty) != 0 && !validPolicyPropertySelector(conditions.OrganizationProperty) {
		return false
	}
	return true
}

func hasPolicySelector(selectors []json.RawMessage) bool {
	for _, selector := range selectors {
		if len(selector) != 0 {
			return true
		}
	}
	return false
}

func organizationRepositoryCoverage(conditions actionsPolicyConditions) policyCoverage {
	selectors := []json.RawMessage{conditions.RepositoryID, conditions.RepositoryName, conditions.RepositoryProperty}
	count := 0
	for _, selector := range selectors {
		if len(selector) != 0 {
			count++
		}
	}
	if count != 1 {
		return policyUnknown
	}
	if len(conditions.RepositoryID) != 0 {
		return policyLimited
	}
	if len(conditions.RepositoryProperty) != 0 {
		return policyUnknown
	}
	var selector policyNameSelector
	if !decodePolicyObject(conditions.RepositoryName, &selector) || selector.Include == nil {
		return policyUnknown
	}
	if selector.Exclude != nil && len(*selector.Exclude) != 0 {
		return policyLimited
	}
	for _, pattern := range *selector.Include {
		if pattern == "~ALL" {
			return policyUniversal
		}
	}
	for _, pattern := range *selector.Include {
		if strings.ContainsAny(pattern, "*?[") {
			return policyUnknown
		}
	}
	return policyLimited
}

func lockfilePolicyCoverage(raw json.RawMessage, scope Scope) policyCoverage {
	var policy actionsPolicy
	if !decodePolicyObject(raw, &policy) {
		return policyUnknown
	}
	switch policy.Enforcement {
	case "disabled", "evaluate":
		return policyLimited
	case "active":
	default:
		return policyUnknown
	}
	ruleCoverage := lockfileRuleCoverage(policy.Rules)
	if ruleCoverage != policyUniversal {
		return ruleCoverage
	}
	if policy.ID <= 0 || policy.Target != "actions" || policy.Source == "" {
		return policyUnknown
	}
	switch policy.SourceType {
	case "Repository":
		if scope != ScopeRepository {
			return policyUnknown
		}
	case "Organization", "Enterprise":
	default:
		return policyUnknown
	}
	var conditions actionsPolicyConditions
	if len(policy.Conditions) != 0 && !decodePolicyObject(policy.Conditions, &conditions) {
		return policyUnknown
	}
	if !validInheritedPolicySelectors(conditions, policy.SourceType) {
		return policyUnknown
	}
	workflowCoverage := workflowPathCoverage(conditions.WorkflowPath)
	if scope == ScopeRepository {
		return workflowCoverage
	}
	repositoryCoverage := organizationRepositoryCoverage(conditions)
	if workflowCoverage == policyLimited || repositoryCoverage == policyLimited {
		return policyLimited
	}
	if workflowCoverage == policyUnknown || repositoryCoverage == policyUnknown {
		return policyUnknown
	}
	return policyUniversal
}

func checkRequireLockfilePolicies(policies []json.RawMessage, known bool, scope Scope) Outcome {
	if !known {
		return Skip("could not retrieve Actions policies")
	}
	seen := make(map[string]bool)
	for _, raw := range policies {
		var identity struct {
			ID         int64  `json:"id"`
			SourceType string `json:"source_type"`
			Source     string `json:"source"`
		}
		if json.Unmarshal(raw, &identity) == nil && identity.ID > 0 && identity.SourceType != "" && identity.Source != "" {
			key := fmt.Sprintf("%s/%s/%d", identity.SourceType, strings.ToLower(identity.Source), identity.ID)
			if seen[key] {
				return Skip("could not determine Actions policy coverage from duplicate policies")
			}
			seen[key] = true
		}
	}
	unknown := false
	for _, raw := range policies {
		switch lockfilePolicyCoverage(raw, scope) {
		case policyUniversal:
			if scope == ScopeRepository {
				return Pass("one active Require lockfile policy covers all workflows in the repository")
			}
			return Pass("one active Require lockfile policy covers all repositories and workflows in the organization")
		case policyUnknown:
			unknown = true
		}
	}
	if unknown {
		return Skip("could not determine whether an active Require lockfile policy covers the entire target")
	}
	if scope == ScopeRepository {
		return Fail("no single active Require lockfile policy covers all workflows in the repository")
	}
	return Fail("no single active Require lockfile policy covers all repositories and workflows in the organization")
}

func fatalActionsPolicyError(err error) bool {
	return isAccessDenied(err) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func equalPolicyJSON(left, right json.RawMessage) bool {
	if !json.Valid(left) || !json.Valid(right) {
		return false
	}
	var values [2]any
	for i, raw := range []json.RawMessage{left, right} {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&values[i]) != nil {
			return false
		}
	}
	return reflect.DeepEqual(values[0], values[1])
}

// hydrateActionsPolicies retrieves missing rules or organization conditions
// without discarding conflicting or unrecognized list data.
func hydrateActionsPolicies(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, scope Scope, policies []json.RawMessage) error {
	for i, raw := range policies {
		var summary actionsPolicy
		if !decodePolicyObject(raw, &summary) || summary.Enforcement != "active" || summary.ID <= 0 || summary.Target != "actions" ||
			(!missingPolicyJSON(summary.Rules) && (scope != ScopeOrganization || !missingPolicyJSON(summary.Conditions))) {
			continue
		}
		var detail json.RawMessage
		var err error
		switch summary.SourceType {
		case "Repository":
			if scope != ScopeRepository {
				continue
			}
			detail, err = gh.GetRepositoryActionsPolicy(ctx, g, repo, summary.ID)
		case "Organization":
			if !strings.EqualFold(summary.Source, repo.Owner) {
				continue
			}
			detail, err = gh.GetOrgActionsPolicy(ctx, g, repo, summary.ID)
		default:
			continue
		}
		if err != nil {
			if fatalActionsPolicyError(err) {
				return err
			}
			continue
		}
		var full actionsPolicy
		if decodePolicyObject(detail, &full) && full.ID == summary.ID && full.Target == summary.Target &&
			full.Enforcement == summary.Enforcement && full.SourceType == summary.SourceType &&
			strings.EqualFold(full.Source, summary.Source) &&
			(missingPolicyJSON(summary.Conditions) || equalPolicyJSON(summary.Conditions, full.Conditions)) &&
			(missingPolicyJSON(summary.Rules) || equalPolicyJSON(summary.Rules, full.Rules)) {
			policies[i] = detail
		}
	}
	return nil
}
