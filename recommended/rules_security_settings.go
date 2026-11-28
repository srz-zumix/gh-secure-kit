package recommended

import (
	"encoding/json"
	"fmt"
	"strings"
)

type securityPrerequisite struct {
	field string
	name  string
}

type repositorySecurityRule struct {
	id            string
	title         string
	field         string
	name          string
	severity      Severity
	privateOnly   bool
	orgOwnedOnly  bool
	prerequisites []securityPrerequisite
}

var repositorySecurityRules = []repositorySecurityRule{
	{"GSK147", "Secret scanning validity checks not enabled", "secret_scanning_validity_checks", "secret scanning validity checks", SeverityMedium, false, true, []securityPrerequisite{{"secret_scanning", "secret scanning"}}},
	{"GSK148", "Secret scanning generic patterns not enabled", "secret_scanning_non_provider_patterns", "secret scanning generic patterns", SeverityMedium, false, true, []securityPrerequisite{{"secret_scanning", "secret scanning"}}},
	{"GSK149", "AI detection of secrets not enabled", "secret_scanning_ai_detection", "AI detection of secrets", SeverityMedium, false, true, []securityPrerequisite{{"secret_scanning", "secret scanning"}}},
	{"GSK150", "Secret scanning delegated bypass not enabled", "secret_scanning_delegated_bypass", "secret scanning delegated bypass", SeverityMedium, false, true, []securityPrerequisite{{"secret_scanning", "secret scanning"}, {"secret_scanning_push_protection", "secret scanning push protection"}}},
	{"GSK151", "Secret scanning delegated alert dismissal not enabled", "secret_scanning_delegated_alert_dismissal", "secret scanning delegated alert dismissal", SeverityMedium, false, true, []securityPrerequisite{{"secret_scanning", "secret scanning"}}},
	{"GSK152", "GitHub Code Security not enabled", "code_security", "GitHub Code Security", SeverityMedium, true, false, nil},
	{"GSK153", "GitHub Advanced Security bundle not enabled", "advanced_security", "GitHub Advanced Security bundle", SeverityInfo, true, false, nil},
}

type organizationSecurityRule struct {
	id            string
	title         string
	field         string
	name          string
	severity      Severity
	visibility    string
	prerequisites []securityPrerequisite
}

var organizationSecurityRules = []organizationSecurityRule{
	{"GSK527", "Default configurations do not enable dependency graph", "dependency_graph", "dependency graph", SeverityHigh, "", nil},
	{"GSK528", "Default configurations do not enable automatic dependency submission", "dependency_graph_autosubmit_action", "automatic dependency submission", SeverityMedium, "", []securityPrerequisite{{"dependency_graph", "dependency graph"}}},
	{"GSK529", "Default configurations do not enable Dependabot alerts", "dependabot_alerts", "Dependabot alerts", SeverityHigh, "", []securityPrerequisite{{"dependency_graph", "dependency graph"}}},
	{"GSK530", "Default configurations do not enable Dependabot security updates", "dependabot_security_updates", "Dependabot security updates", SeverityMedium, "", []securityPrerequisite{{"dependabot_alerts", "Dependabot alerts"}}},
	{"GSK531", "Default configurations do not enable Dependabot delegated alert dismissal", "dependabot_delegated_alert_dismissal", "Dependabot delegated alert dismissal", SeverityMedium, "", []securityPrerequisite{{"dependabot_alerts", "Dependabot alerts"}}},
	{"GSK532", "Default configurations do not enable Dependabot reachability analysis", "dependabot_reachability", "Dependabot reachability analysis", SeverityMedium, "", []securityPrerequisite{{"dependabot_alerts", "Dependabot alerts"}}},
	{"GSK533", "Default configurations do not enable code scanning default setup", "code_scanning_default_setup", "code scanning default setup", SeverityHigh, "", nil},
	{"GSK534", "Default configurations do not enable code scanning delegated alert dismissal", "code_scanning_delegated_alert_dismissal", "code scanning delegated alert dismissal", SeverityMedium, "", nil},
	{"GSK535", "Default configurations do not enable secret scanning", "secret_scanning", "secret scanning", SeverityHigh, "", nil},
	{"GSK536", "Default configurations do not enable secret scanning push protection", "secret_scanning_push_protection", "secret scanning push protection", SeverityHigh, "", []securityPrerequisite{{"secret_scanning", "secret scanning"}}},
	{"GSK537", "Default configurations do not enable secret scanning delegated bypass", "secret_scanning_delegated_bypass", "secret scanning delegated bypass", SeverityMedium, "", []securityPrerequisite{{"secret_scanning", "secret scanning"}, {"secret_scanning_push_protection", "secret scanning push protection"}}},
	{"GSK538", "Default configurations do not enable secret scanning validity checks", "secret_scanning_validity_checks", "secret scanning validity checks", SeverityMedium, "", []securityPrerequisite{{"secret_scanning", "secret scanning"}}},
	{"GSK539", "Default configurations do not enable secret scanning generic patterns", "secret_scanning_non_provider_patterns", "secret scanning generic patterns", SeverityMedium, "", []securityPrerequisite{{"secret_scanning", "secret scanning"}}},
	{"GSK540", "Default configurations do not enable AI detection of secrets", "secret_scanning_generic_secrets", "AI detection of secrets", SeverityMedium, "", []securityPrerequisite{{"secret_scanning", "secret scanning"}}},
	{"GSK541", "Default configurations do not block AI-detected secrets", "secret_scanning_generic_secrets_push_protection", "push protection for AI-detected secrets", SeverityMedium, "", []securityPrerequisite{{"secret_scanning", "secret scanning"}, {"secret_scanning_push_protection", "secret scanning push protection"}, {"secret_scanning_generic_secrets", "AI detection of secrets"}}},
	{"GSK542", "Default configurations do not enable secret scanning delegated alert dismissal", "secret_scanning_delegated_alert_dismissal", "secret scanning delegated alert dismissal", SeverityMedium, "", []securityPrerequisite{{"secret_scanning", "secret scanning"}}},
	{"GSK543", "Default configurations do not enable secret scanning extended metadata", "secret_scanning_extended_metadata", "secret scanning extended metadata", SeverityMedium, "", []securityPrerequisite{{"secret_scanning", "secret scanning"}, {"secret_scanning_validity_checks", "secret scanning validity checks"}}},
	{"GSK544", "Default configurations do not enable private vulnerability reporting", "private_vulnerability_reporting", "private vulnerability reporting", SeverityMedium, "public", nil},
	{"GSK545", "Default configurations do not enable the GitHub Advanced Security bundle", "advanced_security", "GitHub Advanced Security bundle", SeverityInfo, "private_and_internal", nil},
	{"GSK546", "Default configurations do not enable GitHub Code Security", "code_security", "GitHub Code Security", SeverityMedium, "private_and_internal", nil},
	{"GSK547", "Default configurations do not enable GitHub Secret Protection", "secret_protection", "GitHub Secret Protection", SeverityMedium, "private_and_internal", nil},
	{"GSK548", "Default security configurations are not enforced", "enforcement", "security configuration enforcement", SeverityMedium, "", nil},
}

func init() {
	for _, def := range repositorySecurityRules {
		register(Rule{
			ID: def.id, Scope: ScopeRepository, SettingsPath: "security_analysis",
			Category: "security", Severity: def.severity, Title: def.title,
			CheckRepo: func(f *RepositoryFacts) Outcome {
				return checkRepositorySecuritySetting(f, def)
			},
		})
	}
	for _, def := range organizationSecurityRules {
		register(Rule{
			ID: def.id, Scope: ScopeOrganization, SettingsPath: "security_products/configurations",
			Category: "security", Severity: def.severity, Title: def.title, TargetKind: "security configuration",
			CheckOrg: func(f *OrganizationFacts) Outcome {
				return checkOrganizationSecurityDefaults(f, def)
			},
		})
	}
	registerAIScanRules()
}

func needsRepositorySecurityAnalysis(rules []Rule) bool {
	for _, def := range repositorySecurityRules {
		if selectedRule(rules, def.id) {
			return true
		}
	}
	return false
}

func needsOrganizationSecurityDefaults(rules []Rule) bool {
	for _, def := range organizationSecurityRules {
		if selectedRule(rules, def.id) {
			return true
		}
	}
	return false
}

func checkRepositorySecuritySetting(f *RepositoryFacts, def repositorySecurityRule) Outcome {
	if def.orgOwnedOnly {
		// GitHub reports these settings as disabled even where they cannot be configured.
		switch f.Repo.GetOwner().GetType() {
		case "Organization":
		case "":
			return Skip("could not determine repository owner type")
		default:
			return Skip(fmt.Sprintf("%s is only available for organization-owned repositories", def.name))
		}
	}
	if def.privateOnly {
		if f.Repo == nil {
			return Skip("could not determine repository visibility")
		}
		visibility := f.Repo.GetVisibility()
		if visibility != "public" && visibility != "private" && visibility != "internal" && (visibility != "" || f.Repo.Private == nil) {
			return Skip("could not determine repository visibility")
		}
		if !isPrivateOrInternal(f.Repo) {
			return Skip("product licensing is not required for public repositories")
		}
	}
	var unknown []string
	for _, prerequisite := range def.prerequisites {
		status, ok := repositorySecurityStatus(f.securityAnalysis, prerequisite.field)
		switch {
		case status == "disabled":
			return Skip(fmt.Sprintf("%s is disabled", prerequisite.name))
		case !ok || status != "enabled":
			unknown = append(unknown, prerequisite.name)
		}
	}
	status, ok := repositorySecurityStatus(f.securityAnalysis, def.field)
	if ok && status == "disabled" {
		detail := fmt.Sprintf("%s is disabled", def.name)
		if len(unknown) > 0 {
			detail += "; could not read prerequisite status: " + strings.Join(unknown, ", ")
		}
		return Fail(detail)
	}
	if len(unknown) > 0 {
		return Skip("could not read prerequisite status: " + strings.Join(unknown, ", "))
	}
	if !ok {
		return Skip(fmt.Sprintf("could not read %s status", def.name))
	}
	switch status {
	case "enabled":
		return Pass(fmt.Sprintf("%s is enabled", def.name))
	default:
		return Skip(fmt.Sprintf("could not determine %s status (%q)", def.name, status))
	}
}

func defaultSecurityStatus(config map[string]json.RawMessage, field string) (string, bool) {
	if _, present := config[field]; present {
		return securityStringField(config, field)
	}
	if field != "code_security" && field != "secret_protection" {
		return "", false
	}
	advanced, ok := securityStringField(config, "advanced_security")
	if ok && (advanced == "enabled" || advanced == field) {
		return "enabled", true
	}
	return "", false
}

func checkOrganizationSecurityDefaults(f *OrganizationFacts, def organizationSecurityRule) Outcome {
	if !f.securityDefaultsKnown {
		return Skip("could not retrieve default security configurations")
	}
	var failures, targets, unknown, ignored, inapplicable []string
	passed := 0
	for _, entry := range f.securityDefaults {
		switch entry.DefaultForNewRepos {
		case "none":
			continue
		case "public", "private_and_internal", "all":
		default:
			unknown = append(unknown, "unknown repository visibility")
			continue
		}
		if def.visibility != "" && entry.DefaultForNewRepos != "all" && entry.DefaultForNewRepos != def.visibility {
			continue
		}
		name, ok := securityStringField(entry.Configuration, "name")
		if !ok || name == "" {
			unknown = append(unknown, entry.DefaultForNewRepos+" configuration")
			continue
		}
		if f.ignores.Match(def.id, name) {
			ignored = append(ignored, name)
			continue
		}
		var unknownPrerequisites []string
		applicable := true
		for _, prerequisite := range def.prerequisites {
			status, ok := defaultSecurityStatus(entry.Configuration, prerequisite.field)
			if status == "disabled" {
				inapplicable = append(inapplicable, fmt.Sprintf("%s (%s disabled)", name, prerequisite.name))
				applicable = false
				break
			}
			if !ok || status != "enabled" {
				unknownPrerequisites = append(unknownPrerequisites, prerequisite.name)
			}
		}
		if !applicable {
			continue
		}
		status, ok := defaultSecurityStatus(entry.Configuration, def.field)
		if len(unknownPrerequisites) > 0 {
			unknown = append(unknown, fmt.Sprintf("%s (prerequisite status unknown: %s)", name, strings.Join(unknownPrerequisites, ", ")))
			if !ok || status != "disabled" {
				continue
			}
		}
		if !ok || status == "not_set" || status == "" {
			unknown = append(unknown, fmt.Sprintf("%s (not set or unavailable)", name))
			continue
		}
		if def.field == "advanced_security" && (status == "code_security" || status == "secret_protection") {
			unknown = append(unknown, fmt.Sprintf("%s (standalone product: %s)", name, status))
			continue
		}
		if def.field == "enforcement" {
			switch status {
			case "enforced", "enterprise_enforced":
				passed++
			case "unenforced":
				failures = append(failures, fmt.Sprintf("%s (%s: %s)", name, entry.DefaultForNewRepos, status))
				targets = append(targets, name)
			default:
				unknown = append(unknown, fmt.Sprintf("%s (%s)", name, status))
			}
			continue
		}
		switch status {
		case "enabled":
			passed++
		case "disabled":
			failures = append(failures, fmt.Sprintf("%s (%s: %s)", name, entry.DefaultForNewRepos, status))
			targets = append(targets, name)
		default:
			unknown = append(unknown, fmt.Sprintf("%s (%s)", name, status))
		}
	}
	if len(failures) > 0 {
		detail := fmt.Sprintf("default configurations do not enable %s: %s", def.name, strings.Join(failures, ", "))
		if len(unknown) > 0 {
			detail += "; could not evaluate " + strings.Join(unknown, ", ")
		}
		if len(inapplicable) > 0 {
			detail += "; not applicable: " + strings.Join(inapplicable, ", ")
		}
		outcome := failTargets(detail, targets)
		outcome.TargetsIncomplete = len(unknown) > 0 || len(inapplicable) > 0 || len(ignored) > 0
		return outcome
	}
	if len(unknown) > 0 {
		return Skip(fmt.Sprintf("could not determine %s for default configurations: %s", def.name, strings.Join(unknown, ", ")))
	}
	if len(ignored) > 0 {
		return skipIgnored("security configuration", ignored)
	}
	if len(inapplicable) > 0 {
		return Skip(fmt.Sprintf("%s is not applicable: %s", def.name, strings.Join(inapplicable, ", ")))
	}
	if passed == 0 {
		return Skip("no applicable default security configuration")
	}
	return Pass(fmt.Sprintf("all applicable default configurations enable %s", def.name))
}

func registerAIScanRules() {
	for _, def := range []struct {
		id    string
		scope Scope
		field string
		name  string
	}{
		{"GSK154", ScopeRepository, "pr_scan", "AI Scan for pull requests"},
		{"GSK155", ScopeRepository, "repository_scan", "AI Scan for repositories"},
		{"GSK549", ScopeOrganization, "pr_scan", "AI Scan for pull requests"},
		{"GSK550", ScopeOrganization, "repository_scan", "AI Scan for repositories"},
	} {
		rule := Rule{
			ID: def.id, Scope: def.scope, SettingsPath: "security_analysis",
			Category: "security", Severity: SeverityMedium, Title: def.name + " not enabled",
		}
		check := func(settings map[string]json.RawMessage) Outcome {
			status, ok := securityStringField(settings, def.field)
			if !ok {
				return Skip(fmt.Sprintf("could not read %s setting", def.name))
			}
			switch status {
			case "enabled":
				return Pass(fmt.Sprintf("%s setting is enabled", def.name))
			case "disabled":
				return Fail(fmt.Sprintf("%s setting is disabled", def.name))
			default:
				return Skip(fmt.Sprintf("could not determine %s setting (%q)", def.name, status))
			}
		}
		if def.scope == ScopeRepository {
			rule.CheckRepo = func(f *RepositoryFacts) Outcome { return check(f.aiScanSettings) }
		} else {
			rule.CheckOrg = func(f *OrganizationFacts) Outcome { return check(f.aiScanSettings) }
		}
		register(rule)
	}
}
