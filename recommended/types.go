// Package recommended implements a catalog of GitHub best-practice checks
// (inspired by https://github.com/microsoft/ghqr) and applies fixes for
// findings that can be safely automated.
package recommended

import (
	"context"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

// Severity indicates how impactful a finding is.
type Severity string

// Severity levels, ordered from most to least impactful.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// severityRank is used to sort and to support `--severity` threshold filtering.
var severityRank = map[Severity]int{
	SeverityCritical: 4,
	SeverityHigh:     3,
	SeverityMedium:   2,
	SeverityLow:      1,
	SeverityInfo:     0,
}

// Severities lists the valid values for the `--severity` flag, ordered from
// most to least severe.
var Severities = []string{
	string(SeverityCritical),
	string(SeverityHigh),
	string(SeverityMedium),
	string(SeverityLow),
	string(SeverityInfo),
}

// Rank returns a numeric rank for the severity (higher is more severe).
func (s Severity) Rank() int {
	return severityRank[s]
}

// Scope indicates which kind of GitHub resource a rule evaluates.
type Scope string

// Supported scopes.
const (
	ScopeRepository   Scope = "repository"
	ScopeOrganization Scope = "organization"
)

// Status is the outcome of evaluating a rule against a target.
type Status string

// Possible outcomes of a rule evaluation.
const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusSkip Status = "skip"
)

// Statuses lists the valid values for the `--status` flag.
var Statuses = []string{
	string(StatusPass),
	string(StatusFail),
	string(StatusSkip),
}

// RepositoryCheckFunc evaluates a rule against repository facts.
type RepositoryCheckFunc func(f *RepositoryFacts) Outcome

// OrganizationCheckFunc evaluates a rule against organization facts.
type OrganizationCheckFunc func(f *OrganizationFacts) Outcome

// RepositoryApplyFunc applies the recommended fix to a repository.
type RepositoryApplyFunc func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error

// OrganizationApplyFunc applies the recommended fix to an organization.
type OrganizationApplyFunc func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *OrganizationFacts) error

// Outcome is the result of evaluating a rule's Check function.
type Outcome struct {
	Status Status
	Detail string
}

// Pass reports that the target already follows the recommendation.
func Pass(detail string) Outcome { return Outcome{Status: StatusPass, Detail: detail} }

// Fail reports that the target does not follow the recommendation.
func Fail(detail string) Outcome { return Outcome{Status: StatusFail, Detail: detail} }

// Skip reports that the rule could not be evaluated (for example, missing permissions).
func Skip(detail string) Outcome { return Outcome{Status: StatusSkip, Detail: detail} }

// Rule is a single best-practice recommendation.
type Rule struct {
	// ID is the stable gh-secure-kit identifier, e.g. "GSK101".
	ID string
	// GHQRID references the equivalent microsoft/ghqr rule ID, if any.
	GHQRID   string
	Scope    Scope
	Category string
	Severity Severity
	Title    string
	// Fixable indicates whether ApplyRepo/ApplyOrg can remediate a failing result.
	Fixable bool

	CheckRepo RepositoryCheckFunc
	CheckOrg  OrganizationCheckFunc
	ApplyRepo RepositoryApplyFunc
	ApplyOrg  OrganizationApplyFunc
}

// Result is the outcome of evaluating a Rule against a specific target.
type Result struct {
	Rule   Rule
	Target string
	Status Status
	Detail string
}
