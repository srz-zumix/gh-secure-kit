// Package localscan implements local, offline secret detection for uncommitted
// or unpushed git content, mirroring GitHub secret scanning push protection.
package localscan

import "regexp"

// Pattern defines a single secret detection rule.
type Pattern struct {
	ID          string
	TokenType   string
	DisplayName string
	Regex       *regexp.Regexp
	Keywords    []string
	// Source indicates where the pattern originated: "builtin" or "config".
	Source string
	// Enabled reflects whether the pattern is active, e.g. after applying
	// an organization's secret scanning pattern configuration.
	Enabled bool
}

// PatternInfo is a JSON/table-friendly view of a Pattern, omitting the
// compiled regular expression.
type PatternInfo struct {
	ID          string `json:"id"`
	TokenType   string `json:"token_type"`
	DisplayName string `json:"display_name"`
	Source      string `json:"source"`
	Enabled     bool   `json:"enabled"`
}

// Info returns a PatternInfo view of p.
func (p Pattern) Info() PatternInfo {
	return PatternInfo{
		ID:          p.ID,
		TokenType:   p.TokenType,
		DisplayName: p.DisplayName,
		Source:      p.Source,
		Enabled:     p.Enabled,
	}
}
