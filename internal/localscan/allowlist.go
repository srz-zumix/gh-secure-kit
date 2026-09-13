package localscan

import (
	"path/filepath"
	"regexp"
	"strings"
)

// defaultAllowlistPatterns match known documentation placeholder values that
// are never real secrets, so they are excluded regardless of user config.
// AWS's documentation style guide requires example access key IDs to end in
// "EXAMPLE" and example secret keys to end in "EXAMPLEKEY" (e.g. the
// AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY pair used
// throughout AWS docs), so any match following that convention is a sample,
// not a leak.
var defaultAllowlistPatterns = []*regexp.Regexp{
	regexp.MustCompile(`EXAMPLE$`),
	regexp.MustCompile(`EXAMPLEKEY['"]?$`),
}

// Allowlist filters out findings that are known to be safe, e.g. test
// fixtures or documentation examples.
type Allowlist struct {
	Regexes   []*regexp.Regexp
	Paths     []string
	Commits   []string
	StopWords []string
}

// Allowed reports whether matchedText, found on lineText in f.File, should
// be excluded from the scan results. lineText is the full line the match
// was found on, used for stopword checks.
func (a *Allowlist) Allowed(f Finding, matchedText, lineText string) bool {
	if a == nil {
		return false
	}
	for _, re := range defaultAllowlistPatterns {
		if re.MatchString(matchedText) {
			return true
		}
	}
	for _, re := range a.Regexes {
		if re.MatchString(matchedText) {
			return true
		}
	}
	for _, p := range a.Paths {
		if matched, _ := filepath.Match(p, f.File); matched {
			return true
		}
		if strings.Contains(f.File, p) {
			return true
		}
	}
	for _, c := range a.Commits {
		if f.Commit != "" && f.Commit == c {
			return true
		}
	}
	for _, sw := range a.StopWords {
		if strings.Contains(lineText, sw) {
			return true
		}
	}
	return false
}
