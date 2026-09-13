package localscan

import (
	"path/filepath"
	"regexp"
	"strings"
)

// defaultAllowlistPatterns maps a built-in pattern ID to the documentation
// placeholder values it should never flag as a real secret, regardless of user
// config. AWS's documentation style guide requires example access key IDs to
// end in "EXAMPLE" and example secret keys to end in "EXAMPLEKEY" (e.g. the
// AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY pair used
// throughout AWS docs), so an AWS token of the documented shape ending that way
// is a sample, not a leak. The patterns are scoped to their pattern ID and, for
// the access key ID, anchored to the full 20-character token, so a custom or
// other-provider value that merely ends in "EXAMPLE" is not silently
// suppressed.
var defaultAllowlistPatterns = map[string]*regexp.Regexp{
	"aws_access_key_id":     regexp.MustCompile(`^[A-Z0-9]{13}EXAMPLE$`),
	"aws_secret_access_key": regexp.MustCompile(`[0-9a-zA-Z/+]{30}EXAMPLEKEY['"]?$`),
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
	if re, ok := defaultAllowlistPatterns[f.PatternID]; ok && re.MatchString(matchedText) {
		return true
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
