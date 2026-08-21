package localscan

import (
	"path/filepath"
	"regexp"
	"strings"
)

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
