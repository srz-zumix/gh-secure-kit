package localscan

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
)

// defaultAllowlistValues maps a built-in pattern ID to well-known dummy
// credentials: the documentation sample credentials AWS publishes throughout
// its docs, and the placeholder GitHub token used by coding agents. Only
// these exact fixtures are suppressed regardless of user config, so a real
// credential that merely shares the "EXAMPLE"/"EXAMPLEKEY" suffix is still
// reported instead of being silently discarded. The list is intentionally not
// exhaustive: a missing sample only causes a false positive (a documented
// example flagged), which is the safe direction for a security scanner. Values
// are matched by substring because the secret detector returns the surrounding
// assignment text (e.g. `aws_secret_access_key = "<value>"`), not the bare
// value.
var defaultAllowlistValues = map[string][]string{
	"aws_access_key_id": {
		"AKIAIOSFODNN7EXAMPLE",
		"AKIAI44QH8DHBEXAMPLE",
	},
	"aws_secret_access_key": {
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
	},
	"github_personal_access_token": {
		"ghp_invalidinvalidinvalidinvalidinvalid00",
	},
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
// was found on, used for stopword checks. matchOffset is the byte offset of
// matchedText within lineText, or a negative value when unknown.
func (a *Allowlist) Allowed(f Finding, matchedText, lineText string, matchOffset int) bool {
	if a == nil {
		return false
	}
	if samples, ok := defaultAllowlistValues[f.PatternID]; ok {
		for _, sample := range samples {
			if strings.Contains(matchedText, sample) {
				return true
			}
			if matchedText != "" && strings.HasPrefix(sample, matchedText) &&
				matchOffset >= 0 && matchOffset <= len(lineText) && strings.HasPrefix(lineText[matchOffset:], sample) {
				return true
			}
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

func (a *Allowlist) allowedBytes(f Finding, matchedText, lineText []byte, matchOffset int) bool {
	if a == nil {
		return false
	}
	if samples, ok := defaultAllowlistValues[f.PatternID]; ok {
		for _, sample := range samples {
			if bytes.Contains(matchedText, []byte(sample)) {
				return true
			}
			// A fixed-length pattern may match only a prefix of an overlong
			// sample, so require the complete sample starting at the match.
			if len(matchedText) > 0 && bytes.HasPrefix([]byte(sample), matchedText) &&
				matchOffset >= 0 && matchOffset <= len(lineText) && bytes.HasPrefix(lineText[matchOffset:], []byte(sample)) {
				return true
			}
		}
	}
	for _, re := range a.Regexes {
		if re.Match(matchedText) {
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
		if bytes.Contains(lineText, []byte(sw)) {
			return true
		}
	}
	return false
}
