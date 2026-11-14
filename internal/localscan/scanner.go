package localscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/srz-zumix/go-gh-extension/pkg/logger"
)

// Scanner detects secrets within fragments using a set of patterns and an
// allowlist.
type Scanner struct {
	Patterns   []Pattern
	Allowlist  *Allowlist
	ShowSecret bool
	Verify     bool
}

// NewScanner builds a Scanner from the builtin patterns merged with any
// user-defined patterns and allowlist entries from cfg.
func NewScanner(cfg *Config, showSecret bool) (*Scanner, error) {
	patterns := BuiltinPatterns()

	if cfg != nil {
		for _, cp := range cfg.Patterns {
			if cp.ID == "" {
				return nil, fmt.Errorf("pattern config entry is missing required field %q", "id")
			}
			if cp.Regex == "" {
				return nil, fmt.Errorf("pattern %q is missing required field %q", cp.ID, "regex")
			}
			re, err := regexp.Compile(cp.Regex)
			if err != nil {
				return nil, fmt.Errorf("failed to compile pattern %q: %w", cp.ID, err)
			}
			// display_name is optional and defaults to the pattern id.
			displayName := cp.DisplayName
			if displayName == "" {
				displayName = cp.ID
			}
			p := Pattern{
				ID:          cp.ID,
				TokenType:   cp.TokenType,
				DisplayName: displayName,
				Regex:       re,
				Keywords:    cp.Keywords,
				Source:      "config",
				Enabled:     true,
			}
			patterns = replaceOrAppendPattern(patterns, p)
		}
	}

	allow := &Allowlist{}
	if cfg != nil {
		for _, r := range cfg.Allowlist.Regexes {
			re, err := regexp.Compile(r)
			if err != nil {
				return nil, fmt.Errorf("failed to compile allowlist regex %q: %w", r, err)
			}
			allow.Regexes = append(allow.Regexes, re)
		}
		allow.Paths = cfg.Allowlist.Paths
		allow.Commits = cfg.Allowlist.Commits
		allow.StopWords = cfg.Allowlist.StopWords
	}

	return &Scanner{Patterns: patterns, Allowlist: allow, ShowSecret: showSecret}, nil
}

// replaceOrAppendPattern overrides a builtin pattern with the same ID, or
// appends p as a new pattern.
func replaceOrAppendPattern(patterns []Pattern, p Pattern) []Pattern {
	for i, existing := range patterns {
		if existing.ID == p.ID {
			patterns[i] = p
			return patterns
		}
	}
	return append(patterns, p)
}

// redactMetadata redacts matches of all enabled patterns in fragment
// metadata (e.g. session name, workspace) unless ShowSecret is set.
// When a match spans multiple lines (e.g. a PEM block whose pattern covers
// only the first body line), the whole field is masked so that the rest of
// the secret is not exposed.
func (s *Scanner) redactMetadata(v string) string {
	if v == "" || s.ShowSecret {
		return v
	}
	for _, pattern := range s.Patterns {
		if !pattern.Enabled {
			continue
		}
		for _, m := range pattern.Regex.FindAllString(v, -1) {
			if strings.Contains(m, "\n") {
				return strings.Repeat("*", len(v))
			}
		}
		v = pattern.Regex.ReplaceAllStringFunc(v, redact)
	}
	return v
}

// ScanFragment scans a single fragment against all enabled patterns and
// returns any findings that are not covered by the allowlist.
func (s *Scanner) ScanFragment(frag Fragment) []Finding {
	return s.scanFragmentContent(frag, frag.Content, nil)
}

func (s *Scanner) scanFragmentBytes(frag Fragment, content []byte) []Finding {
	return s.scanFragmentContent(frag, "", content)
}

func (s *Scanner) scanFragmentContent(frag Fragment, stringContent string, byteContent []byte) []Finding {
	byteMode := byteContent != nil
	name := s.redactMetadata(frag.SessionName)
	workspace := s.redactMetadata(frag.Workspace)
	var findings []Finding
	for _, p := range s.Patterns {
		if !p.Enabled {
			continue
		}
		// Byte-backed scans skip the keyword prefilter to avoid allocating a lowercased copy of the mapped log.
		if !byteMode && len(p.Keywords) > 0 && !containsAnyKeyword(stringContent, p.Keywords) {
			continue
		}
		var locs [][]int
		if byteMode {
			locs = p.Regex.FindAllIndex(byteContent, -1)
		} else {
			locs = p.Regex.FindAllStringIndex(stringContent, -1)
		}
		lineNumber, lineCountedTo := 1, 0
		for _, loc := range locs {
			for lineCountedTo < loc[0] {
				var current byte
				if byteMode {
					current = byteContent[lineCountedTo]
				} else {
					current = stringContent[lineCountedTo]
				}
				if current == '\n' {
					lineNumber++
				}
				lineCountedTo++
			}
			var matched string
			var matchedBytes []byte
			if byteMode {
				matchedBytes = byteContent[loc[0]:loc[1]]
				matched = string(matchedBytes)
			} else {
				matched = stringContent[loc[0]:loc[1]]
			}
			// BaseLine carries the file line of the fragment's first line
			// (used for commit diff fragments that hold only added hunks);
			// zero means the fragment content starts at file line 1.
			base := frag.BaseLine
			if base <= 0 {
				base = 1
			}
			f := Finding{
				PatternID:   p.ID,
				TokenType:   p.TokenType,
				DisplayName: p.DisplayName,
				Commit:      frag.CommitSHA,
				Author:      frag.Author,
				Date:        frag.Date,
				File:        frag.FilePath,
				StartLine:   base + lineNumber - 1,
				Match:       matched,
				Secret:      matched,
				Source:      frag.Source,
				SessionID:   frag.SessionID,
				SessionName: name,
				Workspace:   workspace,
			}
			if frag.Line > 0 {
				f.StartLine = frag.Line
			}
			allowed := false
			if byteMode {
				allowed = s.Allowlist.allowedBytes(f, matchedBytes, lineAtBytes(byteContent, loc[0]), loc[0]-lineStartAtBytes(byteContent, loc[0]))
			} else {
				allowed = s.Allowlist.Allowed(f, matched, lineAt(stringContent, loc[0]), loc[0]-lineStartAt(stringContent, loc[0]))
			}
			if allowed {
				continue
			}
			if byteMode {
				f.matchHash = sha256.Sum256(matchedBytes)
			} else {
				f.matchHash = sha256.Sum256([]byte(matched))
			}
			if s.Verify && p.Source == "builtin" {
				f.verificationPattern = p.ID
				f.rawSecret = matched
			}
			if !s.ShowSecret {
				// Redact both Match and Secret so JSON output never leaks
				// the raw value when --show-secret is not set.
				redacted := redact(matched)
				f.Match = redacted
				f.Secret = redacted
			}
			findings = append(findings, f)
		}
	}
	return findings
}

// Scan collects the fragments produced by src and returns every finding
// detected by the scanner. It keeps command handlers free of scan
// orchestration logic.
func Scan(src Source, scanner *Scanner) ([]Finding, error) {
	// Gate the per-fragment bookkeeping used only for the debug summary so it
	// allocates nothing and does no extra work when debug logging is disabled.
	debugEnabled := slog.Default().Enabled(context.Background(), slog.LevelDebug)
	var findings []Finding
	var commits, files map[string]struct{}
	if debugEnabled {
		commits = make(map[string]struct{})
		files = make(map[string]struct{})
	}
	fragmentCount := 0
	type findingKey struct {
		file, commit, pattern string
		matchHash             [32]byte
	}
	seen := make(map[findingKey]struct{})
	handle := func(frag Fragment) error {
		fragmentCount++
		fragFindings := scanner.ScanFragment(frag)
		if debugEnabled {
			logger.Debug("scanned fragment", "commit", frag.CommitSHA, "file", frag.FilePath, "base_line", frag.BaseLine, "findings", len(fragFindings))
			if frag.CommitSHA != "" {
				commits[frag.CommitSHA] = struct{}{}
			}
			if frag.FilePath != "" {
				files[frag.FilePath] = struct{}{}
			}
		}
		for _, finding := range fragFindings {
			key := findingKey{finding.File, finding.Commit, finding.PatternID, finding.matchHash}
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, finding)
		}
		return nil
	}

	// Prefer streaming so the source can release each fragment's content as it
	// is scanned instead of holding the whole run in memory at once.
	if streamer, ok := src.(FragmentStreamer); ok {
		logger.Debug("streaming fragments", "patterns", len(scanner.Patterns))
		if err := streamer.StreamFragments(handle); err != nil {
			return nil, err
		}
	} else {
		fragments, err := src.Fragments()
		if err != nil {
			return nil, err
		}
		logger.Debug("scanning fragments", "fragments", len(fragments), "patterns", len(scanner.Patterns))
		for _, frag := range fragments {
			if err := handle(frag); err != nil {
				return nil, err
			}
		}
	}
	if debugEnabled {
		logger.Debug("scan completed", "fragments", fragmentCount, "commits", len(commits), "files", len(files), "findings", len(findings))
	}
	return findings, nil
}

func containsAnyKeyword(content string, keywords []string) bool {
	lower := strings.ToLower(content)
	for _, keyword := range keywords {
		if strings.Contains(lower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func lineNumberAt(content string, idx int) int {
	return lineNumberAtBytes([]byte(content), idx)
}

func lineNumberAtBytes(content []byte, idx int) int {
	line := 1
	for i := 0; i < idx && i < len(content); i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}

// lineAt returns the full line of content containing byte offset idx.
// lineStartAt returns the byte offset of the start of the line containing idx.
func lineStartAt(content string, idx int) int {
	return lineStartAtBytes([]byte(content), idx)
}

func lineStartAtBytes(content []byte, idx int) int {
	if idx < 0 || idx > len(content) {
		return 0
	}
	return bytes.LastIndexByte(content[:idx], '\n') + 1
}

func lineAt(content string, idx int) string {
	return string(lineAtBytes([]byte(content), idx))
}

func lineAtBytes(content []byte, idx int) []byte {
	if idx < 0 || idx > len(content) {
		return nil
	}
	start := lineStartAtBytes(content, idx)
	end := bytes.IndexByte(content[idx:], '\n')
	if end < 0 {
		return content[start:]
	}
	return content[start : idx+end]
}

// redact masks the middle of a secret, keeping a few characters on each end
// for identification purposes.
func redact(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}
