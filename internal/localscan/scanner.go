package localscan

import (
	"context"
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

// ScanFragment scans a single fragment against all enabled patterns and
// returns any findings that are not covered by the allowlist.
func (s *Scanner) ScanFragment(frag Fragment) []Finding {
	var findings []Finding
	for _, p := range s.Patterns {
		if !p.Enabled {
			continue
		}
		if len(p.Keywords) > 0 && !containsAnyKeyword(frag.Content, p.Keywords) {
			continue
		}
		locs := p.Regex.FindAllStringIndex(frag.Content, -1)
		for _, loc := range locs {
			matched := frag.Content[loc[0]:loc[1]]
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
				StartLine:   base + lineNumberAt(frag.Content, loc[0]) - 1,
				Match:       matched,
				Secret:      matched,
			}
			if s.Allowlist.Allowed(f, matched, lineAt(frag.Content, loc[0])) {
				continue
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
	fragments, err := src.Fragments()
	if err != nil {
		return nil, err
	}
	logger.Debug("scanning fragments", "fragments", len(fragments), "patterns", len(scanner.Patterns))
	// Gate the per-fragment bookkeeping used only for the debug summary so it
	// allocates nothing and does no extra work when debug logging is disabled.
	debugEnabled := slog.Default().Enabled(context.Background(), slog.LevelDebug)
	var findings []Finding
	var commits, files map[string]struct{}
	if debugEnabled {
		commits = make(map[string]struct{})
		files = make(map[string]struct{})
	}
	for _, frag := range fragments {
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
		findings = append(findings, fragFindings...)
	}
	if debugEnabled {
		logger.Debug("scan completed", "commits", len(commits), "files", len(files), "findings", len(findings))
	}
	return findings, nil
}

func containsAnyKeyword(content string, keywords []string) bool {
	lower := strings.ToLower(content)
	for _, k := range keywords {
		if strings.Contains(lower, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

func lineNumberAt(content string, idx int) int {
	line := 1
	for i := 0; i < idx && i < len(content); i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}

// lineAt returns the full line of content containing byte offset idx.
func lineAt(content string, idx int) string {
	if idx < 0 || idx > len(content) {
		return ""
	}
	start := strings.LastIndexByte(content[:idx], '\n') + 1
	end := strings.IndexByte(content[idx:], '\n')
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
