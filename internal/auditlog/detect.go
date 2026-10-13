package auditlog

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// Detection is an audit log entry classified into a category.
// Entry is a named field because embedding would promote AuditEntry.MarshalJSON and drop Category.
type Detection struct {
	Category string             `json:"category"`
	Target   string             `json:"target,omitempty"`
	Entry    *github.AuditEntry `json:"entry"`
}

// Options controls Detect.
type Options struct {
	// Categories limits detection; all categories are used when empty.
	Categories []string
	// Since and Until bound the entry time; a zero value means unbounded.
	Since time.Time
	Until time.Time
}

// ParseTimeRange parses --since/--until values; an empty string yields a zero time.
func ParseTimeRange(since, until string) (time.Time, time.Time, error) {
	var s, u time.Time
	var err error
	if since != "" {
		if s, err = parser.ParseTime(since); err != nil {
			return s, u, fmt.Errorf("invalid --since: %w", err)
		}
	}
	if until != "" {
		if u, err = parser.ParseTime(until); err != nil {
			return s, u, fmt.Errorf("invalid --until: %w", err)
		}
	}
	if !s.IsZero() && !u.IsZero() && s.After(u) {
		return s, u, fmt.Errorf("--since must not be later than --until")
	}
	return s, u, nil
}

// BuildPhrase appends a created-date qualifier (UTC, day granularity) to query.
func BuildPhrase(query string, since, until time.Time) string {
	const layout = "2006-01-02"
	switch {
	case !since.IsZero() && !until.IsZero():
		return fmt.Sprintf("%s created:%s..%s", query, since.UTC().Format(layout), until.UTC().Format(layout))
	case !since.IsZero():
		return fmt.Sprintf("%s created:>=%s", query, since.UTC().Format(layout))
	case !until.IsZero():
		return fmt.Sprintf("%s created:<=%s", query, until.UTC().Format(layout))
	}
	return query
}

// EntryTime returns the time of the entry, preferring @timestamp over created_at.
func EntryTime(e *github.AuditEntry) (time.Time, bool) {
	if e.Timestamp != nil {
		return e.Timestamp.Time, true
	}
	if e.CreatedAt != nil {
		return e.CreatedAt.Time, true
	}
	return time.Time{}, false
}

// Filter classifies entries, drops unmatched ones and those outside the time range,
// and returns the rest newest first.
func Filter(entries []*github.AuditEntry, categories []string, since, until time.Time) []Detection {
	var result []Detection
	for _, e := range entries {
		if e == nil || e.Action == nil {
			continue
		}
		category := Classify(*e.Action)
		if category == "" {
			continue
		}
		if len(categories) > 0 && !slices.Contains(categories, category) {
			continue
		}
		if t, ok := EntryTime(e); ok {
			if !since.IsZero() && t.Before(since) {
				continue
			}
			if !until.IsZero() && t.After(until) {
				continue
			}
		}
		result = append(result, Detection{Category: category, Target: Target(category, e), Entry: e})
	}
	sort.SliceStable(result, func(i, j int) bool {
		ti, _ := EntryTime(result[i].Entry)
		tj, _ := EntryTime(result[j].Entry)
		return ti.After(tj)
	})
	return result
}

// Detect queries the organization audit log for each category and returns the matches.
func Detect(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, opts Options) ([]Detection, error) {
	var entries []*github.AuditEntry
	for _, q := range Queries(opts.Categories) {
		got, err := gh.GetAuditLog(ctx, g, repo, &gh.GetAuditLogOptions{
			Phrase: BuildPhrase(q, opts.Since, opts.Until),
			Order:  "desc",
		})
		if err != nil {
			return nil, err
		}
		entries = append(entries, got...)
	}
	return Filter(entries, opts.Categories, opts.Since, opts.Until), nil
}
