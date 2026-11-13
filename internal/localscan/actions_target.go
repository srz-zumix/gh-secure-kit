package localscan

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// ActionsRunTarget selects a run's latest or specified attempt, or one job.
// An attempt of zero selects the latest attempt, or the job's actual attempt.
type ActionsRunTarget struct {
	RunID   int64
	Attempt int64
	JobID   int64
}

// ActionsRunTargets contains the parsed --run selections and inferred repository.
type ActionsRunTargets struct {
	Runs       []int64
	Targets    []ActionsRunTarget
	Repository *repository.Repository
}

// ParseActionsRunTargets parses repeated URLs and repeated or comma-separated IDs.
func ParseActionsRunTargets(values []string) (ActionsRunTargets, error) {
	var result ActionsRunTargets
	seenRuns := make(map[int64]bool)
	seenTargets := make(map[ActionsRunTarget]bool)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if strings.Contains(value, "://") {
			target, repo, err := parseActionsRunURL(value)
			if err != nil {
				return ActionsRunTargets{}, err
			}
			if result.Repository != nil && !sameActionsRepository(*result.Repository, repo) {
				return ActionsRunTargets{}, fmt.Errorf("all --run URLs must reference the same repository and host")
			}
			if result.Repository == nil {
				result.Repository = &repo
			}
			addActionsRunTarget(&result, target, seenRuns, seenTargets)
			continue
		}
		for _, rawID := range strings.Split(value, ",") {
			id, numeric, err := actionsSelectorID(strings.TrimSpace(rawID))
			if err != nil || !numeric {
				return ActionsRunTargets{}, fmt.Errorf("--run requires positive run IDs or HTTPS Actions URLs")
			}
			addActionsRunTarget(&result, ActionsRunTarget{RunID: id}, seenRuns, seenTargets)
		}
	}
	opts := ActionsScanOptions{Runs: result.Runs, RunTargets: result.Targets, RunsPerWorkflow: 1}
	if err := opts.Validate(); err != nil {
		return ActionsRunTargets{}, err
	}
	return result, nil
}

func addActionsRunTarget(result *ActionsRunTargets, target ActionsRunTarget, seenRuns map[int64]bool, seenTargets map[ActionsRunTarget]bool) {
	if !seenRuns[target.RunID] {
		result.Runs = append(result.Runs, target.RunID)
		seenRuns[target.RunID] = true
	}
	if !seenTargets[target] {
		result.Targets = append(result.Targets, target)
		seenTargets[target] = true
	}
}

func parseActionsRunURL(value string) (ActionsRunTarget, repository.Repository, error) {
	const invalidURL = "--run URL must be an HTTPS Actions run, attempt, or job URL"
	scheme, rest, found := strings.Cut(value, "://")
	if !found || !strings.EqualFold(scheme, "https") {
		return ActionsRunTarget{}, repository.Repository{}, fmt.Errorf("%s", invalidURL)
	}
	parsed, err := parser.ParseGitHubURL("https://" + rest)
	if err != nil || parsed == nil || parsed.Url == nil || parsed.Repo == nil {
		return ActionsRunTarget{}, repository.Repository{}, fmt.Errorf("%s", invalidURL)
	}
	u := parsed.Url
	escapedPath := strings.ToLower(u.EscapedPath())
	decodedPath := strings.ToLower(u.Path)
	if u.User != nil || u.Opaque != "" || u.Hostname() == "" || strings.HasSuffix(u.Host, ":") ||
		strings.Contains(u.Path, `\`) || strings.Contains(u.Path, "//") ||
		strings.Contains(escapedPath, "%2f") || strings.Contains(escapedPath, "%5c") ||
		strings.Contains(decodedPath, "%2f") || strings.Contains(decodedPath, "%5c") {
		return ActionsRunTarget{}, repository.Repository{}, fmt.Errorf("%s", invalidURL)
	}
	host, err := canonicalActionsHost(u)
	if err != nil {
		return ActionsRunTarget{}, repository.Repository{}, fmt.Errorf("%s", invalidURL)
	}
	parts := parsed.PathParts
	if len(parts) < 5 || parts[2] != "actions" || parts[3] != "runs" ||
		!validActionsRepositoryPart(parts[0]) || !validActionsRepositoryPart(parts[1]) {
		return ActionsRunTarget{}, repository.Repository{}, fmt.Errorf("%s", invalidURL)
	}
	runID, numeric, err := actionsSelectorID(parts[4])
	if err != nil || !numeric {
		return ActionsRunTarget{}, repository.Repository{}, fmt.Errorf("--run URL requires a positive run ID")
	}
	target := ActionsRunTarget{RunID: runID}
	remaining := parts[5:]
	if len(remaining) >= 2 && remaining[0] == "attempts" {
		attempt, numeric, err := actionsSelectorID(remaining[1])
		if err != nil || !numeric || int64(int(attempt)) != attempt {
			return ActionsRunTarget{}, repository.Repository{}, fmt.Errorf("--run URL requires a positive attempt number")
		}
		target.Attempt = attempt
		remaining = remaining[2:]
	}
	if len(remaining) == 2 && remaining[0] == "job" {
		jobID, numeric, err := actionsSelectorID(remaining[1])
		if err != nil || !numeric {
			return ActionsRunTarget{}, repository.Repository{}, fmt.Errorf("--run URL requires a positive job ID")
		}
		target.JobID = jobID
		remaining = nil
	}
	if len(remaining) != 0 {
		return ActionsRunTarget{}, repository.Repository{}, fmt.Errorf("%s", invalidURL)
	}
	repo := repository.Repository{Host: host, Owner: parts[0], Name: parts[1]}
	return target, repo, nil
}

func canonicalActionsHost(u *url.URL) (string, error) {
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	for _, c := range host {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':') {
			return "", fmt.Errorf("invalid host")
		}
	}
	port := u.Port()
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", fmt.Errorf("invalid port")
		}
		if number != 443 {
			return net.JoinHostPort(host, strconv.Itoa(number)), nil
		}
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]", nil
	}
	return host, nil
}

func canonicalActionsHostString(host string) (string, error) {
	u, err := url.Parse("https://" + host)
	if err != nil || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("invalid host")
	}
	return canonicalActionsHost(u)
}

func validActionsRepositoryPart(part string) bool {
	if part == "" || part == "." || part == ".." {
		return false
	}
	for _, c := range part {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func sameActionsRepository(left, right repository.Repository) bool {
	return strings.EqualFold(left.Host, right.Host) &&
		strings.EqualFold(left.Owner, right.Owner) &&
		strings.EqualFold(left.Name, right.Name)
}

// ResolveActionsRepository prefers the repository in a --run URL over checkout inference.
func ResolveActionsRepository(input string, inferred *repository.Repository) (repository.Repository, error) {
	if inferred != nil && input == "" {
		return *inferred, nil
	}
	repo, err := parser.Repository(parser.RepositoryInput(input))
	if err != nil || inferred == nil {
		return repo, err
	}
	repo.Host, err = canonicalActionsHostString(repo.Host)
	if err != nil || !sameActionsRepository(repo, *inferred) {
		return repository.Repository{}, fmt.Errorf("--repo must match the repository and host in --run URLs")
	}
	return *inferred, nil
}
