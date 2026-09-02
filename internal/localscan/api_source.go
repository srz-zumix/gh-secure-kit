package localscan

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/go-git/go-git/v5"
	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/logger"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// apiMaxCommitsPerCompare and apiMaxFilesPerCommit are the hard caps the
// GitHub API applies to a comparison and to a commit's file list. Hitting one
// of them means the response is incomplete.
const (
	apiMaxCommitsPerCompare = 250
	apiMaxFilesPerCommit    = 3000
)

var hunkHeaderRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// APISource produces fragments from commit diffs read through the GitHub API,
// so a revision range can be scanned without the commits existing locally.
type APISource struct {
	ctx    context.Context
	target Target
	repo   string
}

// NewAPISource creates an APISource for the given target. repo may be empty,
// in which case the repository is resolved from the git remotes of the target
// path (--path).
func NewAPISource(ctx context.Context, t Target, repo string) *APISource {
	return &APISource{ctx: ctx, target: t, repo: repo}
}

// Fragments implements Source.
func (s *APISource) Fragments() ([]Fragment, error) {
	if s.target.Mode != TargetRevRange {
		return nil, fmt.Errorf("the GitHub API can only scan an explicit revision range, not the %q target", s.target.Mode)
	}
	if s.target.MaxCommits < 0 {
		return nil, fmt.Errorf("max-commits must be zero or positive, got %d", s.target.MaxCommits)
	}

	repo, err := s.resolveRepository()
	if err != nil {
		return nil, fmt.Errorf("failed to determine the repository to read through the GitHub API: %w", err)
	}
	client, err := gh.NewGitHubClientWithRepo(repo)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub client: %w", err)
	}

	shas, err := s.commitSHAs(client, repo)
	if err != nil {
		return nil, err
	}
	logger.Debug("scanning commits through the GitHub API", "repository", repo.Owner+"/"+repo.Name, "rev-range", s.target.RevRange, "commits", len(shas))

	var frags []Fragment
	for _, sha := range shas {
		commit, err := gh.GetCommit(s.ctx, client, repo, sha)
		if err != nil {
			return nil, fmt.Errorf("failed to get commit %s through the GitHub API: %w", sha, err)
		}
		f, err := fragmentsForAPICommit(commit)
		if err != nil {
			return nil, err
		}
		frags = append(frags, f...)
	}
	return frags, nil
}

// resolveRepository determines the GitHub repository whose commits the API
// should read. An explicit --repo wins; otherwise the repository is taken from
// the git remotes of the scanned path (--path), not the current working
// directory. When --path points inside a repository, its work-tree root is
// used so remote resolution still succeeds.
func (s *APISource) resolveRepository() (repository.Repository, error) {
	opts := []parser.RepositoryOption{parser.RepositoryInput(s.repo)}
	if root, err := gitWorktreeRoot(s.target.RepoPath); err == nil {
		opts = append(opts, parser.RepositoryInputOptional(root))
	}
	return parser.Repository(opts...)
}

// gitWorktreeRoot returns the work-tree root of the git repository that
// contains path, so remote resolution targets the scanned repository even when
// path is a subdirectory.
func gitWorktreeRoot(path string) (string, error) {
	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return "", err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return "", err
	}
	return wt.Filesystem.Root(), nil
}

// commitSHAs lists the commits the range covers, oldest first.
func (s *APISource) commitSHAs(client *gh.GitHubClient, repo repository.Repository) ([]string, error) {
	from, to, explicit, err := splitRevRange(s.target.RevRange)
	if err != nil {
		return nil, err
	}
	if !explicit {
		// A bare revision is a single commit, and the API already diffs it
		// against its first parent.
		return []string{to}, nil
	}

	comparison, err := gh.CompareCommits(s.ctx, client, repo, from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to compare %s..%s through the GitHub API: %w", from, to, err)
	}
	commits := comparison.Commits
	if total := comparison.GetTotalCommits(); total > len(commits) {
		return nil, fmt.Errorf("the GitHub API returned only %d of the %d commits in %s..%s (the comparison is capped at %d commits); scan a smaller range or use a local checkout", len(commits), total, from, to, apiMaxCommitsPerCompare)
	}
	if s.target.MaxCommits > 0 && len(commits) > s.target.MaxCommits {
		return nil, fmt.Errorf("scan aborted: more than %d commits to scan; raise --max-commits or set it to 0 to scan without a limit", s.target.MaxCommits)
	}

	shas := make([]string, 0, len(commits))
	for _, c := range commits {
		shas = append(shas, c.GetSHA())
	}
	return shas, nil
}

// fragmentsForAPICommit turns the added lines of a commit's diff into
// fragments. It fails instead of scanning a partial diff, so a secret is never
// missed because the API left content out.
func fragmentsForAPICommit(commit *github.RepositoryCommit) ([]Fragment, error) {
	sha := commit.GetSHA()
	if len(commit.Files) >= apiMaxFilesPerCommit {
		return nil, fmt.Errorf("commit %s changes at least %d files, which is the maximum the GitHub API reports; scan it with a local checkout instead", sha, apiMaxFilesPerCommit)
	}

	author := commit.GetCommit().GetAuthor().GetName()
	date := commit.GetCommit().GetAuthor().GetDate().Time

	var frags []Fragment
	for _, f := range commit.Files {
		if f.GetPatch() != "" {
			frags = append(frags, fragmentsFromPatch(f.GetPatch(), f.GetFilename(), sha, author, date)...)
			continue
		}
		// A binary file reports no additions, so an omitted patch with added
		// lines means the API truncated the diff.
		if f.GetAdditions() > 0 {
			return nil, fmt.Errorf("the GitHub API did not return the diff of %q in commit %s, most likely because it is too large; scan it with a local checkout instead", f.GetFilename(), sha)
		}
	}
	return frags, nil
}

// fragmentsFromPatch splits a unified diff into one fragment per contiguous
// block of added lines, keeping the line numbers of the new file.
func fragmentsFromPatch(patch, filePath, sha, author string, date time.Time) []Fragment {
	var frags []Fragment
	var block []string
	inHunk := false
	newLine := 0
	blockStart := 0

	flush := func() {
		if len(block) == 0 {
			return
		}
		content := strings.Join(block, "\n") + "\n"
		block = nil
		if isBinaryString(content) {
			return
		}
		frags = append(frags, Fragment{
			Content:   content,
			FilePath:  filePath,
			CommitSHA: sha,
			Author:    author,
			Date:      date,
			BaseLine:  blockStart,
		})
	}

	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "@@") {
			flush()
			if m := hunkHeaderRe.FindStringSubmatch(line); m != nil {
				newLine, _ = strconv.Atoi(m[1])
				inHunk = true
			} else {
				inHunk = false
			}
			continue
		}
		if !inHunk {
			continue
		}
		switch {
		case strings.HasPrefix(line, "+"):
			if len(block) == 0 {
				blockStart = newLine
			}
			block = append(block, strings.TrimPrefix(line, "+"))
			newLine++
		case strings.HasPrefix(line, "-"), strings.HasPrefix(line, "\\"):
			// Removed lines and the "no newline" marker are absent from the
			// new file, so they do not advance its line number.
			flush()
		default:
			flush()
			newLine++
		}
	}
	flush()
	return frags
}
